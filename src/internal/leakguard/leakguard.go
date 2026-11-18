// Package leakguard registers secret values the CLI is about to hand out with
// the leak protection of the Phase AI session it runs in. It indexes each value
// locally with the session's key and sends only keyed hashes; the proxy then
// replaces the value with ph:<type>:<id> wherever it appears in model traffic.
//
// Outside a Phase AI session it does nothing and makes no call.
package leakguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// Timeout bounds one registration, key fetch included. A command that hands
// out values waits at most this long for the proxy.
const Timeout = time.Second

// maxEntryBytes is the largest one value's entries may be and still fit in a
// registration of their own.
const maxEntryBytes = 4<<20 - 4<<10

// maxBatchBytes keeps each registration under the proxy's 4 MiB limit.
var maxBatchBytes = 3 << 20

// Value is one value to protect. Type is the placeholder's type (the secret's
// type, or "dynamic" for a lease) and ID its id.
type Value struct {
	Type  string
	ID    string
	Value string
}

// Result counts what the proxy protected and what it could not.
type Result struct {
	Added       int
	Unprotected int
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ErrInventoryFull is returned when the proxy holds as many values as it can.
// The proxy answered: it is reachable, it just cannot protect more values.
var ErrInventoryFull = errors.New("the leak protection inventory is full")

// Environment is what the package reads from the process's environment;
// tests replace it.
var Environment = os.Getenv

// Active reports whether this process runs inside a Phase AI session: the
// session marker and the proxy that carries the session's capability are both
// in its environment.
func Active() bool {
	return Environment("PHASE_AI_ENABLED") == "1" && proxyURL() != ""
}

func proxyURL() string {
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if value := Environment(key); value != "" {
			return value
		}
	}
	return ""
}

// Protectable reports whether values of this type are registered. config values
// are meant to be read and are left alone.
func Protectable(secretType string) bool {
	return !strings.EqualFold(strings.TrimSpace(secretType), "config")
}

// PlaceholderID makes a placeholder id from a name when no Phase id is at hand:
// the name itself when it fits, otherwise a digest of it. Nothing of the value
// goes into it.
func PlaceholderID(name string) string {
	if identifier.MatchString(name) {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "k" + hex.EncodeToString(sum[:8])
}

var (
	keyMu     sync.Mutex
	cachedKey *censor.Key
	keyProxy  string
)

// Register protects values with the session's leak protection. It does nothing
// outside a session, or when there is nothing to protect. It never sends a
// value: the proxy receives keyed hashes only.
func Register(ctx context.Context, values []Value) (Result, error) {
	var result Result
	if !Active() {
		return result, nil
	}
	values = protectable(values)
	if len(values) == 0 {
		return result, nil
	}
	client, err := sessionClient(proxyURL())
	if err != nil {
		return result, err
	}
	keyContext, cancelKey := context.WithTimeout(ctx, Timeout)
	key, err := sessionKey(keyContext, client)
	cancelKey()
	if err != nil {
		return result, err
	}
	// Indexing is local work, so only the calls to the proxy count against
	// the timeout: the key above, and the registrations below together.
	var batches [][]json.RawMessage
	var batch []json.RawMessage
	size := 0
	for _, value := range values {
		entries, err := censor.IndexValue(key, value.Type, value.ID, value.Value)
		if err != nil {
			return result, errors.New("a value could not be indexed for leak protection")
		}
		encoded, err := entries.Marshal()
		if err != nil {
			return result, errors.New("a value could not be indexed for leak protection")
		}
		if len(encoded) > maxEntryBytes {
			// Too large to register: the proxy counts it as unprotected.
			tooLong := &censor.Entries{Version: censor.EntriesVersion, Type: value.Type, ID: value.ID,
				Forms: []censor.Form{}, Unprotected: []censor.Unprotected{{Reason: censor.ReasonTooLong}}}
			if encoded, err = tooLong.Marshal(); err != nil {
				return result, errors.New("a value could not be indexed for leak protection")
			}
		}
		if size+len(encoded) > maxBatchBytes && len(batch) > 0 {
			batches, batch, size = append(batches, batch), nil, 0
		}
		batch = append(batch, encoded)
		size += len(encoded)
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	postContext, cancelPost := context.WithTimeout(ctx, Timeout)
	defer cancelPost()
	for _, batch := range batches {
		added, err := post(postContext, client, batch)
		result.Added += added.Added
		result.Unprotected += added.Unprotected
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// protectable drops config values, empty values and values whose type or id
// cannot form a placeholder.
func protectable(values []Value) []Value {
	kept := make([]Value, 0, len(values))
	for _, value := range values {
		if !Protectable(value.Type) || strings.TrimSpace(value.Value) == "" {
			continue
		}
		value.Type = strings.ToLower(strings.TrimSpace(value.Type))
		if !identifier.MatchString(value.Type) {
			value.Type = "secret"
		}
		if !identifier.MatchString(value.ID) {
			value.ID = PlaceholderID(value.ID)
		}
		kept = append(kept, value)
	}
	return kept
}

func sessionClient(rawProxyURL string) (*http.Client, error) {
	parsed, err := url.Parse(rawProxyURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User == nil {
		return nil, errors.New("the Phase AI proxy address is invalid")
	}
	password, present := parsed.User.Password()
	if !phaseproxy.ValidProxyUsername(parsed.User.Username()) || !present || password == "" {
		return nil, errors.New("the Phase AI proxy credential is unavailable")
	}
	if !phaseproxy.IsLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("the Phase AI proxy is not on this machine")
	}
	// Control calls go to the main capability, whichever Connection the
	// environment selected.
	parsed.User = url.UserPassword("phase", password)
	transport := &http.Transport{
		Proxy:       http.ProxyURL(parsed),
		DialContext: (&net.Dialer{Timeout: Timeout}).DialContext,
	}
	return &http.Client{
		Transport: transport, Timeout: Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// sessionKey fetches the key once per process and proxy.
func sessionKey(ctx context.Context, client *http.Client) (*censor.Key, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	current := proxyURL()
	if cachedKey != nil && keyProxy == current {
		return cachedKey, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, phaseproxy.ControlURL+"/v1/inventory/key", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("the Phase AI proxy did not answer")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Phase AI proxy refused the key request (HTTP %d)", response.StatusCode)
	}
	var answer remoteapi.InventoryKeyResponse
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer) != nil ||
		answer.SchemaVersion != agentapi.SchemaVersion || answer.Format != censor.EntriesVersion {
		return nil, errors.New("the Phase AI proxy sent a key this version of Phase does not read")
	}
	raw, err := base64.StdEncoding.DecodeString(answer.Key)
	if err != nil {
		return nil, errors.New("the Phase AI proxy sent an invalid key")
	}
	key, err := censor.KeyFromBytes(raw)
	if err != nil {
		return nil, errors.New("the Phase AI proxy sent an invalid key")
	}
	cachedKey, keyProxy = key, current
	return key, nil
}

func post(ctx context.Context, client *http.Client, entries []json.RawMessage) (Result, error) {
	body, err := json.Marshal(remoteapi.InventoryRequest{SchemaVersion: agentapi.SchemaVersion, Entries: entries})
	if err != nil {
		return Result{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, phaseproxy.ControlURL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Result{}, errors.New("the Phase AI proxy did not answer")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		if failure.Error.Code == "leak_inventory_full" {
			return Result{}, ErrInventoryFull
		}
		return Result{}, fmt.Errorf("the Phase AI proxy refused the values (HTTP %d)", response.StatusCode)
	}
	var answer remoteapi.InventoryResponse
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer) != nil || answer.SchemaVersion != agentapi.SchemaVersion {
		return Result{}, errors.New("the Phase AI proxy sent an answer this version of Phase does not read")
	}
	return Result{Added: answer.Added, Unprotected: answer.Unprotected}, nil
}
