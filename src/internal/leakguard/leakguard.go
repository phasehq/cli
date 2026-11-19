// Package leakguard registers secret values the CLI is about to hand out with
// the leak protection of a running Phase AI proxy. It indexes each value
// locally with the proxy's key and sends only keyed hashes; the proxy then
// replaces the value with ph:<type>:<id> wherever it appears in model traffic.
//
// The proxy is found through an ordered list of sources: the session a
// command runs in names it in the environment, and other sources find one
// that runs on the machine for commands whose shell does not carry that
// environment. When no source finds one it does nothing and makes no call.
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
	"net/http"
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
	Type string
	ID   string
	// KeyName says ID is the secret's key name and not an id the Console
	// issued. The proxy is told, and keeps such an id out of the events it
	// sends: the Console does not know the key names of an end-to-end
	// encrypted app. The placeholder the model sees is the same either way.
	KeyName bool
	Value   string
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

// ErrNotListening is returned when nothing accepts connections at the
// proxy's address: no proxy runs there. A proxy that is slow, or answers
// with something this version does not read, is another error.
var ErrNotListening = errors.New("nothing is listening at the Phase AI proxy's address")

// unanswered is the error for a call the proxy did not answer.
func unanswered(err error) error {
	if connectionRefused(err) {
		return ErrNotListening
	}
	return errors.New("the Phase AI proxy did not answer")
}

// Environment is what the package reads from the process's environment;
// tests replace it.
var Environment = os.Getenv

// Active reports whether this process runs inside a Phase AI session: the
// session marker and the proxy that carries the session's capability are both
// in its environment.
func Active() bool {
	return Environment("PHASE_AI_ENABLED") == "1" && proxyURL() != ""
}

// SourceSession is the source that reads the session's own environment.
const SourceSession = "session"

// Source is one way to find a running Phase AI proxy. Find returns the
// proxy's address with its capability, as a runtime hands it out, and whether
// one runs. Every command that hands out a value calls it, so it must cost
// next to nothing when no proxy runs: a look at the environment or one file,
// never the network.
type Source struct {
	Name string
	Find func() (proxyURL string, found bool)
}

var (
	sourcesMu sync.RWMutex
	// sources are tried in order. The session's own environment comes first:
	// a command inside a session registers with that session's proxy.
	sources = []Source{{Name: SourceSession, Find: sessionProxy}}
)

func sessionProxy() (string, bool) {
	if !Active() {
		return "", false
	}
	return proxyURL(), true
}

// AddSource adds a way to find a running proxy, tried after the ones already
// there.
func AddSource(source Source) {
	if source.Name == "" || source.Find == nil {
		return
	}
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	sources = append(sources, source)
}

// Proxy is a running Phase AI proxy to register values with.
type Proxy struct {
	// URL is the proxy's address with its capability.
	URL string
	// Source names the source that found it.
	Source string
}

// InSession reports a proxy named by the process's own environment: the
// command runs inside that proxy's session, where what it hands out is read
// by the model unless the proxy removes it.
func (p Proxy) InSession() bool { return p.Source == SourceSession }

// Locate returns the proxy to register with: the first one a source finds.
func Locate() (Proxy, bool) {
	sourcesMu.RLock()
	ordered := sources
	sourcesMu.RUnlock()
	for _, source := range ordered {
		if found, ok := source.Find(); ok && found != "" {
			return Proxy{URL: found, Source: source.Name}, true
		}
	}
	return Proxy{}, false
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

// Register protects values with the leak protection of the proxy Locate
// finds. It does nothing when none is found, or when there is nothing to
// protect.
func Register(ctx context.Context, values []Value) (Result, error) {
	proxy, found := Locate()
	if !found {
		return Result{}, nil
	}
	return proxy.Register(ctx, values)
}

// registration is one POST: entries and, for each, what its id is.
type registration struct {
	entries []json.RawMessage
	kinds   []string
}

// Register protects values with this proxy's leak protection. It never sends
// a value: the proxy receives keyed hashes only.
func (p Proxy) Register(ctx context.Context, values []Value) (Result, error) {
	var result Result
	values = protectable(values)
	if len(values) == 0 {
		return result, nil
	}
	client, err := phaseproxy.ControlClient(p.URL, Timeout, Timeout)
	if err != nil {
		return result, err
	}
	keyContext, cancelKey := context.WithTimeout(ctx, Timeout)
	key, err := proxyKey(keyContext, client, p.URL)
	cancelKey()
	if err != nil {
		return result, err
	}
	// Indexing is local work, so only the calls to the proxy count against
	// the timeout: the key above, and the registrations below together.
	var batches []registration
	var batch registration
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
		if size+len(encoded) > maxBatchBytes && len(batch.entries) > 0 {
			batches, batch, size = append(batches, batch), registration{}, 0
		}
		kind := remoteapi.InventoryIDPhase
		if value.KeyName {
			kind = remoteapi.InventoryIDKeyName
		}
		batch.entries, batch.kinds = append(batch.entries, encoded), append(batch.kinds, kind)
		size += len(encoded)
	}
	if len(batch.entries) > 0 {
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

// proxyKey fetches a proxy's key once per process and proxy.
func proxyKey(ctx context.Context, client *http.Client, current string) (*censor.Key, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if cachedKey != nil && keyProxy == current {
		return cachedKey, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, phaseproxy.ControlURL+"/v1/inventory/key", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, unanswered(err)
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

func post(ctx context.Context, client *http.Client, batch registration) (Result, error) {
	body, err := json.Marshal(remoteapi.InventoryRequest{SchemaVersion: agentapi.SchemaVersion, Entries: batch.entries, IDKinds: batch.kinds})
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
		return Result{}, unanswered(err)
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
