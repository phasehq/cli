// Package leakguard registers secret values the CLI is about to hand out with
// the leak protection of a running Phase AI proxy. It indexes each value
// locally with the proxy's key and sends only keyed hashes; the proxy then
// replaces the value with ph:<type>:<id> wherever it appears in model traffic.
//
// The proxy is found through an ordered list of sources: the session a
// command runs in names it in the environment, and other sources find one
// that runs on the machine for commands whose shell does not carry that
// environment. When no source finds one it does nothing and makes no call,
// unless the environment still carries the session's marker: a registration
// then fails, as it does when the session's proxy is down.
// A source can also say its proxy is restarting; a registration then waits
// for it, for Timeout in all.
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
// out values waits at most this long for the proxy, and, before that, at most
// this long for a proxy that is restarting to come back.
const Timeout = time.Second

// dialTimeout bounds the connection to the proxy's address, which is always
// a loopback one. A proxy that listens there takes the connection at once.
// Where nothing listens most systems refuse at once too, but that cannot be
// counted on: left to itself Windows tries again for a second or two before
// it says so. Go asks it not to for a loopback address, which is best effort
// and which Windows before build 16299 honours only in part. A command that
// finds stale state must not stall that long to learn there is no proxy. The
// timeout is well under Timeout, so it is the dial that runs out of time, and
// is seen to, before anything else does. Tests change it.
var dialTimeout = 250 * time.Millisecond

// controlClient makes the client a registration reaches the proxy with; tests
// replace it to change how a connection fails.
var controlClient = phaseproxy.ControlClient

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

// ErrInventoryFull is returned when the proxy answered and has no room for
// more values from this login. A proxy that starts again has room.
var ErrInventoryFull = errors.New("the leak protection inventory is full")

// ErrNotListening is returned when nothing accepts connections at the
// proxy's address: the connection was refused, or was not made within the
// dial timeout. No proxy runs there. A proxy that took the connection and is
// slow, or answers with something this version does not read, is another
// error.
var ErrNotListening = errors.New("nothing is listening at the Phase AI proxy's address")

// ErrRestarting is returned when the proxy's process runs but took no
// registration in time: it was starting, or between two sessions with its
// listener closed, and did not come back within Timeout. Its values are not
// protected; unlike ErrNotListening it does not mean no proxy runs.
var ErrRestarting = errors.New("the Phase AI proxy is restarting and did not come back in time")

// restartPoll is how often a proxy that is restarting is looked for again.
var restartPoll = 25 * time.Millisecond

// unanswered is the error for a call the proxy did not answer.
//
// A connection that was refused means nothing listens at the proxy's address.
// So does one that was not made within dialTimeout, on every platform: the
// address is a loopback one, so there is no network to blame for a dial that
// hangs, and that is how a port nothing listens on shows where the system is
// slow to refuse, as Windows can be (see dialTimeout). Both are
// ErrNotListening. What that means is for the caller to say by where the
// proxy was found. Outside the session's environment it is no proxy running:
// the state that named the address is stale, and a command says nothing.
// Inside a session, whose own proxy is meant to be there, it is a failure
// like any other. A proxy that took the connection and did not answer in
// time is not ErrNotListening anywhere.
func unanswered(err error) error {
	if connectionRefused(err) || dialTimedOut(err) {
		return ErrNotListening
	}
	return errors.New("the Phase AI proxy did not answer")
}

// dialTimedOut reports a call that failed because the connection to the
// proxy's address was not made in time.
func dialTimedOut(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if operation, ok := err.(*net.OpError); ok && operation.Op == "dial" {
			return operation.Timeout()
		}
	}
	return false
}

// Environment is what the package reads from the process's environment;
// tests replace it.
var Environment = os.Getenv

// Active reports whether this process runs inside a Phase AI session: the
// session marker and the proxy that carries the session's capability are both
// in its environment.
func Active() bool {
	return marked() && proxyURL() != ""
}

// marked reports the session marker alone. With no proxy beside it the
// process still runs inside a session, one whose proxy it cannot name.
func marked() bool {
	return Environment("PHASE_AI_ENABLED") == "1"
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
	// Restarting is optional. It reports a proxy of this source whose process
	// runs and takes no registration at this moment: it is starting, or it
	// is between two sessions and its listener is closed. Register waits for
	// such a proxy, because a value handed out meanwhile would never reach
	// the inventory the proxy comes back with. It is asked only when Find
	// found nothing, or nothing listened where Find pointed, and like Find
	// it looks at a file or two and never at the network.
	Restarting func() bool
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
	// URL is the proxy's address with its capability. It is empty for a
	// proxy that is restarting: Register waits for its source to find it.
	URL string
	// Source names the source that found it.
	Source string
	// Identity is who the registering command is, never who the proxy is:
	// the proxy is told. Zero when the command cannot tell.
	Identity phaseproxy.InventoryIdentity
	// source is that source, asked again while the proxy is restarting.
	source *Source
}

// InSession reports a proxy named by the process's own environment: the
// command runs inside that proxy's session, where what it hands out is read
// by the model unless the proxy removes it.
func (p Proxy) InSession() bool { return p.Source == SourceSession }

// Locate returns the proxy to register with: the first one a source finds,
// or says is restarting.
//
// A session whose environment kept the marker and lost the proxy is still a
// session: what a command hands out there is in front of the model. When no
// source finds a proxy for it, it is returned as the session's proxy with no
// address, so a registration fails as it does for a session whose proxy is
// down, and is not taken for a shell outside any session.
func Locate() (Proxy, bool) {
	sourcesMu.RLock()
	ordered := sources
	sourcesMu.RUnlock()
	for index := range ordered {
		source := &ordered[index]
		if found, ok := source.Find(); ok && found != "" {
			return Proxy{URL: found, Source: source.Name, source: source}, true
		}
		if source.Restarting != nil && source.Restarting() {
			return Proxy{Source: source.Name, source: source}, true
		}
	}
	if marked() {
		return Proxy{Source: SourceSession}, true
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

// handedKey is what a proxy handed this command to index with.
type handedKey struct {
	key *censor.Key
	// scheme is the matching scheme the proxy reads: this build's or an older one.
	scheme int
	// id names the keys to the proxy, which refuses entries made under others.
	id string
}

// keyFor is who a key was handed to, at which proxy.
type keyFor struct {
	proxy    string
	identity phaseproxy.InventoryIdentity
}

var (
	keyMu      sync.Mutex
	cachedKeys = map[keyFor]handedKey{}
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
//
// When nothing listens at the proxy's address, or its source has not found it
// yet, and the source says the proxy is restarting, Register waits for it: it
// asks the source again every few milliseconds and registers once the proxy
// is back. The wait is Timeout in all, counted from the first look, so the
// dials that found nothing listening are part of it, and the last of them is
// cut short where the wait ends. If the proxy is not back in time the error
// is ErrRestarting. A source that says nothing of the kind leaves
// ErrNotListening, after one dial.
func (p Proxy) Register(ctx context.Context, values []Value) (Result, error) {
	values = protectable(values)
	if len(values) == 0 {
		return Result{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	address, dial := p.URL, dialTimeout
	deadline := time.Now().Add(Timeout)
	for {
		if address == "" && p.source != nil {
			if found, ok := p.source.Find(); ok {
				address = found
			}
		}
		if address != "" {
			result, err := register(ctx, address, p.Identity, values, dial)
			if !errors.Is(err, ErrNotListening) {
				return result, err
			}
			if dial < dialTimeout && time.Until(deadline) <= 0 {
				// The end of the wait cut this dial short, so running out of
				// time says nothing of what listens there: the proxy may be
				// back and not have been given the time to take the
				// connection. The wait is over, and that is all that is known.
				return Result{}, ErrRestarting
			}
		}
		if p.source == nil || p.source.Restarting == nil || !p.source.Restarting() {
			return Result{}, ErrNotListening
		}
		left := time.Until(deadline)
		if left <= 0 {
			return Result{}, ErrRestarting
		}
		select {
		case <-ctx.Done():
			return Result{}, ErrRestarting
		case <-time.After(min(restartPoll, left)):
		}
		if left = time.Until(deadline); left <= 0 {
			return Result{}, ErrRestarting
		}
		// The next dial ends with the wait at the latest: where a dial to an
		// address nothing listens at takes its whole timeout, a few of them
		// would otherwise carry the wait past its end.
		dial = min(dialTimeout, left)
		// Its source is asked again: the proxy may come back at another
		// address, or as another process with another capability.
		address = ""
	}
}

// errKeyChanged is the proxy refusing entries made under keys it no longer
// hands this command: the key is fetched again and the values indexed again.
var errKeyChanged = errors.New("the Phase AI proxy uses another key for this command")

// register sends filtered values to the proxy at address, its URL with its
// capability, as the command identity says it is. dial bounds the connection.
func register(ctx context.Context, address string, identity phaseproxy.InventoryIdentity, values []Value, dial time.Duration) (Result, error) {
	client, err := controlClient(address, dial, Timeout)
	if err != nil {
		return Result{}, err
	}
	result, err := registerWith(ctx, client, address, identity, values)
	if errors.Is(err, errKeyChanged) {
		// Nothing of the refused registration was added.
		keyMu.Lock()
		delete(cachedKeys, keyFor{address, identity})
		keyMu.Unlock()
		result, err = registerWith(ctx, client, address, identity, values)
	}
	return result, err
}

func registerWith(ctx context.Context, client *http.Client, address string, identity phaseproxy.InventoryIdentity, values []Value) (Result, error) {
	var result Result
	keyContext, cancelKey := context.WithTimeout(ctx, Timeout)
	handed, err := proxyKey(keyContext, client, address, identity)
	cancelKey()
	if err != nil {
		return result, err
	}
	key, scheme := handed.key, handed.scheme
	// Indexing is local work, so only the calls to the proxy count against
	// the timeout: the key above, and the registrations below together.
	var batches []registration
	var batch registration
	size := 0
	for _, value := range values {
		entries, err := censor.IndexValueScheme(key, scheme, value.Type, value.ID, value.Value)
		if err != nil {
			return result, errors.New("a value could not be indexed for leak protection")
		}
		encoded, err := entries.Marshal()
		if err != nil {
			return result, errors.New("a value could not be indexed for leak protection")
		}
		if len(encoded) > maxEntryBytes {
			// Too large to register: the proxy counts it as unprotected.
			tooLong := &censor.Entries{Version: scheme, Type: value.Type, ID: value.ID,
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
		added, err := post(postContext, client, identity, handed.id, batch)
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

// proxyKey fetches the keys a proxy hands a command that says it is identity,
// and the scheme the proxy reads: once per process, proxy and identity.
func proxyKey(ctx context.Context, client *http.Client, current string, identity phaseproxy.InventoryIdentity) (handedKey, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if handed, ok := cachedKeys[keyFor{current, identity}]; ok {
		return handed, nil
	}
	body, err := json.Marshal(remoteapi.InventoryKeyRequest{SchemaVersion: agentapi.SchemaVersion, Tenant: identity.Tenant, Login: identity.Login})
	if err != nil {
		return handedKey{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, phaseproxy.ControlURL+"/v1/inventory/key", bytes.NewReader(body))
	if err != nil {
		return handedKey{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return handedKey{}, unanswered(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return handedKey{}, fmt.Errorf("the Phase AI proxy refused the key request (HTTP %d)", response.StatusCode)
	}
	var answer remoteapi.InventoryKeyResponse
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer) != nil ||
		answer.SchemaVersion != agentapi.SchemaVersion || !censor.SchemeSupported(answer.Format) {
		return handedKey{}, errors.New("the Phase AI proxy sent a key this version of Phase does not read")
	}
	lookup, err := base64.StdEncoding.DecodeString(answer.Key)
	if err != nil {
		return handedKey{}, errors.New("the Phase AI proxy sent an invalid key")
	}
	// The confirming key is this login's own. A proxy that reads scheme 1
	// only sends the one key, which is all that scheme uses.
	var key *censor.Key
	if answer.ConfirmKey == "" {
		key, err = censor.LookupKeyFromBytes(lookup)
	} else if confirm, decodeErr := base64.StdEncoding.DecodeString(answer.ConfirmKey); decodeErr == nil {
		key, err = censor.KeyFromBytes(lookup, confirm)
	} else {
		err = decodeErr
	}
	if err != nil {
		return handedKey{}, errors.New("the Phase AI proxy sent an invalid key")
	}
	if !key.Supports(answer.Format) {
		return handedKey{}, errors.New("the Phase AI proxy sent a key this version of Phase does not read")
	}
	handed := handedKey{key: key, scheme: answer.Format, id: answer.KeyID}
	cachedKeys[keyFor{current, identity}] = handed
	return handed, nil
}

func post(ctx context.Context, client *http.Client, identity phaseproxy.InventoryIdentity, keyID string, batch registration) (Result, error) {
	body, err := json.Marshal(remoteapi.InventoryRequest{
		SchemaVersion: agentapi.SchemaVersion, Entries: batch.entries, IDKinds: batch.kinds,
		Tenant: identity.Tenant, Login: identity.Login, KeyID: keyID,
	})
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
		switch failure.Error.Code {
		case "leak_inventory_full":
			return Result{}, ErrInventoryFull
		case "inventory_key_changed":
			return Result{}, errKeyChanged
		}
		return Result{}, fmt.Errorf("the Phase AI proxy refused the values (HTTP %d)", response.StatusCode)
	}
	var answer remoteapi.InventoryResponse
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&answer) != nil || answer.SchemaVersion != agentapi.SchemaVersion {
		return Result{}, errors.New("the Phase AI proxy sent an answer this version of Phase does not read")
	}
	return Result{Added: answer.Added, Unprotected: answer.Unprotected}, nil
}
