// Package leakguard registers secret values the CLI is about to hand out with
// the leak protection of every running Phase AI proxy. It indexes each value
// locally with a proxy's key and sends only keyed hashes; the proxy then
// replaces the value with ph:<type>:<id> wherever it appears in model traffic.
// The type and the id are the caller's and nothing of a proxy's key goes into
// them, so a value has the same placeholder at every proxy that knows it.
//
// The proxies are found through an ordered list of sources: the session a
// command runs in names its proxy in the environment, and other sources find
// one that runs on the machine. Each reads model traffic the others do not
// see, so a value is registered with every one that is found, one after
// another. When no source finds one the package does nothing and makes no
// call, unless the environment still carries the session's marker: a
// registration then fails, as it does when the session's proxy is down. A
// source can also say its proxy is restarting; a registration then waits for
// it, for Timeout in all.
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
	"slices"
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
// this long for a proxy that is restarting to come back. With more than one
// proxy to register with it is also what they share: see Proxy.Register.
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

// ErrInventoryFull is returned when the proxy holds as many values as it can.
// The proxy answered: it is reachable, it just cannot protect more values.
var ErrInventoryFull = errors.New("the leak protection inventory is full")

// ErrNotListening is returned when nothing accepts connections at the
// proxy's address: the connection was refused, or was not made within the
// dial timeout. No proxy runs there. A proxy that took the connection and is
// slow, or answers with something this version does not read, is another
// error.
var ErrNotListening = errors.New("nothing is listening at the Phase AI proxy's address")

// ErrRestarting is returned when the proxy's process runs but took no
// registration in time: it was starting, or between two sessions with its
// listener closed, and did not come back in the time the registration had,
// which is Timeout unless other proxies were registered with before it. Its
// values are not protected; unlike ErrNotListening it does not mean no proxy
// runs.
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
	// sources are asked in order. The session's own environment comes first:
	// a command inside a session registers with that session's proxy before
	// any other.
	sources = []Source{{Name: SourceSession, Find: sessionProxy}}
)

func sessionProxy() (string, bool) {
	if !Active() {
		return "", false
	}
	return proxyURL(), true
}

// AddSource adds a way to find a running proxy, asked after the ones already
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
	// source is that source, asked again while the proxy is restarting.
	source *Source
	// turns is what the proxies found together share: the time one command
	// spends registering with them.
	turns *turns
}

// turns is shared by the proxies one Locate found. It holds when the first
// registration with any of them began, which is what the time of the
// registrations after it is counted from.
type turns struct {
	mu    sync.Mutex
	began time.Time
}

// next says how long the registration that begins now may spend on its proxy.
// The first has a registration's usual bounds and no limit of its own. Each
// one after it has what is left of Timeout since the first began, and never
// less than one dial timeout: a proxy that is slow, or away, costs the proxies
// after it nothing but that.
func (t *turns) next() (allowed time.Duration, limited bool) {
	if t == nil {
		return 0, false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.began.IsZero() {
		t.began = now
		return 0, false
	}
	return max(t.began.Add(Timeout).Sub(now), dialTimeout), true
}

// InSession reports a proxy named by the process's own environment: the
// command runs inside that proxy's session, where what it hands out is read
// by the model unless the proxy removes it.
func (p Proxy) InSession() bool { return p.Source == SourceSession }

// Locate returns every proxy to register with, in the order of the sources:
// each one a source finds, or says is restarting. Inside a session the
// session's own proxy is the first of them. None means no proxy runs.
//
// Every source is asked each time, the session's or not: a proxy that runs on
// the machine reads the model traffic of tools the session's proxy never
// sees, and a value handed out in the session can reach those too. A proxy
// two sources find is one proxy, and is returned once, as the earlier
// source's: a shell that loads the environment of the proxy the harness hooks
// keep running has that proxy as its session's own.
//
// A session whose environment kept the marker and lost the proxy is still a
// session: what a command hands out there is in front of the model. When no
// source finds a proxy for it, it is returned as the session's proxy with no
// address, so a registration fails as it does for a session whose proxy is
// down, and is not taken for a shell outside any session.
//
// The proxies returned were found together, and share the time one command
// spends registering (Proxy.Register).
func Locate() []Proxy {
	sourcesMu.RLock()
	ordered := sources
	sourcesMu.RUnlock()
	var (
		proxies []Proxy
		shared  *turns
	)
	for index := range ordered {
		source := &ordered[index]
		found, ok := source.Find()
		if !ok || found == "" {
			if source.Restarting == nil || !source.Restarting() {
				continue
			}
			// Away for a moment: Register waits for its source to find it.
			found = ""
		} else if slices.ContainsFunc(proxies, func(earlier Proxy) bool { return earlier.URL == found }) {
			continue
		}
		if shared == nil {
			shared = &turns{}
		}
		proxies = append(proxies, Proxy{URL: found, Source: source.Name, source: source, turns: shared})
	}
	if len(proxies) == 0 && marked() {
		return []Proxy{{Source: SourceSession, turns: &turns{}}}
	}
	return proxies
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

// maxCachedKeys bounds the keys kept. They are as many as the proxies a
// process registers with, and one more each time one of them comes back from
// a restart as another process.
const maxCachedKeys = 16

var (
	keyMu sync.Mutex
	// cachedKeys holds the key of each proxy this process fetched one from,
	// by the proxy's address with its capability.
	cachedKeys = map[string]*censor.Key{}
)

// Register protects values with the leak protection of every proxy Locate
// finds, one after another. It does nothing when none is found, or when there
// is nothing to protect. What it returns is what the first of them came to,
// which inside a session is the session's own proxy; a caller that has to
// know of each registers with the proxies Locate returns itself.
func Register(ctx context.Context, values []Value) (Result, error) {
	var (
		result Result
		failed error
	)
	for index, proxy := range Locate() {
		registered, err := proxy.Register(ctx, values)
		if index == 0 {
			result, failed = registered, err
		}
	}
	return result, failed
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
//
// The proxies one Locate found are registered with one after another, and a
// command must not wait on each of them in turn as long as it would on one.
// So only the first registration with any of them has the bounds above. Each
// one after it has what is left of Timeout since the first began, for its
// wait and its calls together, and never less than one dial timeout. Its dial
// is given at most half of what it has: it is then the dial that runs out
// first, and is seen to, so nothing listening is still told from a proxy that
// did not answer. A proxy that runs answers in a fraction of either. Indexing
// is local work and is not counted.
func (p Proxy) Register(ctx context.Context, values []Value) (Result, error) {
	values = protectable(values)
	if len(values) == 0 {
		return Result{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// wait is how long a proxy that is restarting is waited for, and whole the
	// longest a dial is given: one given less was cut short by the wait's end.
	wait, whole := Timeout, dialTimeout
	allowed, limited := p.turns.next()
	if limited {
		wait, whole = allowed, min(dialTimeout, allowed/2)
	}
	address, dial := p.URL, whole
	deadline := time.Now().Add(wait)
	for {
		if address == "" && p.source != nil {
			if found, ok := p.source.Find(); ok {
				address = found
			}
		}
		if address != "" {
			calls := bounds{dial: dial, key: Timeout, values: Timeout}
			if limited {
				calls = bounds{dial: dial, key: time.Until(deadline), shared: true}
			}
			result, err := register(ctx, address, values, calls)
			if !errors.Is(err, ErrNotListening) {
				return result, err
			}
			if dial < whole && time.Until(deadline) <= 0 {
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
		dial = min(whole, left)
		// Its source is asked again: the proxy may come back at another
		// address, or as another process with another capability.
		address = ""
	}
}

// bounds are how long the calls of one registration may take: the connection
// to be made, the key request, and the registrations of the values together.
// With shared set the registrations have what the key request left of key.
type bounds struct {
	dial, key, values time.Duration
	shared            bool
}

// register sends values, already filtered, to the proxy at address, its URL
// with its capability, within the bounds given.
func register(ctx context.Context, address string, values []Value, within bounds) (Result, error) {
	var result Result
	client, err := controlClient(address, within.dial, Timeout)
	if err != nil {
		return result, err
	}
	asked := time.Now()
	keyContext, cancelKey := context.WithTimeout(ctx, within.key)
	key, err := proxyKey(keyContext, client, address)
	cancelKey()
	if err != nil {
		return result, err
	}
	if within.shared {
		within.values = within.key - time.Since(asked)
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
	postContext, cancelPost := context.WithTimeout(ctx, within.values)
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
	if key := cachedKeys[current]; key != nil {
		return key, nil
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
	if len(cachedKeys) >= maxCachedKeys {
		clear(cachedKeys)
	}
	cachedKeys[current] = key
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
