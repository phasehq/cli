package aiproxy

import (
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

// LeakProtectionEnvironmentKey selects what the proxy does with model traffic:
// censor (the default), observe or off. It is read from the proxy process's own
// environment when the process starts.
const LeakProtectionEnvironmentKey = "PHASE_AI_LEAK_PROTECTION"

const (
	leakModeCensor  = "censor"
	leakModeObserve = "observe"
	leakModeOff     = "off"
)

// leakModeFrom reads the mode. Anything it does not know is the default, so a
// typo never turns protection off.
func leakModeFrom(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case leakModeObserve:
		return leakModeObserve
	case leakModeOff:
		return leakModeOff
	default:
		return leakModeCensor
	}
}

// leakGuard is the proxy process's inventory of secret values the CLI handed
// out, and what it knows about the hosts it inspects. It holds keyed hashes
// only and lives in memory for the life of the process: a recycled backend
// session keeps it, and nothing is written anywhere.
type leakGuard struct {
	mode  string
	hosts leakHostTable
	key   *censor.Key
	index *censor.Index
	// limitedRules are the rules applied off the conversation paths: only
	// Phase's own token formats. Elsewhere a pattern rule could fire on the
	// harness's own login or telemetry token and break it.
	limitedRules *censor.Rules
	reported     *placeholderLog

	// matches remembers what the table says about the hosts seen, so the
	// check every request makes allocates nothing.
	matchMu sync.Mutex
	matches map[string]*leakHostMatch

	mu sync.Mutex
	// unprotected names the type and id of values that could not be indexed.
	// They are counted for status and never returned.
	unprotected map[string]struct{}

	handshakes *handshakeTracker
}

func newLeakGuard(mode string) (*leakGuard, error) {
	key, err := censor.NewKey()
	if err != nil {
		return nil, err
	}
	index, err := censor.NewIndex(key, censor.IndexOptions{})
	if err != nil {
		return nil, err
	}
	limited, err := censor.DefaultRules().Only(phaseTokenRules...)
	if err != nil {
		return nil, err
	}
	return &leakGuard{
		mode: leakModeFrom(mode), hosts: defaultLeakHosts, key: key, index: index, limitedRules: limited,
		reported: newPlaceholderLog(), unprotected: map[string]struct{}{}, handshakes: newHandshakeTracker(),
	}, nil
}

// scanOptionsFor applies every rule where conversation content travels and
// only Phase's token rules elsewhere on the host. Indexed values are found on
// every path.
func (g *leakGuard) scanOptionsFor(match *leakHostMatch, path string) censor.ScanOptions {
	if match.conversation(path) {
		return censor.ScanOptions{}
	}
	return censor.ScanOptions{Rules: g.limitedRules}
}

func (g *leakGuard) newScan(match *leakHostMatch, protocol string, opts censor.ScanOptions) *leakScan {
	return &leakScan{match: match, mode: g.mode, protocol: protocol, opts: opts}
}

// Placeholders already reported, per host, so the history every model request
// repeats is reported once. The set is bounded; once a host's is full, new
// placeholders there are reported at most once a minute.
const (
	maxReportedPlaceholders = 4096
	reportedOverflowPeriod  = time.Minute
)

type reportedHost struct {
	seen     map[string]struct{}
	overflow time.Time
}

type placeholderLog struct {
	mu    sync.Mutex
	hosts map[string]*reportedHost
	now   func() time.Time
}

func newPlaceholderLog() *placeholderLog {
	return &placeholderLog{hosts: map[string]*reportedHost{}}
}

// fresh returns the placeholders not yet reported for host and marks them
// reported. Only hosts in the table are ever inspected, so the map of hosts
// stays small.
func (l *placeholderLog) fresh(host string, placeholders []string) []string {
	if len(placeholders) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.hosts[host]
	if state == nil {
		state = &reportedHost{seen: map[string]struct{}{}}
		l.hosts[host] = state
	}
	var fresh, unkept []string
	for _, placeholder := range placeholders {
		if _, done := state.seen[placeholder]; done {
			continue
		}
		if len(state.seen) < maxReportedPlaceholders {
			state.seen[placeholder] = struct{}{}
			fresh = append(fresh, placeholder)
			continue
		}
		unkept = append(unkept, placeholder)
	}
	if len(unkept) > 0 {
		now := time.Now()
		if l.now != nil {
			now = l.now()
		}
		if state.overflow.IsZero() || now.Sub(state.overflow) >= reportedOverflowPeriod {
			state.overflow = now
			fresh = append(fresh, unkept...)
		}
	}
	return fresh
}

// Certificate alerts (RFC 8446 section 6.2): bad_certificate,
// unsupported_certificate, certificate_revoked, certificate_expired,
// certificate_unknown and unknown_ca.
var certificateAlerts = map[uint64]bool{42: true, 43: true, 44: true, 45: true, 46: true, 48: true}

// refusedCertificate reports a handshake the client ended with a certificate
// alert. crypto/tls returns an alert it received as a net.OpError whose Op is
// "remote error" and whose Err is its unexported alert type, a uint8.
func refusedCertificate(err error) bool {
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" || remote.Err == nil {
		return false
	}
	alert := reflect.ValueOf(remote.Err)
	return alert.Kind() == reflect.Uint8 && certificateAlerts[alert.Uint()]
}

func newLeakGuardFromEnvironment() (*leakGuard, error) {
	return newLeakGuard(os.Getenv(LeakProtectionEnvironmentKey))
}

// errLeakInventoryFull is what a registration gets once the index is at a cap.
var errLeakInventoryFull = errors.New("the leak protection inventory is full")

// add indexes validated entries. Nothing of a batch is added once the index is
// full, and the entries added before it stay.
func (g *leakGuard) add(entries []*censor.Entries) (added, unprotected int, err error) {
	for _, entry := range entries {
		if err := g.index.Add(entry); err != nil {
			if errors.Is(err, censor.ErrIndexFull) {
				return added, unprotected, errLeakInventoryFull
			}
			return added, unprotected, err
		}
		name := entry.Type + ":" + entry.ID
		g.mu.Lock()
		if entry.Protected() {
			delete(g.unprotected, name)
			added++
		} else {
			g.unprotected[name] = struct{}{}
			unprotected++
		}
		g.mu.Unlock()
	}
	return added, unprotected, nil
}

func (g *leakGuard) unprotectedCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.unprotected)
}

// status is counts and host names only.
func (g *leakGuard) status() *remoteapi.LeakProtectionStatus {
	inspected := g.hosts.hostNames(leakTreatmentInspect)
	unread := g.hosts.hostNames(leakTreatmentUnread)
	if g.mode == leakModeOff {
		unread = append(inspected, unread...)
		inspected = []string{}
	} else if bypassed := g.handshakes.bypassedHosts(); len(bypassed) > 0 {
		kept := inspected[:0:0]
		for _, host := range inspected {
			if containsString(bypassed, host) {
				unread = append(unread, host)
				continue
			}
			kept = append(kept, host)
		}
		inspected = kept
	}
	if unread == nil {
		unread = []string{}
	}
	return &remoteapi.LeakProtectionStatus{
		Mode: g.mode, SecretsKnown: g.index.Stats().Secrets, Unprotected: g.unprotectedCount(),
		InspectedHosts: inspected, UnreadHosts: unread,
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// inspects reports what the table says about a CONNECT target. Hosts the
// table reads are answered with the proxy's certificate on port 443 only.
func (g *leakGuard) inspects(host string, port int) *leakHostMatch {
	if g == nil || g.mode == leakModeOff || port != 443 {
		return nil
	}
	g.matchMu.Lock()
	match, known := g.matches[host]
	g.matchMu.Unlock()
	if !known {
		match = g.hosts.lookup(host)
		if match != nil {
			g.matchMu.Lock()
			if g.matches == nil || len(g.matches) >= maxRememberedHosts {
				g.matches = map[string]*leakHostMatch{}
			}
			g.matches[host] = match
			g.matchMu.Unlock()
		}
	}
	if !match.inspected() {
		return nil
	}
	return match
}

// maxRememberedHosts bounds the matches kept; a domain entry matches any
// number of subdomains.
const maxRememberedHosts = 256

// Handshake pass-through windows. A client that will not complete TLS with the
// proxy's certificate would otherwise fail on every attempt, so after two
// refusals in a row its CONNECTs to that host are passed through unread for a
// while, longer each time it refuses again. A window is a period in which
// nothing is inspected, so it is kept narrow:
//   - only a refusal counts: the client answered the certificate with a TLS
//     certificate alert. A dropped connection, a reset, a timeout or bytes
//     that are not TLS say nothing about the certificate, and any process
//     could send them to open a window;
//   - it is per host: the proxy serves one session, and one host's refusals
//     say nothing about another's;
//   - one refusal is not enough, because a client can give up on one
//     connection for reasons of its own;
//   - a handshake that succeeds clears it.
const (
	handshakeBypassFirst = 20 * time.Second
	handshakeBypassMax   = 10 * time.Minute
)

type handshakeState struct {
	failures int
	until    time.Time
}

type handshakeTracker struct {
	mu    sync.Mutex
	hosts map[string]*handshakeState
	now   func() time.Time
}

func newHandshakeTracker() *handshakeTracker {
	return &handshakeTracker{hosts: map[string]*handshakeState{}}
}

func (t *handshakeTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// note records how a handshake went, and returns the length of the window it
// opened, if it opened one.
func (t *handshakeTracker) note(host string, ok bool) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok {
		delete(t.hosts, host)
		return 0
	}
	state := t.hosts[host]
	if state == nil {
		state = &handshakeState{}
		t.hosts[host] = state
	}
	state.failures++
	if state.failures < 2 {
		return 0
	}
	pause := handshakeBypassFirst << min(state.failures-2, 5)
	if pause > handshakeBypassMax {
		pause = handshakeBypassMax
	}
	state.until = t.clock().Add(pause)
	return pause
}

func (t *handshakeTracker) bypassed(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.hosts[host]
	return state != nil && t.clock().Before(state.until)
}

func (t *handshakeTracker) bypassedHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	var hosts []string
	for host, state := range t.hosts {
		if now.Before(state.until) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
