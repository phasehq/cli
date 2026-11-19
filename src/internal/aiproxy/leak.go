package aiproxy

import (
	"errors"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
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
	// skipped are the pattern rules this proxy is not applying. Status counts
	// and names them.
	skipped  []censor.SkippedRule
	reported *placeholderLog

	// matches remembers what the table says about the hosts seen, per flow, so
	// the check every request makes allocates nothing.
	matchMu sync.Mutex
	matches map[leakMatchKey]*leakHostMatch

	mu sync.Mutex
	// unprotected names the type and id of values that could not be indexed.
	// They are counted for status and never returned.
	unprotected map[string]struct{}
	// keyNamed holds the placeholders whose id is a secret's key name, as the
	// client that registered them said. An event never carries such an id.
	keyNamed map[string]struct{}

	handshakes *handshakeTracker
	unread     *unreadLog
	// mirrored keeps the hellos of clients whose hello is copied, as they
	// sent them with no session to offer.
	mirrored *freshHellos
}

// leakMatchKey is a flow and the host as a client wrote it.
type leakMatchKey struct {
	tool, capture, host string
}

func newLeakGuard(mode string) (*leakGuard, error) {
	return newLeakGuardWithRules(mode, censor.DefaultRules())
}

// leakRuleAbsent is why a rule the proxy depends on is not applied when its
// rule file does not hold it.
const leakRuleAbsent = "the rule file does not hold this rule"

// newLeakGuardWithRules makes the guard for a rule file. The file can be
// newer or older than the binary, so a rule in it that this version cannot
// apply, and a Phase token rule it does not hold, never stop the proxy: the
// rules that do apply still protect, and status says what was left out.
func newLeakGuardWithRules(mode string, rules *censor.Rules) (*leakGuard, error) {
	key, err := censor.NewKey()
	if err != nil {
		return nil, err
	}
	index, err := censor.NewIndex(key, censor.IndexOptions{Rules: rules})
	if err != nil {
		return nil, err
	}
	limited, absent, err := phaseTokenRuleSet(rules)
	if err != nil {
		return nil, err
	}
	return &leakGuard{
		mode: leakModeFrom(mode), hosts: defaultLeakHosts, key: key, index: index, limitedRules: limited,
		skipped:  append(rules.Skipped(), absent...),
		reported: newPlaceholderLog(), unprotected: map[string]struct{}{}, keyNamed: map[string]struct{}{},
		handshakes: newHandshakeTracker(), unread: newUnreadLog(), mirrored: newFreshHellos(),
	}, nil
}

// phaseTokenRuleSet returns the rules that run on every path of an inspected
// host: Phase's own token formats, as far as the rule file holds them. A rule
// the file does not hold is returned as left out. One the file holds and this
// version could not apply is left out too, and is already among the file's
// skipped rules.
func phaseTokenRuleSet(rules *censor.Rules) (*censor.Rules, []censor.SkippedRule, error) {
	var held []string
	var absent []censor.SkippedRule
	for _, id := range phaseTokenRules {
		one, err := rules.Only(id)
		switch {
		case err != nil:
			// Only refuses an id the file never had.
			absent = append(absent, censor.SkippedRule{ID: id, Reason: leakRuleAbsent})
		case one.Len() > 0:
			held = append(held, id)
		}
	}
	limited, err := rules.Only(held...)
	return limited, absent, err
}

// maxStatusRules bounds the rule ids status names; the count goes on past it.
const maxStatusRules = 64

// skippedRuleIDs names the rules that are not applied, for status. An id is
// text from the rule file, so only one that is a plain identifier is named.
func (g *leakGuard) skippedRuleIDs() []string {
	var ids []string
	for _, rule := range g.skipped {
		if len(ids) < maxStatusRules && controlIdentifier.MatchString(rule.ID) && !slices.Contains(ids, rule.ID) {
			ids = append(ids, rule.ID)
		}
	}
	sort.Strings(ids)
	return ids
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

// Placeholders already reported, per tool and host, so the history every model
// request repeats is reported once. The set is bounded; once one is full, new
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
	hosts map[leakStateKey]*reportedHost
	now   func() time.Time
}

func newPlaceholderLog() *placeholderLog {
	return &placeholderLog{hosts: map[leakStateKey]*reportedHost{}}
}

// fresh returns the placeholders not yet reported for a tool and host and
// marks them reported. Only hosts in the table are ever inspected, so the map
// stays small; it is bounded all the same.
func (l *placeholderLog) fresh(key leakStateKey, placeholders []string) []string {
	if len(placeholders) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.hosts[key]
	if state == nil {
		// A domain entry matches any number of subdomains.
		if len(l.hosts) >= maxRememberedHosts {
			clear(l.hosts)
		}
		state = &reportedHost{seen: map[string]struct{}{}}
		l.hosts[key] = state
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

// Something left unread is reported once for its tool, host and reason, then
// at most once a minute: a client whose connections, bodies or messages cannot
// be read sends one after another, and each would say the same thing. A
// finding that sits only in text the provider signed is limited the same way,
// under a reason of its own.
const (
	unreadPeriod = time.Minute
	// leakQuietSignedText is the key a signed-text finding is limited under.
	// It is never an event's reason.
	leakQuietSignedText = "signed_text"
)

type unreadKey struct {
	leakStateKey
	reason string
}

type unreadLog struct {
	mu   sync.Mutex
	last map[unreadKey]time.Time
	now  func() time.Time
}

func newUnreadLog() *unreadLog {
	return &unreadLog{last: map[unreadKey]time.Time{}}
}

// fresh reports whether something left unread for reason is to be reported
// now, and remembers that it was.
func (l *unreadLog) fresh(key leakStateKey, reason string) bool {
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	entry := unreadKey{leakStateKey: key, reason: reason}
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, reported := l.last[entry]; reported && now.Sub(last) < unreadPeriod {
		return false
	}
	// A domain entry matches any number of subdomains.
	if len(l.last) >= maxRememberedHosts {
		clear(l.last)
	}
	l.last[entry] = now
	return true
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

// maxUnprotectedNames bounds the values remembered as too short or plain to
// protect. Such a value adds nothing to the index, so the index's own caps do
// not bound them; past this the count stays where it is.
const maxUnprotectedNames = 4096

// add indexes validated entries. Nothing of a batch is added once the index is
// full, and the entries added before it stay. keyNamed says, entry by entry,
// that the entry's id is a secret's key name; an entry it does not cover has
// an id the Console issued.
func (g *leakGuard) add(entries []*censor.Entries, keyNamed []bool) (added, unprotected int, err error) {
	for i, entry := range entries {
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
			// Once a placeholder is known to hold a key name it stays so,
			// whatever a later registration says of the same id.
			if i < len(keyNamed) && keyNamed[i] {
				g.keyNamed[entry.Placeholder()] = struct{}{}
			}
			added++
		} else {
			// A value is counted once however often it is registered, and the
			// names kept for that are bounded.
			if _, counted := g.unprotected[name]; !counted && len(g.unprotected) < maxUnprotectedNames {
				g.unprotected[name] = struct{}{}
			}
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

// eventPlaceholders is how placeholders are written in an event. One whose id
// is a secret's key name is written as ph:<type> alone, once for its type: the
// Console does not know the key names of an end-to-end encrypted app, and an
// event must not tell it. What the model is shown keeps the whole placeholder.
func (g *leakGuard) eventPlaceholders(placeholders []string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.keyNamed) == 0 {
		return placeholders
	}
	written := make([]string, 0, len(placeholders))
	for _, placeholder := range placeholders {
		if _, named := g.keyNamed[placeholder]; named {
			placeholder = placeholder[:strings.LastIndexByte(placeholder, ':')]
			if slices.Contains(written, placeholder) {
				continue
			}
		}
		written = append(written, placeholder)
	}
	return written
}

// status is counts and names only: of hosts, and of pattern rules. Every
// listed host is read for a client of the proxy environment, whichever tool
// the proxy serves, so the hosts are the table's.
func (g *leakGuard) status() *remoteapi.LeakProtectionStatus {
	inspected := g.hosts.hostNames(leakTreatmentInspect)
	unread := g.hosts.hostNames(leakTreatmentUnread)
	if g.mode == leakModeOff {
		unread = append(inspected, unread...)
		inspected = []string{}
	} else if bypassed := g.handshakes.bypassedHosts(); len(bypassed) > 0 {
		kept := inspected[:0:0]
		for _, host := range inspected {
			if slices.Contains(bypassed, host) {
				unread = append(unread, host)
				continue
			}
			kept = append(kept, host)
		}
		inspected = kept
	}
	sort.Strings(unread)
	if inspected == nil {
		inspected = []string{}
	}
	if unread == nil {
		unread = []string{}
	}
	return &remoteapi.LeakProtectionStatus{
		Mode: g.mode, SecretsKnown: g.index.Stats().Secrets, Unprotected: g.unprotectedCount(),
		InspectedHosts: inspected, UnreadHosts: unread,
		RulesSkipped: len(g.skipped), SkippedRules: g.skippedRuleIDs(),
	}
}

func containsString(values []string, value string) bool {
	return slices.Contains(values, value)
}

// inspects reports what the table says about a CONNECT target for a flow.
// Hosts the table reads are answered with the proxy's certificate on port 443
// only.
func (g *leakGuard) inspects(flow FlowContext, host string, port int) *leakHostMatch {
	if g == nil || g.mode == leakModeOff || port != 443 {
		return nil
	}
	// A tunnel's flow from a program that is not a listed tool is never read.
	if flow.Tool == "" && flow.Capture == CaptureTunnel {
		return nil
	}
	key := leakMatchKey{tool: flow.Tool, capture: flow.capture(), host: host}
	g.matchMu.Lock()
	match, known := g.matches[key]
	g.matchMu.Unlock()
	if !known {
		match = g.hosts.lookupFlow(flow, host)
		if match != nil {
			g.matchMu.Lock()
			if g.matches == nil || len(g.matches) >= maxRememberedHosts {
				g.matches = map[leakMatchKey]*leakHostMatch{}
			}
			g.matches[key] = match
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
//   - it is per tool and host: one host's refusals say nothing about
//     another's, and one tool's refusals say nothing about another tool on
//     the same host;
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
	hosts map[leakStateKey]*handshakeState
	now   func() time.Time
}

func newHandshakeTracker() *handshakeTracker {
	return &handshakeTracker{hosts: map[leakStateKey]*handshakeState{}}
}

func (t *handshakeTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// note records how a handshake went, and returns the length of the window it
// opened, if it opened one.
func (t *handshakeTracker) note(key leakStateKey, ok bool) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok {
		delete(t.hosts, key)
		return 0
	}
	state := t.hosts[key]
	if state == nil {
		state = &handshakeState{}
		t.hosts[key] = state
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

func (t *handshakeTracker) bypassed(key leakStateKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.hosts[key]
	return state != nil && t.clock().Before(state.until)
}

// bypassedHosts names the hosts in a window for any tool.
func (t *handshakeTracker) bypassedHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	var hosts []string
	for key, state := range t.hosts {
		if now.Before(state.until) && !slices.Contains(hosts, key.host) {
			hosts = append(hosts, key.host)
		}
	}
	return hosts
}
