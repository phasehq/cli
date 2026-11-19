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
	// connections counts what became of the connections that were not simply
	// terminated and read: those handed to the service unread, and those
	// opened with a copy of the client's hello.
	connections *connectionLog
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
		handshakes: newHandshakeTracker(), unread: newUnreadLog(), mirrored: newFreshHellos(), connections: newConnectionLog(),
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
		protected, err := g.addOne(entry, i < len(keyNamed) && keyNamed[i])
		switch {
		case errors.Is(err, censor.ErrIndexFull):
			return added, unprotected, errLeakInventoryFull
		case err != nil:
			return added, unprotected, err
		case protected:
			added++
		default:
			unprotected++
		}
	}
	return added, unprotected, nil
}

// addOne indexes one entry and records what is known of its id. The guard's
// lock is held over both. A request scanned between the two would find the
// value and not know yet that its placeholder holds a key name, and its event
// would carry the name; eventPlaceholders waits for the same lock.
func (g *leakGuard) addOne(entry *censor.Entries, keyNamed bool) (protected bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err = g.index.Add(entry); err != nil {
		return false, err
	}
	name := entry.Type + ":" + entry.ID
	if !entry.Protected() {
		// A value is counted once however often it is registered, and the
		// names kept for that are bounded.
		if _, counted := g.unprotected[name]; !counted && len(g.unprotected) < maxUnprotectedNames {
			g.unprotected[name] = struct{}{}
		}
		return false, nil
	}
	delete(g.unprotected, name)
	// Once a placeholder is known to hold a key name it stays so, whatever a
	// later registration says of the same id.
	if keyNamed {
		g.keyNamed[entry.Placeholder()] = struct{}{}
	}
	return true, nil
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

// status is counts, names and reasons only: of hosts, and of pattern rules.
// Every listed host is read for a client of the proxy environment, whichever
// tool the proxy serves, so the hosts are the table's. A host the table reads
// is listed as not read, with why, while that is what happens to it: in a
// pass-through window, and while a connection to it that was handed to the
// service unread is open or was opened in the last unreadPeriod.
func (g *leakGuard) status() *remoteapi.LeakProtectionStatus {
	inspected := g.hosts.hostNames(leakTreatmentInspect)
	// A host one tool lists as not read is read when another tool's list
	// reads it.
	unread := slices.DeleteFunc(g.hosts.hostNames(leakTreatmentUnread), func(name string) bool { return slices.Contains(inspected, name) })
	status := &remoteapi.LeakProtectionStatus{
		Mode: g.mode, SecretsKnown: g.index.Stats().Secrets, Unprotected: g.unprotectedCount(),
		RulesSkipped: len(g.skipped), SkippedRules: g.skippedRuleIDs(),
	}
	if g.mode == leakModeOff {
		unread = append(inspected, unread...)
		inspected = nil
	} else {
		status.UnreadReasons = g.notReadNow()
		for host := range status.UnreadReasons {
			inspected = slices.DeleteFunc(inspected, func(name string) bool { return name == host })
			// A name under a domain entry is listed by itself: the rest of
			// the domain is still read.
			if !slices.Contains(unread, host) {
				unread = append(unread, host)
			}
		}
		status.MirroredHosts = g.mirroredStatus()
	}
	sort.Strings(unread)
	status.InspectedHosts, status.UnreadHosts = append([]string{}, inspected...), append([]string{}, unread...)
	return status
}

// readHostNames names the hosts the table reads, a domain also as *.name:
// none when leak protection is off.
func (g *leakGuard) readHostNames() []string {
	if g.mode == leakModeOff {
		return nil
	}
	return g.hosts.hostNames(leakTreatmentInspect)
}

// notReadNow names the hosts the table reads that are not being read at this
// moment, each with why: nil when there are none.
func (g *leakGuard) notReadNow() map[string][]string {
	reasons := g.connections.unreadNow()
	for _, host := range g.handshakes.bypassedHosts() {
		if slices.Contains(reasons[host], leakReasonTLSRefused) {
			continue
		}
		if reasons == nil {
			reasons = map[string][]string{}
		}
		reasons[host] = append(reasons[host], leakReasonTLSRefused)
		sort.Strings(reasons[host])
	}
	return reasons
}

// mirroredStatus counts, for each host whose hello is copied, how its
// connections went: the table's flagged hosts, and any name under a flagged
// domain that was connected to.
func (g *leakGuard) mirroredStatus() []remoteapi.MirroredHostStatus {
	names := g.hosts.mirroredHostNames()
	for _, host := range g.connections.hostNames() {
		if g.hosts.mirrors(host) && !slices.Contains(names, host) {
			names = append(names, host)
		}
	}
	sort.Strings(names)
	var hosts []remoteapi.MirroredHostStatus
	for _, host := range names {
		copied, rebuilt, passed := g.connections.counts(host)
		hosts = append(hosts, remoteapi.MirroredHostStatus{Host: host, Copied: copied, Rebuilt: rebuilt, PassedThrough: passed})
	}
	return hosts
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
//   - it is the client's that refused, told apart by its TLS hello (see
//     leak_hello.go): the key of a connection whose hello was read holds the
//     hello's fingerprint, and the tool's other clients are still read;
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
		t.makeRoom()
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

// makeRoom keeps what is remembered within maxRememberedHosts: a domain
// entry matches any number of subdomains. What goes first is what holds no
// open window. When every host remembered is in a window they all go, which
// only means those hosts are read again.
func (t *handshakeTracker) makeRoom() {
	if len(t.hosts) < maxRememberedHosts {
		return
	}
	now := t.clock()
	for key, state := range t.hosts {
		if !now.Before(state.until) {
			delete(t.hosts, key)
		}
	}
	if len(t.hosts) >= maxRememberedHosts {
		clear(t.hosts)
	}
}

func (t *handshakeTracker) bypassed(key leakStateKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.hosts[key]
	return state != nil && t.clock().Before(state.until)
}

// bypassedHosts names the hosts in a window for any tool or client.
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

// A connection handed to the service unread stays unread for as long as the
// client keeps it: a whole session can run over one. connectionLog counts
// such connections per host, so status can say a host is not being read
// while one is open, and for unreadPeriod after one was opened, which is as
// long as their event is not repeated. For a host whose hello is copied it
// also counts the connections that were opened with a copy.
type connectionLog struct {
	mu    sync.Mutex
	hosts map[string]*hostConnections
	now   func() time.Time
}

type hostConnections struct {
	// copied is the connections opened with a copy of the client's hello and
	// read; rebuilt is the times the hello sent was made from one that
	// offered a session, the client not having been seen without one.
	copied, rebuilt int
	// unread is the connections handed to the service unread, by reason.
	unread map[string]*unreadConnections
}

type unreadConnections struct {
	total, open int
	// opened is when the latest of them was opened.
	opened time.Time
}

func newConnectionLog() *connectionLog {
	return &connectionLog{hosts: map[string]*hostConnections{}}
}

func (l *connectionLog) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// host returns what is counted for a host, or nil when there is no room for
// another: a domain entry matches any number of subdomains. A host with no
// open connection makes room for a new one; one with an open connection is
// never dropped, since status has to go on naming it.
func (l *connectionLog) host(name string) *hostConnections {
	if counted := l.hosts[name]; counted != nil {
		return counted
	}
	if len(l.hosts) >= maxRememberedHosts {
		for other, counted := range l.hosts {
			if !counted.anyOpen() {
				delete(l.hosts, other)
			}
		}
		if len(l.hosts) >= maxRememberedHosts {
			return nil
		}
	}
	counted := &hostConnections{unread: map[string]*unreadConnections{}}
	l.hosts[name] = counted
	return counted
}

func (c *hostConnections) anyOpen() bool {
	for _, unread := range c.unread {
		if unread.open > 0 {
			return true
		}
	}
	return false
}

// noteCopied counts a connection opened with a copy of the client's hello.
func (l *connectionLog) noteCopied(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if counted := l.host(host); counted != nil {
		counted.copied++
	}
}

// noteRebuilt counts a hello sent that was rebuilt from one that offered a
// session.
func (l *connectionLog) noteRebuilt(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if counted := l.host(host); counted != nil {
		counted.rebuilt++
	}
}

// passed counts a connection handed to the service unread, and returns what
// its end is told to.
func (l *connectionLog) passed(host, reason string) (ended func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	counted := l.host(host)
	if counted == nil {
		return func() {}
	}
	unread := counted.unread[reason]
	if unread == nil {
		unread = &unreadConnections{}
		counted.unread[reason] = unread
	}
	unread.total++
	unread.open++
	unread.opened = l.clock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			unread.open--
		})
	}
}

// unreadNow names the hosts with a connection handed over unread that is
// open, or was opened in the last unreadPeriod, each with the reasons.
func (l *connectionLog) unreadNow() map[string][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	var hosts map[string][]string
	for host, counted := range l.hosts {
		for reason, unread := range counted.unread {
			if unread.open == 0 && now.Sub(unread.opened) >= unreadPeriod {
				continue
			}
			if hosts == nil {
				hosts = map[string][]string{}
			}
			hosts[host] = append(hosts[host], reason)
		}
		sort.Strings(hosts[host])
	}
	return hosts
}

func (l *connectionLog) hostNames() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := make([]string, 0, len(l.hosts))
	for host := range l.hosts {
		names = append(names, host)
	}
	return names
}

// counts returns what was counted for a host; passed is nil when no
// connection to it was handed over.
func (l *connectionLog) counts(host string) (copied, rebuilt int, passed map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	counted := l.hosts[host]
	if counted == nil {
		return 0, 0, nil
	}
	for reason, unread := range counted.unread {
		if passed == nil {
			passed = map[string]int{}
		}
		passed[reason] = unread.total
	}
	return counted.copied, counted.rebuilt, passed
}
