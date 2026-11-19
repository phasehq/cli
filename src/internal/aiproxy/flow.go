package aiproxy

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// There is more than one way for traffic to reach the proxy. A client that
// was given the proxy through its environment sends its own CONNECT. A
// capture layer in this process, such as a tunnel's router, sends a CONNECT
// from loopback for a flow it took off the network, and knows which local
// program opened that flow. The two carry different traffic: the first only
// what runs in an AI tool's process tree, the second everything on the
// machine. So the way a connection came in travels with it as a FlowContext,
// and nothing below assumes either of them.

const (
	// CaptureProxy is a client that was given the proxy through its
	// environment.
	CaptureProxy = "proxy"
	// CaptureTunnel is a flow a tunnel handed to the proxy.
	CaptureTunnel = "tunnel"
)

// PeerLocal is the capture peer that is this machine: the proxy environment
// and this machine's own tunnel. A tunnel's other half may run elsewhere.
const PeerLocal = "local"

// FlowContext says how a connection reached the proxy and whose it is. Code in
// this process makes it: nothing of it is read from what a program sends.
type FlowContext struct {
	// Capture is CaptureProxy or CaptureTunnel. It decides how strictly a
	// host is tied to a tool: behind the environment proxy every program is
	// in an AI tool's process tree and any listed host is read; a tunnel
	// carries every program on the machine, and a host is read only for the
	// tool it is listed under.
	Capture string
	// Tool is the id of the AI tool that opened the connection, as the leak
	// protection table names it (claude, codex, opencode, cursor). It is empty
	// when the program is not known to be one of them.
	Tool string
	// Peer is the capture peer the flow came from, as the capture layer names
	// it; empty is PeerLocal. What is remembered of traffic is kept per peer.
	Peer string
}

// capture is the flow's capture with the zero value read as CaptureProxy.
func (f FlowContext) capture() string {
	if f.Capture == CaptureTunnel {
		return CaptureTunnel
	}
	return CaptureProxy
}

// peer is the flow's peer with the zero value read as PeerLocal.
func (f FlowContext) peer() string {
	if f.Peer == "" {
		return PeerLocal
	}
	return f.Peer
}

var (
	flowToolPattern = regexp.MustCompile(`^[a-z0-9._-]{0,32}$`)
	// A peer's id is written into events and compared exactly, so it is plain.
	flowPeerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// normalised returns the flow as the proxy keeps it, or an error for one it
// cannot use.
func (f FlowContext) normalised() (FlowContext, error) {
	tool := strings.ToLower(strings.TrimSpace(f.Tool))
	if f.Capture != CaptureProxy && f.Capture != CaptureTunnel {
		return FlowContext{}, errors.New("a flow is captured by the proxy environment or by a tunnel")
	}
	if !flowToolPattern.MatchString(tool) {
		return FlowContext{}, errors.New("a flow's tool is a short lower-case id")
	}
	if !flowPeerPattern.MatchString(f.peer()) {
		return FlowContext{}, errors.New("a flow's peer is a short plain id")
	}
	return FlowContext{Capture: f.Capture, Tool: tool, Peer: f.Peer}, nil
}

const (
	// flowNoteLifetime is how long a noted flow waits for its CONNECT. The
	// capture layer sends the CONNECT right after the note, so a note that is
	// still there after this belongs to a connection that never asked.
	flowNoteLifetime = 10 * time.Second
	// maxFlowNotes bounds the notes waiting for their CONNECT.
	maxFlowNotes = 4096
)

var errFlowNotesFull = errors.New("too many flows are waiting for their CONNECT")

type flowNote struct {
	flow    FlowContext
	expires time.Time
}

// flowNotes holds what capture layers said about connections that have not
// sent their CONNECT yet, by the loopback address each will come from. Only
// code in this process can write to it: nothing a request carries is ever
// read into it.
type flowNotes struct {
	mu    sync.Mutex
	notes map[netip.AddrPort]flowNote
	// tunnelled holds the addresses of the connections a tunnel has open to
	// the proxy, each with the mark of the call that put it there. They are as
	// many as those connections, and each goes when its connection does,
	// with the note that connection never used.
	tunnelled map[netip.AddrPort]tunnelConnection
	marks     uint64
	now       func() time.Time
}

// tunnelConnection is one connection a tunnel has open to the proxy.
type tunnelConnection struct {
	mark uint64
	// unread is what the tunnel asked to be told when the proxy hands the
	// connection's tunnel to its service unread, after answering its CONNECT.
	unread func()
}

func newFlowNotes() *flowNotes {
	return &flowNotes{notes: map[netip.AddrPort]flowNote{}, tunnelled: map[netip.AddrPort]tunnelConnection{}}
}

func (n *flowNotes) clock() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

// loopbackAddress reads the address a connection comes from. A flow is noted
// only for a loopback address: the proxy listens nowhere else.
func loopbackAddress(remoteAddr string) (netip.AddrPort, bool) {
	address, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.AddrPort{}, false
	}
	address = netip.AddrPortFrom(address.Addr().Unmap().WithZone(""), address.Port())
	return address, address.Addr().IsLoopback() && address.Port() != 0
}

func (n *flowNotes) note(remoteAddr string, flow FlowContext) error {
	flow, err := flow.normalised()
	if err != nil {
		return err
	}
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return errors.New("a flow is noted for the loopback address and port its CONNECT comes from")
	}
	now := n.clock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, known := n.notes[address]; !known && len(n.notes) >= maxFlowNotes {
		for waiting, note := range n.notes {
			if !now.Before(note.expires) {
				delete(n.notes, waiting)
			}
		}
		// A note still waiting is never dropped for a new one: its CONNECT
		// would arrive with no context and be taken for another kind of client.
		if len(n.notes) >= maxFlowNotes {
			return errFlowNotesFull
		}
	}
	n.notes[address] = flowNote{flow: flow, expires: now.Add(flowNoteLifetime)}
	return nil
}

// take returns the flow noted for the address a CONNECT came from, once.
func (n *flowNotes) take(remoteAddr string) (FlowContext, bool) {
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return FlowContext{}, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	note, noted := n.notes[address]
	if !noted {
		return FlowContext{}, false
	}
	delete(n.notes, address)
	if !n.clock().Before(note.expires) {
		return FlowContext{}, false
	}
	return note.flow, true
}

// tunnel records that the connection from remoteAddr is a tunnel's own until
// the function it returns is called, which also drops a note that connection
// never used. An address that is not loopback is one the proxy never accepts
// a connection from, and is not kept.
func (n *flowNotes) tunnel(remoteAddr string) (closed func()) {
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return func() {}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.tunnelled == nil {
		n.tunnelled = map[netip.AddrPort]tunnelConnection{}
	}
	n.marks++
	mark := n.marks
	n.tunnelled[address] = tunnelConnection{mark: mark}
	// The tunnel notes its flow after this. A note already waiting here was
	// left for an earlier connection from the same address, which is gone.
	delete(n.notes, address)
	return func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		// The address may have gone to a later connection by now, and neither
		// that one's place here nor its note is this call's to forget.
		if n.tunnelled[address].mark == mark {
			delete(n.tunnelled, address)
			delete(n.notes, address)
		}
	}
}

// watch keeps what a tunnel asked to be told when the tunnel of its connection
// from remoteAddr is handed on unread. It is kept with the connection, and
// goes with it.
func (n *flowNotes) watch(remoteAddr string, unread func()) {
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if connection, tunnelled := n.tunnelled[address]; tunnelled {
		connection.unread = unread
		n.tunnelled[address] = connection
	}
}

// handedOver tells the tunnel whose connection comes from remoteAddr, if it
// asked, that the proxy is handing that connection's tunnel to its service
// unread. It says so once. Any other connection has nobody to tell.
func (n *flowNotes) handedOver(remoteAddr string) {
	if n == nil {
		return
	}
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return
	}
	n.mu.Lock()
	connection, tunnelled := n.tunnelled[address]
	if tunnelled && connection.unread != nil {
		n.tunnelled[address] = tunnelConnection{mark: connection.mark}
	}
	n.mu.Unlock()
	if tunnelled && connection.unread != nil {
		connection.unread()
	}
}

// tunnels reports whether the connection from remoteAddr is one a tunnel has
// open to the proxy.
func (n *flowNotes) tunnels(remoteAddr string) bool {
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, tunnelled := n.tunnelled[address]
	return tunnelled
}

// flowNotes returns the process-wide notes, made on first use so a zero
// Engine behaves like New().
func (e *Engine) flowNotes() *flowNotes {
	engineRuntimeInitMu.Lock()
	defer engineRuntimeInitMu.Unlock()
	if e.runtime == nil {
		e.runtime = &engineRuntime{}
	}
	if e.runtime.flows == nil {
		e.runtime.flows = newFlowNotes()
	}
	return e.runtime.flows
}

// NoteFlow tells the proxy whose connection is about to send a CONNECT from
// remoteAddr, the loopback address and port of the caller's own connection
// to the proxy (its LocalAddr). It is for a capture layer in this process: a
// tunnel's router calls it for each flow it hands over, before it writes the
// CONNECT. The note is used up by the first CONNECT from that address,
// whether the proxy serves that CONNECT or refuses it, so a second CONNECT on
// the same connection needs a note of its own. A note nobody uses is
// forgotten after about ten seconds, and at once when a tunnel is done with
// the connection it was left for (TunnelConnection).
//
// A CONNECT nobody noted is a client that was given the proxy through its
// environment. An error means the note was not kept, and the caller must not
// hand the flow over: its CONNECT would be taken for such a client. Only on a
// connection a tunnel said is its own can the flow still go, for a
// Connection's credential, since nothing of it is read.
func (e *Engine) NoteFlow(remoteAddr string, flow FlowContext) error {
	return e.flowNotes().note(remoteAddr, flow)
}

// TunnelConnection tells the proxy that the connection a capture layer has
// just opened to it, from remoteAddr (that connection's LocalAddr), is a
// tunnel's, and returns what the capture layer calls when it is done with
// that connection, whatever became of it. In between, what the proxy knows of
// the address is that connection's alone:
//
//   - a CONNECT from it that finds no note is a tunnel's flow from no known
//     tool: the credential of a Connection is still attached, and nothing is
//     read. Without this such a CONNECT is taken for a client of the proxy
//     environment, for which every listed host is read. That happens to a
//     flow whose note was refused and which is handed over all the same,
//     because it needs a Connection's credential, and to one whose CONNECT
//     is read only after its note was forgotten;
//   - a note its CONNECT never used goes with it. Left to wait out its ten
//     seconds, the note would name the next program to connect from the same
//     address and port, which the system hands out again.
//
// A tunnel calls it for every connection it opens to the proxy, before
// NoteFlow, and calls what it returns before it closes the connection: while
// the tunnel still holds the port, nothing else can connect from that address.
func (e *Engine) TunnelConnection(remoteAddr string) (closed func()) {
	return e.flowNotes().tunnel(remoteAddr)
}

// OnTunnelUnread asks the proxy to call unread if it hands the tunnel of the
// connection from remoteAddr to its service without reading it, after it has
// answered that connection's CONNECT as a tunnel it serves itself. It does so
// when the client, known by its TLS hello, is one that keeps refusing the
// proxy's certificate at that host, and when a hello that has to be copied
// cannot be. The CONNECT's answer was given before either could be known, so
// this is how a capture layer that counts what was read learns of it.
//
// A tunnel calls it after TunnelConnection, for the same address, and before
// it sends its CONNECT. unread is called at most once, from the goroutine
// that serves the connection, and is forgotten with the connection.
func (e *Engine) OnTunnelUnread(remoteAddr string, unread func()) {
	e.flowNotes().watch(remoteAddr, unread)
}

// ReadHost is one host leak protection reads for a tool, on port 443.
type ReadHost struct {
	Host string
	// Subdomains says every name under Host is read as well.
	Subdomains bool
}

// ShouldRead reports whether leak protection reads host, on port 443, for
// the processes of tool. A capture layer hands such a flow to the proxy and
// leaves every other flow to the same host alone: a host is read only for the
// tool it is listed under, and never for a program that is not known to be a
// listed tool. It is false for every host when leak protection is off.
func (e *Engine) ShouldRead(tool, host string) bool {
	guard, err := e.leakGuard()
	if err != nil {
		return false
	}
	flow, err := FlowContext{Capture: CaptureTunnel, Tool: tool}.normalised()
	if err != nil || flow.Tool == "" {
		return false
	}
	return guard.inspects(flow, host, 443) != nil
}

// ReadHosts lists the hosts leak protection reads for the processes of tool:
// what a capture layer has to route to the proxy for that tool. It is empty
// for a tool that is not listed and when leak protection is off.
func (e *Engine) ReadHosts(tool string) []ReadHost {
	guard, err := e.leakGuard()
	if err != nil || guard.mode == leakModeOff {
		return nil
	}
	flow, err := FlowContext{Capture: CaptureTunnel, Tool: tool}.normalised()
	if err != nil || flow.Tool == "" {
		return nil
	}
	var hosts []ReadHost
	for _, rule := range guard.hosts.rulesOf(flow.Tool) {
		if rule.Treatment == leakTreatmentInspect {
			hosts = append(hosts, ReadHost{Host: rule.Host, Subdomains: rule.Subdomains})
		}
	}
	return hosts
}

// ownFlow is a connection nobody noted: a client that was given the proxy
// through its environment. It is named after the one tool this proxy serves,
// when the proxy knows it; what is read does not depend on that.
func (p *httpProxy) ownFlow() FlowContext {
	return FlowContext{Capture: CaptureProxy, Tool: p.tool, Peer: PeerLocal}
}

// connectFlow says how a CONNECT reached the proxy. It reads the note for
// the address the CONNECT came from and nothing of the request itself: no
// header, target or credential can set a flow. A tunnel's own connection with
// no note left for it is still a tunnel's, and never the proxy's own client's:
// nothing says whose flow it carries, so it is read for no tool.
func (p *httpProxy) connectFlow(req *http.Request) FlowContext {
	if p.flows != nil {
		if flow, noted := p.flows.take(req.RemoteAddr); noted {
			return flow
		}
		if p.flows.tunnels(req.RemoteAddr) {
			// It names no peer either: nothing of it is read, so nothing is kept.
			return FlowContext{Capture: CaptureTunnel}
		}
	}
	return p.ownFlow()
}

// dropFlow uses up the note of a CONNECT that is turned away before the
// proxy handles it.
func (p *httpProxy) dropFlow(req *http.Request) {
	if req != nil && req.Method == http.MethodConnect {
		p.connectFlow(req)
	}
}
