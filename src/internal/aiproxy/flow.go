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

// FlowContext says how a connection reached the proxy and whose it is.
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
}

// capture is the flow's capture with the zero value read as CaptureProxy.
func (f FlowContext) capture() string {
	if f.Capture == CaptureTunnel {
		return CaptureTunnel
	}
	return CaptureProxy
}

var flowToolPattern = regexp.MustCompile(`^[a-z0-9._-]{0,32}$`)

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
	return FlowContext{Capture: f.Capture, Tool: tool}, nil
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
	now   func() time.Time
}

func newFlowNotes() *flowNotes {
	return &flowNotes{notes: map[netip.AddrPort]flowNote{}}
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

// forget drops the note left for an address, if one still waits there.
func (n *flowNotes) forget(remoteAddr string) {
	address, ok := loopbackAddress(remoteAddr)
	if !ok {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.notes, address)
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
// forgotten after about ten seconds; ForgetFlow drops it at once.
//
// A CONNECT nobody noted is a client that was given the proxy through its
// environment. An error means the note was not kept, and the caller must not
// hand the flow over: its CONNECT would be taken for such a client.
func (e *Engine) NoteFlow(remoteAddr string, flow FlowContext) error {
	return e.flowNotes().note(remoteAddr, flow)
}

// ForgetFlow drops the note left for remoteAddr. A capture layer calls it
// when the connection it noted ends without sending its CONNECT: the note
// would otherwise wait out its ten seconds, and another program that
// connected from the same address and port in that time would be taken for
// the noted flow.
func (e *Engine) ForgetFlow(remoteAddr string) {
	e.flowNotes().forget(remoteAddr)
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
	guard, err := e.leakHosts()
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
	guard, err := e.leakHosts()
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
	return FlowContext{Capture: CaptureProxy, Tool: p.tool}
}

// connectFlow says how a CONNECT reached the proxy. It reads the note for
// the address the CONNECT came from and nothing of the request itself: no
// header, target or credential can set a flow.
func (p *httpProxy) connectFlow(req *http.Request) FlowContext {
	if p.flows != nil {
		if flow, noted := p.flows.take(req.RemoteAddr); noted {
			return flow
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
