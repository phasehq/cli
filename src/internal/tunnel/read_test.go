package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/tunnel/owner"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	modelHost      = "model.example.test"
	otherModelHost = "chat.example.test"
	plainHost      = "www.example.test"
)

var (
	claudeCode = owner.Process{PID: 4001, Executable: "/Users/someone/.local/share/claude/versions/2.1.316", Args: []string{"claude"}, UID: os.Getuid()}
	codexCLI   = owner.Process{PID: 4002, Executable: "/opt/homebrew/bin/codex", Args: []string{"codex"}, UID: os.Getuid()}
	browser    = owner.Process{PID: 4003, Executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", UID: os.Getuid()}
)

type flowNote struct{ from, tool string }

// fakeReader reads each tool's hosts for that tool only, as the proxy does.
type fakeReader struct {
	mu    sync.Mutex
	hosts map[string][]string
	asked []string
	notes []flowNote
	// before runs at the start of NoteFlow, to check what has happened by then.
	before func(connectFrom string)
	// refuse makes NoteFlow fail, as the proxy does when it can't keep a note.
	refuse error
	// refused are the addresses a note was refused for, and closed the ones the
	// router said it had closed its connection from.
	refused, closed []string
	// peers are the peers the noted flows came from, one for each note.
	peers []string
	// unreads is what the router asked to be told, by the address it asked for.
	unreads map[string]func()
}

func (f *fakeReader) covers(listed, host string) bool {
	if suffix, wild := strings.CutPrefix(listed, "*."); wild {
		return strings.HasSuffix(host, "."+suffix)
	}
	return listed == host
}

func (f *fakeReader) ReadsHost(host string) bool {
	f.mu.Lock()
	f.asked = append(f.asked, host)
	f.mu.Unlock()
	for tool := range f.hosts {
		if f.ShouldRead(tool, host) {
			return true
		}
	}
	return false
}

func (f *fakeReader) ShouldRead(tool, host string) bool {
	for _, listed := range f.hosts[tool] {
		if f.covers(listed, host) {
			return true
		}
	}
	return false
}

func (f *fakeReader) NoteFlow(connectFrom, peer, tool string, unread func()) (func(), error) {
	if f.before != nil {
		f.before(connectFrom)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unreads == nil {
		f.unreads = map[string]func(){}
	}
	f.unreads[connectFrom] = unread
	closed := func() {
		f.mu.Lock()
		f.closed = append(f.closed, connectFrom)
		delete(f.unreads, connectFrom)
		f.mu.Unlock()
	}
	if f.refuse != nil {
		f.refused = append(f.refused, connectFrom)
		return closed, f.refuse
	}
	f.notes = append(f.notes, flowNote{connectFrom, tool})
	f.peers = append(f.peers, peer)
	return closed, nil
}

// handOn says, as the proxy does, that the flow from an address is handed to its
// service unread.
func (f *fakeReader) handOn(from string) {
	f.mu.Lock()
	unread := f.unreads[from]
	f.mu.Unlock()
	if unread != nil {
		unread()
	}
}

// closedOnce reports whether the router said, exactly once, that it had closed its
// connection from each address it told the reader about, and how many those were.
func (f *fakeReader) closedOnce() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	told := map[string]int{}
	for _, note := range f.notes {
		told[note.from]++
	}
	for _, from := range f.refused {
		told[from]++
	}
	for _, from := range f.closed {
		told[from]--
	}
	for _, left := range told {
		if left != 0 {
			return len(told), false
		}
	}
	return len(told), true
}

func (f *fakeReader) ToolHosts() map[string][]string { return f.hosts }

// noted returns the tool noted for a CONNECT from an address, and whether any was.
func (f *fakeReader) noted(from string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, note := range f.notes {
		if note.from == from {
			return note.tool, true
		}
	}
	return "", false
}

func (f *fakeReader) noteCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.notes)
}

// fakeOwners answers owner lookups, and remembers what was asked.
type fakeOwners struct {
	mu      sync.Mutex
	process owner.Process
	err     error
	hang    chan struct{}
	asked   []Flow
}

func (f *fakeOwners) find(_ context.Context, localPort int, remote netip.AddrPort) (owner.Process, error) {
	f.mu.Lock()
	f.asked = append(f.asked, Flow{Source: netip.AddrPortFrom(netip.Addr{}, uint16(localPort)), Dest: remote})
	process, err, hang := f.process, f.err, f.hang
	f.mu.Unlock()
	if hang != nil {
		// A lookup that pays no attention to its deadline.
		<-hang
	}
	return process, err
}

func (f *fakeOwners) lookups() []Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Flow(nil), f.asked...)
}

// readRecord reads one whole TLS record, or nothing if the connection ends first.
func readRecord(conn net.Conn) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil
	}
	return append(header, body...)
}

// arrival is one flow as an end of it saw it.
type arrival struct {
	authority string // the CONNECT's target, at the proxy
	from      string
	tool      string // what had been noted for from when the CONNECT arrived
	noted     bool
	hello     []byte
}

// fakeEnds stands in for the credential proxy and for a real destination.
type fakeEnds struct {
	proxyAddress, destination string
	atProxy, atDestination    chan arrival
	// connects are the addresses a CONNECT has arrived from.
	connects sync.Map
	// refuse makes the proxy turn every CONNECT away, as it does while it can't
	// vouch for its session.
	refuse atomic.Bool
	// relay makes the proxy take every CONNECT and only relay its tunnel, as it does
	// for a host its table doesn't read.
	relay atomic.Bool
	// handsOn makes the proxy answer that it serves the tunnel and then hand it on
	// unread: "late" once it has read the program's hello, as it does for a
	// program that keeps refusing its certificate, and "early" before its answer
	// has been written.
	handsOn atomic.Value
}

func startFakeEnds(t *testing.T, notes *fakeReader) *fakeEnds {
	t.Helper()
	ends := &fakeEnds{atProxy: make(chan arrival, 16), atDestination: make(chan arrival, 16)}
	listen := func(serve func(net.Conn)) string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					serve(conn)
				}()
			}
		}()
		return listener.Addr().String()
	}
	ends.proxyAddress = listen(func(conn net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil || request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") == "" {
			return
		}
		from := conn.RemoteAddr().String()
		ends.connects.Store(from, true)
		seen := arrival{authority: request.Host, from: from}
		seen.tool, seen.noted = notes.noted(from)
		if ends.refuse.Load() {
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			ends.atProxy <- seen
			return
		}
		// The proxy says so when it serves a tunnel itself, and says nothing of one
		// it only relays.
		serves := phaseproxy.TunnelHeader + ": " + phaseproxy.TunnelTerminated + "\r\n"
		if ends.relay.Load() {
			serves = ""
		}
		handsOn, _ := ends.handsOn.Load().(string)
		if handsOn == "early" {
			notes.handOn(from)
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n"+serves+"\r\n")
		seen.hello = readRecord(conn)
		if handsOn == "late" {
			notes.handOn(from)
		}
		ends.atProxy <- seen
	})
	ends.destination = listen(func(conn net.Conn) {
		ends.atDestination <- arrival{from: conn.RemoteAddr().String(), hello: readRecord(conn)}
	})
	return ends
}

func (e *fakeEnds) connected(from string) bool {
	_, connected := e.connects.Load(from)
	return connected
}

type readSetup struct {
	t      *testing.T
	router *Router
	reader *fakeReader
	owners *fakeOwners
	ends   *fakeEnds
}

// newReadSetup is a router that reads modelHost for Claude Code and otherModelHost
// for Codex, with stand-ins for the proxy, the destinations and the owner lookup.
func newReadSetup(t *testing.T, rules ...Rule) *readSetup {
	t.Helper()
	reader := &fakeReader{hosts: map[string][]string{"claude": {modelHost}, "codex": {otherModelHost}}}
	ends := startFakeEnds(t, reader)
	router := NewRouter(&Upstream{Servers: []string{}, Override: map[string]string{
		modelHost + ":443": ends.destination, modelHost + ":80": ends.destination,
	}}, nil)
	if err := router.Update("http://phase:secret@"+ends.proxyAddress, "", rules); err != nil {
		t.Fatal(err)
	}
	owners := &fakeOwners{process: browser}
	router.Read(reader, false)
	router.FindOwnersWith(owners.find, 2*time.Second)
	return &readSetup{t: t, router: router, reader: reader, owners: owners, ends: ends}
}

var nextSourcePort atomic.Uint32

// open sends a TLS hello for host through the router, as a program reaching a real
// address would, and returns the flow it made.
func (s *readSetup) open(host string) Flow {
	s.t.Helper()
	upstream, err := net.Dial("tcp", s.ends.destination)
	if err != nil {
		s.t.Fatal(err)
	}
	flow := Flow{
		Source:   netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))),
		Dest:     netip.MustParseAddrPort("203.0.113.7:443"),
		Prepared: upstream,
	}
	s.run(host, flow)
	return flow
}

// openHeld is open, and returns the program's end of the flow for the test to close.
func (s *readSetup) openHeld(host string) net.Conn {
	s.t.Helper()
	upstream, err := net.Dial("tcp", s.ends.destination)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.run(host, Flow{
		Source:   netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))),
		Dest:     netip.MustParseAddrPort("203.0.113.7:443"),
		Prepared: upstream,
	})
}

// run plays a program opening flow and sending a TLS hello for host. It returns the
// program's end, which is closed when the test ends if not before.
func (s *readSetup) run(host string, flow Flow) net.Conn {
	s.t.Helper()
	return s.runAfter(0, host, flow)
}

// runAfter is run for a program that waits before it sends its hello.
func (s *readSetup) runAfter(wait time.Duration, host string, flow Flow) net.Conn {
	s.t.Helper()
	program, routerEnd := net.Pipe()
	finished := make(chan struct{})
	go func() {
		time.Sleep(wait)
		_ = tls.Client(program, &tls.Config{ServerName: host, InsecureSkipVerify: true}).Handshake()
	}()
	go func() {
		defer close(finished)
		defer routerEnd.Close()
		s.router.HandleTCP(routerEnd, flow)
	}()
	s.t.Cleanup(func() {
		program.Close()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			s.t.Error("the router never let go of the flow")
		}
	})
	return program
}

func (s *readSetup) arrives(where chan arrival) arrival {
	s.t.Helper()
	select {
	case seen := <-where:
		return seen
	case <-time.After(10 * time.Second):
		s.t.Fatal("the flow never arrived")
		return arrival{}
	}
}

// wholeHello checks the bytes read to find the name were all sent on.
func wholeHello(t *testing.T, hello []byte, host string) {
	t.Helper()
	if len(hello) < 6 || hello[0] != 0x16 || hello[5] != 0x01 {
		t.Fatalf("not a TLS hello: %d bytes", len(hello))
	}
	if !bytes.Contains(hello, []byte(host)) {
		t.Fatalf("the hello doesn't name %s", host)
	}
}

func (s *readSetup) counts(want map[string]int) {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := s.router.Counts()
		if reflect.DeepEqual(got, want) {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("counts %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAHostNobodyReadsCostsNoLookup(t *testing.T) {
	setup := newReadSetup(t)
	setup.open(plainHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, plainHost)
	if asked := setup.owners.lookups(); len(asked) != 0 {
		t.Fatalf("the flow's program was looked up: %v", asked)
	}
	if setup.reader.noteCount() != 0 {
		t.Fatal("the proxy was told about a flow it never gets")
	}
	setup.counts(map[string]int{"tcp": 1})
}

func TestNothingIsReadUntilAReaderIsSet(t *testing.T) {
	setup := newReadSetup(t)
	setup.router.Read(nil, false)
	setup.owners.process = claudeCode
	setup.open(modelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
	if asked := setup.owners.lookups(); len(asked) != 0 {
		t.Fatalf("the flow's program was looked up: %v", asked)
	}
	setup.counts(map[string]int{"tcp": 1})
}

func TestAToolsModelTrafficGoesToTheProxy(t *testing.T) {
	setup := newReadSetup(t)
	setup.owners.process = claudeCode
	// By the time the proxy is told who opened the flow, no CONNECT has left for it.
	setup.reader.before = func(connectFrom string) {
		time.Sleep(50 * time.Millisecond)
		if setup.ends.connected(connectFrom) {
			t.Error("the CONNECT was sent before the proxy was told who opened the flow")
		}
	}
	flow := setup.open(modelHost)
	seen := setup.arrives(setup.ends.atProxy)
	if seen.authority != modelHost+":443" {
		t.Fatalf("CONNECT %s", seen.authority)
	}
	if !seen.noted || seen.tool != "claude" {
		t.Fatalf("when the CONNECT arrived from %s, the proxy had been told %q (told at all: %v)", seen.from, seen.tool, seen.noted)
	}
	if address, err := netip.ParseAddrPort(seen.from); err != nil || !address.Addr().IsLoopback() {
		t.Fatalf("the CONNECT came from %s", seen.from)
	}
	wholeHello(t, seen.hello, modelHost)
	if direct := setup.arrives(setup.ends.atDestination); direct.hello != nil {
		t.Fatal("the hello also went straight to the destination")
	}
	asked := setup.owners.lookups()
	if len(asked) != 1 || asked[0].Source.Port() != flow.Source.Port() || asked[0].Dest != flow.Dest {
		t.Fatalf("looked up %v for the flow %v to %v", asked, flow.Source, flow.Dest)
	}
	setup.counts(map[string]int{"read": 1})
}

// realFlow is a flow to a real address, with the connection that was opened to its
// destination before the program's own completed.
func (s *readSetup) realFlow() Flow {
	s.t.Helper()
	upstream, err := net.Dial("tcp", s.ends.destination)
	if err != nil {
		s.t.Fatal(err)
	}
	return Flow{
		Source:   netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))),
		Dest:     netip.MustParseAddrPort("203.0.113.7:443"),
		Prepared: upstream,
	}
}

// A tool whose hello comes a moment after its connection is still read. Taken for a
// flow with no name, it would be relayed unread for as long as the tool kept it, and
// a kept connection carries every request after the first.
func TestAToolsFlowIsReadWhenItsHelloComesLate(t *testing.T) {
	setup := newReadSetup(t)
	setup.owners.process = claudeCode
	setup.runAfter(400*time.Millisecond, modelHost, setup.realFlow())
	seen := setup.arrives(setup.ends.atProxy)
	if seen.authority != modelHost+":443" || !seen.noted || seen.tool != "claude" {
		t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
	}
	wholeHello(t, seen.hello, modelHost)
	if direct := setup.arrives(setup.ends.atDestination); direct.hello != nil {
		t.Fatal("the hello also went straight to the destination")
	}
	setup.counts(map[string]int{"read": 1})
}

// The wait for a hello does end. A flow let go then is unread whatever it goes on to
// carry, so it is counted as that, apart from the flows whose host nobody reads.
func TestAFlowWhoseHelloNeverComesInTimeIsCountedApart(t *testing.T) {
	setup := newReadSetup(t)
	setup.owners.process = claudeCode
	setup.router.helloWait = 150 * time.Millisecond
	setup.runAfter(600*time.Millisecond, modelHost, setup.realFlow())
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
	if asked := setup.owners.lookups(); len(asked) != 0 || setup.reader.noteCount() != 0 {
		t.Fatalf("a flow nothing is known of was looked up (%v) or told of", asked)
	}
	setup.counts(map[string]int{"tcp": 1, "unread_no_hello": 1})
}

func TestAnotherProgramsTrafficToTheSameHostIsLeftUnread(t *testing.T) {
	for name, process := range map[string]owner.Process{
		"a browser":             browser,
		"another tool":          codexCLI,
		"the chat app":          {Executable: "/Applications/Claude.app/Contents/MacOS/Claude", UID: os.Getuid()},
		"a script":              {Executable: "/usr/bin/python3", Args: []string{"python3", "ask.py"}, UID: os.Getuid()},
		"nothing known of it":   {UID: os.Getuid()},
		"the phase CLI's proxy": {Executable: "/opt/homebrew/bin/phase", Args: []string{"phase", "ai", "runtime"}, UID: os.Getuid()},
	} {
		t.Run(name, func(t *testing.T) {
			setup := newReadSetup(t)
			setup.owners.process = process
			setup.open(modelHost)
			wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
			if setup.reader.noteCount() != 0 {
				t.Fatal("the proxy was told about a flow it never gets")
			}
			select {
			case seen := <-setup.ends.atProxy:
				t.Fatalf("the flow went to the proxy: CONNECT %s", seen.authority)
			default:
			}
			setup.counts(map[string]int{"tcp": 1, "unread_not_tool": 1})
		})
	}
}

func TestEachToolIsReadForItsOwnHostsOnly(t *testing.T) {
	setup := newReadSetup(t)
	setup.owners.process = codexCLI
	setup.open(otherModelHost)
	if seen := setup.arrives(setup.ends.atProxy); seen.authority != otherModelHost+":443" || seen.tool != "codex" {
		t.Fatalf("CONNECT %s, noted %q", seen.authority, seen.tool)
	}
	setup.arrives(setup.ends.atDestination)
	setup.owners.mu.Lock()
	setup.owners.process = claudeCode
	setup.owners.mu.Unlock()
	setup.open(otherModelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, otherModelHost)
	setup.counts(map[string]int{"read": 1, "tcp": 1, "unread_not_tool": 1})
}

func TestAFailedLookupLeavesTheFlowUnread(t *testing.T) {
	for name, err := range map[string]error{
		"nobody found":       owner.ErrNotFound,
		"not supported here": owner.ErrUnsupported,
		"held by two":        owner.ErrShared,
		"the lookup broke":   errors.New("lsof: exit status 2"),
		"it ran out of time": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			setup := newReadSetup(t)
			// Even with a tool's name on the answer, an error means nobody is known.
			setup.owners.process, setup.owners.err = claudeCode, err
			setup.open(modelHost)
			wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
			if setup.reader.noteCount() != 0 {
				t.Fatal("the proxy was told about a flow it never gets")
			}
			setup.counts(map[string]int{"tcp": 1, "owner_lookup_failed": 1})
		})
	}
}

func TestASlowLookupNeverHoldsAFlowPastItsDeadline(t *testing.T) {
	setup := newReadSetup(t)
	setup.owners.process, setup.owners.hang = claudeCode, make(chan struct{})
	t.Cleanup(func() { close(setup.owners.hang) })
	const wait = 150 * time.Millisecond
	setup.router.FindOwnersWith(setup.owners.find, wait)
	start := time.Now()
	setup.open(modelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
	if elapsed := time.Since(start); elapsed < wait || elapsed > wait+time.Second {
		t.Fatalf("the flow was held for %s by a lookup that may take %s", elapsed, wait)
	}
	setup.counts(map[string]int{"tcp": 1, "owner_lookup_failed": 1})
}

// A program opening many connections at once doesn't get a lookup started for each.
func TestLookupsRunAFewAtATime(t *testing.T) {
	router := NewRouter(&Upstream{}, nil)
	var running, most, started atomic.Int32
	release := make(chan struct{})
	router.FindOwnersWith(func(context.Context, int, netip.AddrPort) (owner.Process, error) {
		started.Add(1)
		now := running.Add(1)
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				break
			}
		}
		<-release
		running.Add(-1)
		return claudeCode, nil
	}, 200*time.Millisecond)
	const flows = 4 * ownerLookups
	var failed atomic.Int32
	var done sync.WaitGroup
	start := time.Now()
	for i := range flows {
		done.Add(1)
		go func() {
			defer done.Done()
			flow := Flow{Source: netip.AddrPortFrom(LocalAddress, uint16(51000+i)), Dest: netip.MustParseAddrPort("203.0.113.7:443")}
			if _, err := router.ownerOf(flow); err != nil {
				failed.Add(1)
			}
		}()
	}
	done.Wait()
	elapsed := time.Since(start)
	close(release)
	if most.Load() != ownerLookups || started.Load() != ownerLookups {
		t.Fatalf("%d lookups ran at once and %d were started, with room for %d", most.Load(), started.Load(), ownerLookups)
	}
	if failed.Load() != flows {
		t.Fatalf("%d of %d flows were left without an answer", failed.Load(), flows)
	}
	if elapsed > time.Second {
		t.Fatalf("flows waited %s for lookups that may take 200ms", elapsed)
	}
	// Once the stuck lookups return, there's room again.
	deadline := time.Now().Add(5 * time.Second)
	for len(router.lookups) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the stuck lookups never gave their places back")
		}
		time.Sleep(5 * time.Millisecond)
	}
	router.FindOwnersWith(func(context.Context, int, netip.AddrPort) (owner.Process, error) { return browser, nil }, time.Second)
	if process, err := router.ownerOf(Flow{Source: netip.AddrPortFrom(LocalAddress, 52000)}); err != nil || process.PID != browser.PID {
		t.Fatalf("after the burst: %+v, %v", process, err)
	}
}

// Reading is something Phase adds to a flow that would work without it. When the proxy
// can't take the flow, the tool still reaches its model.
func TestAToolsFlowGoesOnUnreadWhenTheProxyCannotTakeIt(t *testing.T) {
	t.Run("the proxy turns it away", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.owners.process = claudeCode
		setup.ends.refuse.Store(true)
		setup.open(modelHost)
		if seen := setup.arrives(setup.ends.atProxy); seen.authority != modelHost+":443" || seen.tool != "claude" {
			t.Fatalf("CONNECT %s, noted %q", seen.authority, seen.tool)
		}
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		setup.counts(map[string]int{"tcp": 1, "unread_no_proxy": 1})
	})
	t.Run("the proxy isn't there", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.owners.process = claudeCode
		gone, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if err := setup.router.Update("http://phase:secret@"+gone.Addr().String(), "", nil); err != nil {
			t.Fatal(err)
		}
		gone.Close()
		setup.open(modelHost)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		if setup.reader.noteCount() != 0 {
			t.Fatal("the proxy was told about a flow that never left for it")
		}
		setup.counts(map[string]int{"tcp": 1, "unread_no_proxy": 1})
	})
	t.Run("captured by name", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process = claudeCode
		setup.ends.refuse.Store(true)
		setup.openByName(modelHost, 443)
		setup.arrives(setup.ends.atProxy)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		setup.counts(map[string]int{"tcp": 1, "unread_no_proxy": 1})
	})
	// A Connection's flow can't go on: only the proxy holds its credential.
	t.Run("a Connection's host fails instead", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.owners.process = claudeCode
		setup.ends.refuse.Store(true)
		setup.open(modelHost)
		setup.arrives(setup.ends.atProxy)
		if direct := setup.arrives(setup.ends.atDestination); direct.hello != nil {
			t.Fatal("a Connection's flow went to its destination without the proxy")
		}
		setup.counts(map[string]int{"proxy_by_tls_name": 1})
	})
	t.Run("a Connection's host captured by name fails instead", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.router.Read(setup.reader, true)
		setup.owners.process = claudeCode
		setup.ends.refuse.Store(true)
		setup.openByName(modelHost, 443)
		setup.arrives(setup.ends.atProxy)
		select {
		case direct := <-setup.ends.atDestination:
			t.Fatalf("a Connection's flow went to its destination without the proxy: %d bytes", len(direct.hello))
		case <-time.After(300 * time.Millisecond):
		}
		setup.counts(map[string]int{"proxy": 1})
	})
}

// For a while after a tool has refused its certificate at a host, the proxy takes that
// tool's flows there and only relays them. Such a flow went through the proxy and was
// read by nobody, so it is counted by what the proxy did with it.
func TestAFlowTheProxyOnlyRelaysIsNotCountedAsRead(t *testing.T) {
	t.Run("caught by the name in its hello", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.owners.process = claudeCode
		setup.ends.relay.Store(true)
		setup.open(modelHost)
		seen := setup.arrives(setup.ends.atProxy)
		if seen.authority != modelHost+":443" || !seen.noted || seen.tool != "claude" {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		wholeHello(t, seen.hello, modelHost)
		setup.counts(map[string]int{"unread_by_proxy": 1})
	})
	t.Run("captured by name", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process = claudeCode
		setup.ends.relay.Store(true)
		setup.openByName(modelHost, 443)
		wholeHello(t, setup.arrives(setup.ends.atProxy).hello, modelHost)
		setup.counts(map[string]int{"unread_by_proxy": 1})
	})
	// A flow that was never handed over to be read says nothing of the proxy.
	t.Run("another program's flow to a Connection's host", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.ends.relay.Store(true)
		setup.open(modelHost)
		setup.arrives(setup.ends.atProxy)
		setup.counts(map[string]int{"proxy_by_tls_name": 1, "unread_not_tool": 1})
	})
}

// The proxy answers a CONNECT before it has seen the program's TLS hello, and it is
// by the hello that it knows a program that keeps refusing its certificate. So it
// can answer that it serves a tunnel, and then hand the flow to its service unread.
// It says so when it does, and the flow is counted by that, not by the answer.
func TestAFlowTheProxyHandsOnAfterItsAnswerIsNotCountedAsRead(t *testing.T) {
	for name, open := range map[string]func(*readSetup){
		"caught by the name in its hello": func(s *readSetup) { s.open(modelHost) },
		"captured by name": func(s *readSetup) {
			s.router.Read(s.reader, true)
			s.openByName(modelHost, 443)
		},
	} {
		t.Run(name, func(t *testing.T) {
			setup := newReadSetup(t)
			setup.owners.process = claudeCode
			setup.ends.handsOn.Store("late")
			open(setup)
			wholeHello(t, setup.arrives(setup.ends.atProxy).hello, modelHost)
			setup.counts(map[string]int{"unread_by_proxy": 1})
			// The next flow, which the proxy does read, is counted as read.
			setup.ends.handsOn.Store("")
			open(setup)
			setup.arrives(setup.ends.atProxy)
			setup.counts(map[string]int{"unread_by_proxy": 1, "read": 1})
		})
	}
	// The proxy's word can come before its answer has been read here.
	t.Run("told before the answer is read", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.owners.process = claudeCode
		setup.ends.handsOn.Store("early")
		setup.open(modelHost)
		setup.arrives(setup.ends.atProxy)
		setup.counts(map[string]int{"unread_by_proxy": 1})
	})
	// A flow that wasn't handed over to be read isn't counted either way.
	t.Run("a Connection's flow", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.ends.handsOn.Store("late")
		setup.open(modelHost)
		setup.arrives(setup.ends.atProxy)
		setup.counts(map[string]int{"proxy_by_tls_name": 1, "unread_not_tool": 1})
	})
}

func modelConnection() Rule {
	return Rule{ConnectionID: "model", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: modelHost, Port: 443}}
}

// A Connection's host goes to the proxy for its credential whichever of this user's
// programs opened the flow. When it's a model host too, the proxy is told whether the
// flow is its tool's. A flow whose program wasn't found goes on unread: nobody can
// say it is this user's.
func TestAConnectionHostThatIsAlsoAModelHostGoesToTheProxyForThisUser(t *testing.T) {
	for _, test := range []struct {
		name    string
		process owner.Process
		err     error
		tool    string
		counted string
	}{
		{"its tool", claudeCode, nil, "claude", "read"},
		{"a browser", browser, nil, "", "unread_not_tool"},
		{"another tool", codexCLI, nil, "", "unread_not_tool"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setup := newReadSetup(t, modelConnection())
			setup.owners.process, setup.owners.err = test.process, test.err
			setup.open(modelHost)
			seen := setup.arrives(setup.ends.atProxy)
			if seen.authority != modelHost+":443" || !seen.noted || seen.tool != test.tool {
				t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
			}
			wholeHello(t, seen.hello, modelHost)
			setup.counts(map[string]int{"proxy_by_tls_name": 1, test.counted: 1})
		})
	}
	for _, test := range []struct {
		name    string
		process owner.Process
		err     error
		counted string
	}{
		{"nobody found", claudeCode, owner.ErrNotFound, "owner_lookup_failed"},
		{"another user's tool", otherUsers(claudeCode), nil, "unread_other_user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setup := newReadSetup(t, modelConnection())
			setup.owners.process, setup.owners.err = test.process, test.err
			setup.open(modelHost)
			wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
			if setup.reader.noteCount() != 0 {
				t.Fatal("the proxy was told about a flow it never gets")
			}
			setup.counts(map[string]int{"tcp": 1, test.counted: 1})
		})
	}
}

// otherUsers is process as another user would run it.
func otherUsers(process owner.Process) owner.Process {
	process.UID = os.Getuid() + 1
	return process
}

// Every user's traffic on this Mac reaches the tunnel. A Connection's credential is
// for this user's own programs: another user's flow to its host, or one whose program
// can't be found in time, goes to the real host unread, by name and by TLS name.
func TestAnotherUsersFlowToAConnectionHostGetsNoCredential(t *testing.T) {
	plain := Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: plainHost}}
	// A model host's flow that can't be vouched for counts as a model flow whose
	// program wasn't found; any other Connection flow has a count of its own.
	opens := map[string]struct {
		open    func(*readSetup)
		unknown string
	}{
		"by its TLS name":    {func(s *readSetup) { s.open(plainHost) }, "connection_owner_unknown"},
		"by its name":        {func(s *readSetup) { s.openByName(plainHost, 443) }, "connection_owner_unknown"},
		"on another port":    {func(s *readSetup) { s.openByName(plainHost, 8443) }, "connection_owner_unknown"},
		"a model host too":   {func(s *readSetup) { s.openByName(modelHost, 443) }, "owner_lookup_failed"},
		"model, by TLS name": {func(s *readSetup) { s.open(modelHost) }, "owner_lookup_failed"},
	}
	for name, open := range opens {
		for _, test := range []struct {
			name    string
			process owner.Process
			err     error
			hang    bool
			counted string
		}{
			{"another user's tool", otherUsers(claudeCode), nil, false, "unread_other_user"},
			{"another user's browser", otherUsers(browser), nil, false, "unread_other_user"},
			{"no program found", owner.Process{}, owner.ErrNotFound, false, open.unknown},
			{"no lookup on this system", owner.Process{}, owner.ErrUnsupported, false, open.unknown},
			{"a lookup that never answers", claudeCode, nil, true, open.unknown},
		} {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				rules := []Rule{plain, {ConnectionID: "model", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: modelHost}}}
				setup := newReadSetup(t, rules...)
				setup.router.Read(setup.reader, true)
				setup.router.Upstream.Override[plainHost+":443"] = setup.ends.destination
				setup.router.Upstream.Override[plainHost+":8443"] = setup.ends.destination
				setup.router.Upstream.Override[modelHost+":8443"] = setup.ends.destination
				setup.owners.process, setup.owners.err = test.process, test.err
				if test.hang {
					setup.router.FindOwnersWith(setup.owners.find, 50*time.Millisecond)
					hang := make(chan struct{})
					setup.owners.hang = hang
					t.Cleanup(func() { close(hang) })
				}
				open.open(setup)
				setup.arrives(setup.ends.atDestination)
				select {
				case seen := <-setup.ends.atProxy:
					t.Fatalf("the flow went to the proxy: CONNECT %s", seen.authority)
				default:
				}
				if setup.reader.noteCount() != 0 {
					t.Fatal("the proxy was told about a flow it never gets")
				}
				deadline := time.Now().Add(5 * time.Second)
				for setup.router.Counts()[test.counted] != 1 {
					if time.Now().After(deadline) {
						t.Fatalf("counts %v, want one %s", setup.router.Counts(), test.counted)
					}
					time.Sleep(10 * time.Millisecond)
				}
			})
		}
	}
}

// The proxy is told it isn't to be read all the same: a CONNECT it knew nothing about
// would be taken for one of its own clients. Its program is looked up once, to know
// the flow is this user's.
func TestAConnectionHostNobodyReadsIsLookedUpOnce(t *testing.T) {
	setup := newReadSetup(t, Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: plainHost, Port: 443}})
	flow := setup.open(plainHost)
	seen := setup.arrives(setup.ends.atProxy)
	if seen.authority != plainHost+":443" || !seen.noted || seen.tool != "" {
		t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
	}
	if asked := setup.owners.lookups(); len(asked) != 1 || asked[0].Source.Port() != flow.Source.Port() || asked[0].Dest != flow.Dest {
		t.Fatalf("looked up %v for the flow %v to %v", asked, flow.Source, flow.Dest)
	}
	setup.counts(map[string]int{"proxy_by_tls_name": 1})
}

// A flow from another peer is that peer's to vouch for: no program here is looked up.
func TestAnotherPeersFlowToAConnectionHostNeedsNoLookup(t *testing.T) {
	setup := newReadSetup(t, Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: plainHost, Port: 443}})
	upstream, err := net.Dial("tcp", setup.ends.destination)
	if err != nil {
		t.Fatal(err)
	}
	setup.run(plainHost, Flow{
		Source: netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))), Dest: netip.MustParseAddrPort("203.0.113.7:443"),
		Peer: "sandbox-1", Prepared: upstream,
	})
	if seen := setup.arrives(setup.ends.atProxy); seen.authority != plainHost+":443" {
		t.Fatalf("CONNECT %s", seen.authority)
	}
	if asked := setup.owners.lookups(); len(asked) != 0 {
		t.Fatalf("the flow's program was looked up: %v", asked)
	}
}

// Every CONNECT the router sends is told of first, whatever the flow is: a
// Connection's host by its name or by its TLS name, on any port, a model host for its
// own tool, and a name the tunnel once handed an address out for.
func TestEveryConnectIsNotedBeforeItIsSent(t *testing.T) {
	plain := Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: plainHost}}
	for name, test := range map[string]struct {
		rules   []Rule
		process owner.Process
		open    func(*readSetup)
		tool    string
	}{
		"a Connection's host by its TLS name":       {[]Rule{plain}, browser, func(s *readSetup) { s.open(plainHost) }, ""},
		"a Connection's host by its name":           {[]Rule{plain}, browser, func(s *readSetup) { s.openByName(plainHost, 443) }, ""},
		"a Connection's host on another port":       {[]Rule{plain}, claudeCode, func(s *readSetup) { s.openByName(plainHost, 8443) }, ""},
		"a model host for its own tool":             {nil, claudeCode, func(s *readSetup) { s.open(modelHost) }, "claude"},
		"a model host that is a Connection's, too":  {[]Rule{modelConnection()}, browser, func(s *readSetup) { s.open(modelHost) }, ""},
		"a Connection's model host on another port": {[]Rule{{ConnectionID: "model", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: modelHost}}}, claudeCode, func(s *readSetup) { s.openByName(modelHost, 8443) }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			setup := newReadSetup(t, test.rules...)
			setup.owners.process = test.process
			setup.reader.before = func(connectFrom string) {
				if setup.ends.connected(connectFrom) {
					t.Error("the CONNECT was sent before the proxy was told whose flow it is")
				}
			}
			test.open(setup)
			seen := setup.arrives(setup.ends.atProxy)
			if !seen.noted || seen.tool != test.tool {
				t.Fatalf("CONNECT %s: the proxy had been told %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
			}
			if address, err := netip.ParseAddrPort(seen.from); err != nil || !address.Addr().IsLoopback() {
				t.Fatalf("the CONNECT came from %s", seen.from)
			}
		})
	}
	t.Run("a name that is no longer anyone's", func(t *testing.T) {
		setup := newReadSetup(t, plain)
		address, ok := setup.address(plainHost)
		if !ok {
			t.Fatal("the name didn't resolve into the tunnel")
		}
		// Its Connection goes, and a program still holds the address.
		setup.router.SetRules(nil)
		setup.run(plainHost, Flow{Source: netip.AddrPortFrom(LocalAddress, 50999), Dest: netip.AddrPortFrom(address, 443)})
		if seen := setup.arrives(setup.ends.atProxy); !seen.noted || seen.tool != "" {
			t.Fatalf("CONNECT %s: the proxy had been told %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
	})
}

// The proxy keeps only so many notes. A flow it couldn't be told about isn't handed
// over to be read: it would be taken for one of the proxy's own clients. A flow that
// needs a Connection's credential still goes, and counts as read for nobody.
func TestAFlowTheProxyCannotBeToldAbout(t *testing.T) {
	full := errors.New("too many flows are waiting for their CONNECT")
	t.Run("a tool's model flow goes on unread", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.owners.process, setup.reader.refuse = claudeCode, full
		setup.open(modelHost)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		select {
		case seen := <-setup.ends.atProxy:
			t.Fatalf("the flow went to the proxy with nothing said of it: CONNECT %s", seen.authority)
		case <-time.After(200 * time.Millisecond):
		}
		setup.counts(map[string]int{"tcp": 1, "unread_not_noted": 1})
	})
	t.Run("captured by name", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process, setup.reader.refuse = claudeCode, full
		setup.openByName(modelHost, 443)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		select {
		case seen := <-setup.ends.atProxy:
			t.Fatalf("the flow went to the proxy with nothing said of it: CONNECT %s", seen.authority)
		case <-time.After(200 * time.Millisecond):
		}
		setup.counts(map[string]int{"tcp": 1, "unread_not_noted": 1})
	})
	t.Run("a Connection's flow still goes to the proxy", func(t *testing.T) {
		setup := newReadSetup(t, Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: plainHost, Port: 443}})
		setup.reader.refuse = full
		setup.open(plainHost)
		seen := setup.arrives(setup.ends.atProxy)
		if seen.authority != plainHost+":443" || seen.noted {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		wholeHello(t, seen.hello, plainHost)
		setup.counts(map[string]int{"proxy_by_tls_name": 1, "proxy_not_noted": 1})
	})
	// Even its own tool's flow isn't counted as read: the proxy was never told.
	t.Run("a Connection's model host still goes, and is read for nobody", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.owners.process, setup.reader.refuse = claudeCode, full
		setup.open(modelHost)
		if seen := setup.arrives(setup.ends.atProxy); seen.authority != modelHost+":443" || seen.noted {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		setup.counts(map[string]int{"proxy_by_tls_name": 1, "proxy_not_noted": 1})
	})
	t.Run("a Connection's host captured by name", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.router.Read(setup.reader, true)
		setup.owners.process, setup.reader.refuse = claudeCode, full
		setup.openByName(modelHost, 443)
		if seen := setup.arrives(setup.ends.atProxy); seen.authority != modelHost+":443" || seen.noted {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		setup.counts(map[string]int{"proxy": 1, "proxy_not_noted": 1})
	})
}

// The reader is told when the router closes each connection it told it about,
// whether the flow ran its course, the proxy turned it away, or it was never sent.
func TestTheReaderIsToldWhenAConnectionToTheProxyCloses(t *testing.T) {
	for name, test := range map[string]struct {
		rules  []Rule
		refuse error
		turn   bool
	}{
		"a flow that ran its course":      {nil, nil, false},
		"a flow the proxy turned away":    {nil, nil, true},
		"a flow that was never sent":      {nil, errors.New("full"), false},
		"a Connection's flow, never told": {[]Rule{modelConnection()}, errors.New("full"), false},
	} {
		t.Run(name, func(t *testing.T) {
			setup := newReadSetup(t, test.rules...)
			setup.owners.process, setup.reader.refuse = claudeCode, test.refuse
			setup.ends.refuse.Store(test.turn)
			program := setup.openHeld(modelHost)
			// The flow is under way before the program goes: at the proxy, or, when
			// it was never sent there, at its destination.
			if test.refuse == nil || len(test.rules) > 0 {
				setup.arrives(setup.ends.atProxy)
			} else {
				wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
			}
			program.Close()
			deadline := time.Now().Add(5 * time.Second)
			for {
				told, closed := setup.reader.closedOnce()
				if told == 1 && closed {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("the reader was told of %d connections, and not that each had closed (all closed: %v)", told, closed)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// saidConn is a connection that says when it is closed.
type saidConn struct {
	net.Conn
	closing func()
}

func (c saidConn) Close() error {
	c.closing()
	return nil
}

// The reader is told the router is done with a connection while the router still
// holds it. The proxy knows the connection by the address it comes from, and once it
// is closed that address can go to another program: told afterwards, the proxy would
// take that program's connection for this one for a moment, with whatever was noted
// for it. Every connection to the proxy is closed through here, however it ends.
func TestTheReaderIsToldBeforeAConnectionToTheProxyIsClosed(t *testing.T) {
	var order []string
	conn := &bufferedConn{
		Conn:   saidConn{closing: func() { order = append(order, "closed") }},
		closed: func() { order = append(order, "told") },
	}
	_ = conn.Close()
	// Closing it again tells nobody anything.
	_ = conn.Close()
	if !reflect.DeepEqual(order, []string{"told", "closed", "closed"}) {
		t.Fatalf("a connection to the proxy went %v", order)
	}
}

// address asks the router's resolver for a name, as the system would.
func (s *readSetup) address(name string) (netip.Addr, bool) {
	s.t.Helper()
	found := answers(s.t, s.router.AnswerDNS(query(s.t, name+".", dnsmessage.TypeA)))
	if len(found) != 1 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(found[0].Body.(*dnsmessage.AResource).A), true
}

func (s *readSetup) openByName(host string, port uint16) Flow {
	s.t.Helper()
	address, ok := s.address(host)
	if !ok || !TunnelPrefix.Contains(address) {
		s.t.Fatalf("%s didn't resolve into the tunnel: %v", host, address)
	}
	flow := Flow{Source: netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))), Dest: netip.AddrPortFrom(address, port)}
	s.run(host, flow)
	return flow
}

func TestModelHostsAreCapturedByNameOnlyWhenAsked(t *testing.T) {
	setup := newReadSetup(t)
	if address, ok := setup.address(modelHost); ok {
		t.Fatalf("with everything routed in, %s was still given the tunnel address %s", modelHost, address)
	}
	if got, _ := setup.router.CapturedDomains(); !reflect.DeepEqual(got, []string{ControlHost}) {
		t.Fatalf("captured %v", got)
	}
	setup.router.Read(setup.reader, true)
	if _, ok := setup.address(modelHost); !ok {
		t.Fatalf("%s wasn't captured by name", modelHost)
	}
	if got := answers(t, setup.router.AnswerDNS(query(t, modelHost+".", dnsmessage.TypeAAAA))); len(got) != 0 {
		t.Fatal("an IPv6 address was handed out, which would skip the router")
	}
	// A name under a model host's domain that nobody reads is the network's to answer.
	if address, ok := setup.address("cdn." + modelHost); ok {
		t.Fatalf("cdn.%s was given %s", modelHost, address)
	}
	want := []string{otherModelHost, modelHost, ControlHost}
	if got, skipped := setup.router.CapturedDomains(); !reflect.DeepEqual(got, want) || skipped != 0 {
		t.Fatalf("captured %v, want %v", got, want)
	}
}

func TestAModelHostCapturedByName(t *testing.T) {
	t.Run("its tool's flow goes to the proxy", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process = claudeCode
		flow := setup.openByName(modelHost, 443)
		seen := setup.arrives(setup.ends.atProxy)
		if seen.authority != modelHost+":443" || !seen.noted || seen.tool != "claude" {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		wholeHello(t, seen.hello, modelHost)
		if asked := setup.owners.lookups(); len(asked) != 1 || asked[0].Source.Port() != flow.Source.Port() || asked[0].Dest != flow.Dest {
			t.Fatalf("looked up %v for the flow %v to %v", asked, flow.Source, flow.Dest)
		}
		setup.counts(map[string]int{"read": 1})
	})
	t.Run("another program's flow leaves unread", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.openByName(modelHost, 443)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		if setup.reader.noteCount() != 0 {
			t.Fatal("the proxy was told about a flow it never gets")
		}
		setup.counts(map[string]int{"tcp": 1, "unread_not_tool": 1})
	})
	t.Run("a failed lookup leaves the flow unread", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process, setup.owners.err = claudeCode, owner.ErrNotFound
		setup.openByName(modelHost, 443)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		setup.counts(map[string]int{"tcp": 1, "owner_lookup_failed": 1})
	})
	t.Run("another port leaves unread, with no lookup", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		setup.owners.process = claudeCode
		setup.openByName(modelHost, 80)
		wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
		if asked := setup.owners.lookups(); len(asked) != 0 {
			t.Fatalf("the flow's program was looked up: %v", asked)
		}
		setup.counts(map[string]int{"tcp": 1})
	})
	t.Run("a destination that can't be reached is counted", func(t *testing.T) {
		setup := newReadSetup(t)
		setup.router.Read(setup.reader, true)
		closed, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		setup.router.Upstream.Override[modelHost+":443"] = closed.Addr().String()
		closed.Close()
		setup.openByName(modelHost, 443)
		setup.counts(map[string]int{"tcp_failed": 1, "unread_not_tool": 1})
	})
	t.Run("a Connection's host as well goes to the proxy whoever opened it", func(t *testing.T) {
		setup := newReadSetup(t, modelConnection())
		setup.router.Read(setup.reader, true)
		setup.openByName(modelHost, 443)
		seen := setup.arrives(setup.ends.atProxy)
		if seen.authority != modelHost+":443" || !seen.noted || seen.tool != "" {
			t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
		}
		setup.counts(map[string]int{"proxy": 1, "unread_not_tool": 1})
	})
}

func TestReadDomains(t *testing.T) {
	got := ReadDomains(map[string][]string{
		"claude":   {"api.anthropic.com"},
		"codex":    {"chatgpt.com", "API.OpenAI.com."},
		"cursor":   {"cursor.sh", "*.cursor.sh", " *.Cursor.SH "},
		"careless": {"", "*.", "localhost", "under_score.example.com", "two words.example.com", "../../etc/hosts", "*.*.example.com"},
	})
	want := []string{"api.anthropic.com", "api.openai.com", "chatgpt.com", "cursor.sh"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := ReadDomains(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestReadToolsListsEachToolWithItsHosts(t *testing.T) {
	router := NewRouter(&Upstream{}, nil)
	if got := router.ReadTools(); got != nil {
		t.Fatalf("with no reader: %v", got)
	}
	hosts := map[string][]string{"codex": {"chatgpt.com", "api.openai.com"}, "claude": {"api.anthropic.com"}, "cursor": {}, "": {"nobody.example"}}
	router.Read(&fakeReader{hosts: hosts}, false)
	want := map[string][]string{"codex": {"api.openai.com", "chatgpt.com"}, "claude": {"api.anthropic.com"}}
	if got := router.ReadTools(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if hosts["codex"][0] != "chatgpt.com" {
		t.Fatal("the reader's own list was reordered")
	}
}

// The Postgres adapter signs in with a Connection's credential, so another user's
// flow to a Postgres Connection's host goes to the real host instead.
func TestAnotherUsersFlowToAPostgresHostSkipsTheAdapter(t *testing.T) {
	const dbHost = "db.example.test"
	listen := func() (string, chan struct{}) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		reached := make(chan struct{}, 4)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				reached <- struct{}{}
				conn.Close()
			}
		}()
		return listener.Addr().String(), reached
	}
	adapter, atAdapter := listen()
	destination, atDestination := listen()
	for name, test := range map[string]struct {
		process owner.Process
		want    chan struct{}
	}{
		"this user's program":    {browser, atAdapter},
		"another user's program": {otherUsers(browser), atDestination},
	} {
		t.Run(name, func(t *testing.T) {
			router := NewRouter(&Upstream{Servers: []string{}, Override: map[string]string{dbHost + ":5432": destination}}, nil)
			rule := Rule{ConnectionID: "db", Protocol: "postgres", Host: agentapi.HostRule{Match: "exact", Value: dbHost, Port: 5432}}
			if err := router.Update("http://phase:secret@127.0.0.1:1", adapter, []Rule{rule}); err != nil {
				t.Fatal(err)
			}
			router.FindOwnersWith(func(context.Context, int, netip.AddrPort) (owner.Process, error) { return test.process, nil }, time.Second)
			found := answers(t, router.AnswerDNS(query(t, dbHost+".", dnsmessage.TypeA)))
			if len(found) != 1 {
				t.Fatal("the host didn't resolve into the tunnel")
			}
			program, routerEnd := net.Pipe()
			defer program.Close()
			go func() {
				defer routerEnd.Close()
				router.HandleTCP(routerEnd, Flow{Source: netip.AddrPortFrom(LocalAddress, 50102), Dest: netip.AddrPortFrom(netip.AddrFrom4(found[0].Body.(*dnsmessage.AResource).A), 5432)})
			}()
			select {
			case <-test.want:
			case <-time.After(5 * time.Second):
				t.Fatal("the flow never reached where it should")
			}
		})
	}
}
