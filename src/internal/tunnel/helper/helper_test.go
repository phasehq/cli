package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
)

// fakeSystem records what the helper changed, and decides what the internet does.
type fakeSystem struct {
	mu          sync.Mutex
	routes      bool
	resolvers   []string
	pinned      bool
	internetUp  bool
	tunnelWorks bool
	log         []string
	// ours are the routes the helper added and hasn't removed. others are routes
	// that were there before it, such as another VPN's: adding one of those fails,
	// as it does on a real system, and removing one takes it from whoever added it,
	// which lost records.
	ours   map[string]bool
	others map[string]bool
	lost   []string
	// stuck are routes of the helper's that can't be removed for now, and removals
	// counts the times it was asked to remove any.
	stuck    map[string]bool
	removals int
}

func (f *fakeSystem) note(entry string) { f.log = append(f.log, entry) }

func (f *fakeSystem) CheckRange() error { return nil }
func (f *fakeSystem) CreateDevice(int) (tun.Device, string, error) {
	return newFakeTun(), "utun99", nil
}
func (f *fakeSystem) Configure(string) error { return nil }
func (f *fakeSystem) AddRoutes(_ string, prefixes []string) (added []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("add routes")
	for _, prefix := range prefixes {
		if f.ours[prefix] {
			// Left from an earlier capture, and the device's own: there to be given back.
			added = append(added, prefix)
			continue
		}
		if f.others[prefix] {
			return added, errors.New("route: writing to routing socket: File exists")
		}
		if f.ours == nil {
			f.ours = map[string]bool{}
		}
		f.ours[prefix] = true
		f.routes = true
		added = append(added, prefix)
	}
	return added, nil
}

// RemoveRoutes removes by destination, as the system does: a route of someone else's
// goes just the same.
func (f *fakeSystem) RemoveRoutes(_ string, prefixes []string) (left []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removals++
	for _, prefix := range prefixes {
		if f.others[prefix] {
			delete(f.others, prefix)
			f.lost = append(f.lost, prefix)
		}
		if f.stuck[prefix] && f.ours[prefix] {
			left = append(left, prefix)
			continue
		}
		delete(f.ours, prefix)
	}
	f.routes = len(f.ours) > 0
	return left
}

// stillThere reports whether a route that was there before the helper still is.
func (f *fakeSystem) stillThere(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.others[prefix]
}

// routeState returns the routes that are the helper's, and the ones it took from
// someone else.
func (f *fakeSystem) routeState() (ours, lost []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for prefix := range f.ours {
		ours = append(ours, prefix)
	}
	sort.Strings(ours)
	return ours, append([]string(nil), f.lost...)
}
func (f *fakeSystem) InstallResolvers(domains []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolvers = append([]string(nil), domains...)
	return nil
}
func (f *fakeSystem) RemoveResolvers() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolvers = nil
}
func (f *fakeSystem) FlushDNS() {}
func (f *fakeSystem) PinPhysical() (string, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned = true
	return "en0", func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.pinned = false
	}, nil
}

func (f *fakeSystem) probe(*net.Dialer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.routes && f.tunnelWorks, !f.routes && f.internetUp:
		return nil
	case f.routes:
		return errors.New("connect: network is unreachable")
	default:
		return errors.New("no internet")
	}
}

func (f *fakeSystem) set(change func(*fakeSystem)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeSystem) state() (routes, pinned bool, resolvers []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routes, f.pinned, append([]string(nil), f.resolvers...)
}

// fakeTun is a tunnel device that never delivers a packet.
type fakeTun struct {
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	t := &fakeTun{events: make(chan tun.Event, 1), closed: make(chan struct{})}
	t.events <- tun.EventUp
	return t
}

func (t *fakeTun) File() *os.File           { return nil }
func (t *fakeTun) MTU() (int, error)        { return tunnel.MTU, nil }
func (t *fakeTun) Name() (string, error)    { return "utun99", nil }
func (t *fakeTun) Events() <-chan tun.Event { return t.events }
func (t *fakeTun) BatchSize() int           { return 1 }
func (t *fakeTun) Write(bufs [][]byte, _ int) (int, error) {
	return len(bufs), nil
}
func (t *fakeTun) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}
func (t *fakeTun) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

type harness struct {
	t      *testing.T
	system *fakeSystem
	socket string
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, system *fakeSystem, engineAnswers bool) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h, err := New(Options{
		SocketPath: filepath.Join(dir, "s"), AllowedUID: os.Getuid(), System: system,
		Probe:         system.probe,
		EngineAnswers: func(time.Duration) bool { return engineAnswers },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()
	test := &harness{t: t, system: system, socket: filepath.Join(dir, "s"), cancel: cancel, done: done}
	t.Cleanup(test.stop)
	// The socket's file is there a moment before the helper listens on it, and a
	// connection in that moment is refused. The helper has started once it answers.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := control.Ask(test.socket, control.Request{Op: control.OpStatus}, time.Second); err == nil {
			return test
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the helper didn't start")
	return nil
}

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		h.t.Error("the helper didn't stop")
	}
}

// attach plays an engine: attach, then ping every 200ms until stopped.
func (h *harness) attach(domains []string) (stop func()) {
	h.t.Helper()
	return h.attachWith(domains, []string{"0.0.0.0/1", "128.0.0.0/1"})
}

func (h *harness) attachWith(domains, routes []string) (stop func()) {
	h.t.Helper()
	_, public, _ := tunnel.NewKeyPair()
	conn, err := control.Dial(h.socket)
	if err != nil {
		h.t.Fatal(err)
	}
	reply, err := conn.Call(control.Request{Op: control.OpAttach, Attach: &control.Attach{
		EnginePublicKey: public, EnginePort: 40000, Domains: domains, Routes: routes,
	}}, 15*time.Second)
	if err != nil {
		h.t.Fatal(err)
	}
	if !tunnel.ValidKey(reply.PeerPublicKey) {
		h.t.Fatalf("the helper's key is malformed: %q", reply.PeerPublicKey)
	}
	quit := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				conn.Close()
				return
			case <-ticker.C:
				if conn.Send(control.Request{Op: control.OpPing}) != nil {
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(quit) }) }
}

func (h *harness) status() control.Status {
	h.t.Helper()
	reply, err := control.Ask(h.socket, control.Request{Op: control.OpStatus}, 15*time.Second)
	if err != nil {
		h.t.Fatal(err)
	}
	return *reply.Status
}

func (h *harness) waitFor(what string, condition func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	routes, pinned, resolvers := h.system.state()
	h.t.Fatalf("%s never happened: routes %v, pinned %v, resolvers %v, status %+v", what, routes, pinned, resolvers, h.status())
}

func (h *harness) captured() bool {
	routes, _, _ := h.system.state()
	return routes && h.status().Capturing
}

func (h *harness) clean() bool {
	routes, pinned, resolvers := h.system.state()
	return !routes && !pinned && len(resolvers) == 0
}

func TestCapturesWhileTheEngineIsAttachedAndStepsAsideWhenItGoes(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	stop := h.attach([]string{"api.github.com"})
	h.waitFor("capture", h.captured)
	routes, pinned, resolvers := system.state()
	if !routes || !pinned || len(resolvers) != 1 || resolvers[0] != "api.github.com" {
		t.Fatalf("routes %v, pinned %v, resolvers %v", routes, pinned, resolvers)
	}
	stop()
	h.waitFor("stepping aside after the engine left", h.clean)
	if status := h.status(); status.Capturing || status.Attached {
		t.Fatalf("status after the engine left: %+v", status)
	}
}

func TestStepsAsideWhenTheEngineHangs(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	_, public, _ := tunnel.NewKeyPair()
	conn, err := control.Dial(h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Call(control.Request{Op: control.OpAttach, Attach: &control.Attach{EnginePublicKey: public, EnginePort: 40000}}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	// No pings: an engine that stopped answering without closing its connection.
	h.waitFor("capture", h.captured)
	h.waitFor("stepping aside after three silent seconds", h.clean)
}

func TestNeverCapturesWithoutTheInternet(t *testing.T) {
	system := &fakeSystem{internetUp: false, tunnelWorks: false}
	h := start(t, system, true)
	defer h.attach(nil)()
	time.Sleep(3 * time.Second)
	if routes, _, _ := system.state(); routes {
		t.Fatal("the helper took the routes with no internet to check against")
	}
	if status := h.status(); status.Capturing {
		t.Fatalf("status: %+v", status)
	}
	// Once the internet is back, it captures.
	system.set(func(f *fakeSystem) { f.internetUp, f.tunnelWorks = true, true })
	h.waitFor("capture once the internet is back", h.captured)
}

// TestBacksOutWhenTrafficDoesNotGetThrough is the first Mac run: the routes went in,
// nothing got through the tunnel, and the machine was left offline.
func TestBacksOutWhenTrafficDoesNotGetThrough(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: false}
	h := start(t, system, true)
	defer h.attach(nil)()
	h.waitFor("an attempt to capture", func() bool {
		system.mu.Lock()
		defer system.mu.Unlock()
		return len(system.log) > 0
	})
	h.waitFor("backing out", h.clean)
	status := h.status()
	if status.Capturing || status.Retry.IsZero() {
		t.Fatalf("it should be waiting to try again: %+v", status)
	}
	time.Sleep(3 * time.Second)
	if !h.clean() {
		t.Fatal("it tried again before its wait was over")
	}
}

func TestStepsAsideWhenTrafficStopsGettingThrough(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	defer h.attach(nil)()
	h.waitFor("capture", h.captured)
	system.set(func(f *fakeSystem) { f.tunnelWorks = false })
	start := time.Now()
	h.waitFor("stepping aside", h.clean)
	if elapsed := time.Since(start); elapsed > 14*time.Second {
		t.Fatalf("took %s to step aside", elapsed)
	}
}

func TestDoesNotCaptureUntilTheEngineAnswers(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, false)
	defer h.attach(nil)()
	time.Sleep(3 * time.Second)
	if !h.clean() {
		t.Fatal("captured before the engine answered through the tunnel")
	}
}

func TestDownStepsAsideAndLetsGo(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	defer h.attach([]string{"example.com"})()
	h.waitFor("capture", h.captured)
	if _, err := control.Ask(h.socket, control.Request{Op: control.OpDown}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if !h.clean() {
		t.Fatal("down left something behind")
	}
	if status := h.status(); status.Attached || status.Device != "" {
		t.Fatalf("status after down: %+v", status)
	}
}

func TestRefusesMalformedAttaches(t *testing.T) {
	h := start(t, &fakeSystem{}, true)
	_, public, _ := tunnel.NewKeyPair()
	for name, attach := range map[string]control.Attach{
		"key":    {EnginePublicKey: "nope", EnginePort: 40000},
		"port":   {EnginePublicKey: public, EnginePort: 80},
		"route":  {EnginePublicKey: public, EnginePort: 40000, Routes: []string{"everything"}},
		"domain": {EnginePublicKey: public, EnginePort: 40000, Domains: []string{"../../etc/passwd"}},
	} {
		attach := attach
		if _, err := control.Ask(h.socket, control.Request{Op: control.OpAttach, Attach: &attach}, 5*time.Second); err == nil {
			t.Errorf("%s: a malformed attach was accepted", name)
		}
	}
}

// The helper takes its routes from an unprivileged caller, and decides for itself
// which ones a capture can be made of. The command line's own check is no reason to
// trust what arrives on the socket.
func TestRefusesRoutesNoCaptureIsMadeOf(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	_, public, _ := tunnel.NewKeyPair()
	for _, route := range []string{
		// The default route itself, in either family.
		"0.0.0.0/0", "::/0", "192.0.2.1/0", "2001:db8::1/0",
		// Loopback, link-local and multicast, whole or in part.
		"127.0.0.0/8", "127.0.0.1/32", "127.64.0.0/10", "::1/128",
		"169.254.0.0/16", "169.254.169.254/32", "fe80::/10", "fe80::1/128", "febf::/16",
		"224.0.0.0/4", "239.255.255.250/32", "ff00::/8", "ff02::fb/128",
		// No address at all, broadcast, and the tunnel's own range.
		"0.0.0.0/8", "0.0.0.0/32", "::/128", "255.255.255.255/32",
		"198.19.248.0/22", "198.19.249.0/24", "198.19.248.53/32",
		// An IPv4 route written as IPv6, and what isn't a route.
		"::ffff:192.0.2.0/120", "192.0.2.0", "192.0.2.0/33", "192.0.2.0/24 ", "192.0.2.0/24;reboot", "",
	} {
		for _, routes := range [][]string{{route}, {"0.0.0.0/1", route, "128.0.0.0/1"}} {
			attach := control.Attach{EnginePublicKey: public, EnginePort: 40000, Routes: routes}
			if _, err := control.Ask(h.socket, control.Request{Op: control.OpAttach, Attach: &attach}, 5*time.Second); err == nil {
				t.Errorf("an attach with the routes %q was accepted", routes)
			}
		}
	}
	if status := h.status(); status.Attached || status.Device != "" {
		t.Fatalf("a refused attach left something behind: %+v", status)
	}
	if ours, _ := system.routeState(); len(ours) != 0 {
		t.Fatalf("routes were added for a refused attach: %v", ours)
	}
}

// What a capture is made of is accepted: each half of the address space, which takes
// in loopback and the rest without lying inside them, a part of the network for a
// first try, and another VPN's range. The routes are kept written one way, each once.
func TestAcceptsTheRoutesACaptureIsMadeOf(t *testing.T) {
	got, err := captureRoutes([]string{
		"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1",
		"0.0.0.0/7", "192.0.2.9/24", "192.0.2.0/24", "100.64.0.0/10", "198.18.0.0/15", "240.0.0.0/4",
		"2001:db8::1/32", "fc00::/7", "::/2",
	})
	want := []string{
		"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1",
		"0.0.0.0/7", "192.0.2.0/24", "100.64.0.0/10", "198.18.0.0/15", "240.0.0.0/4",
		"2001:db8::/32", "fc00::/7", "::/2",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := captureRoutes(tunnel.FullRoutes); err != nil || !reflect.DeepEqual(got, tunnel.FullRoutes) {
		t.Fatalf("the routes that capture everything: %v, %v", got, err)
	}
	if got, err := captureRoutes(nil); err != nil || len(got) != 0 {
		t.Fatalf("no routes: %v, %v", got, err)
	}

	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	defer h.attachWith(nil, []string{"192.0.2.9/24", "0.0.0.0/7", "192.0.2.0/24"})()
	h.waitFor("capture", h.captured)
	if ours, _ := system.routeState(); !reflect.DeepEqual(ours, []string{"0.0.0.0/7", "192.0.2.0/24"}) {
		t.Fatalf("the routes added: %v", ours)
	}
	if status := h.status(); !reflect.DeepEqual(status.Routes, []string{"192.0.2.0/24", "0.0.0.0/7"}) {
		t.Fatalf("the routes in status: %v", status.Routes)
	}
}

// Another VPN can hold the very route a capture asks for. Adding it fails, and the
// helper backs out. The system removes a route by where it goes to, whoever added it,
// so the helper gives back only what it added itself: the other VPN keeps its route.
func TestGivesBackOnlyTheRoutesItAdded(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true, others: map[string]bool{"128.0.0.0/1": true}}
	h := start(t, system, true)
	defer h.attach(nil)()
	h.waitFor("an attempt to capture", func() bool {
		system.mu.Lock()
		defer system.mu.Unlock()
		return len(system.log) >= 1
	})
	h.waitFor("backing out", h.clean)
	ours, lost := system.routeState()
	if len(ours) != 0 || len(lost) != 0 || !system.stillThere("128.0.0.0/1") {
		t.Fatalf("after backing out: the helper's routes %v, taken from another VPN %v", ours, lost)
	}
	status := h.status()
	if status.Capturing || status.Retry.IsZero() || !strings.Contains(status.Reason, "couldn't capture") {
		t.Fatalf("status: %+v", status)
	}
	// Asked to stop while it waits to try again, it still removes nothing of theirs.
	if _, err := control.Ask(h.socket, control.Request{Op: control.OpDown}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, lost := system.routeState(); len(lost) != 0 || !system.stillThere("128.0.0.0/1") {
		t.Fatalf("stopping took another VPN's routes: %v", lost)
	}
}

// Stepping aside before anything was captured removes no route at all: none is the
// helper's yet, and every one it was asked for may be someone else's.
func TestStepsAsideWithoutRemovingRoutesItNeverAdded(t *testing.T) {
	system := &fakeSystem{internetUp: false, tunnelWorks: false, others: map[string]bool{"0.0.0.0/1": true, "128.0.0.0/1": true}}
	h := start(t, system, true)
	stop := h.attach([]string{"api.github.com"})
	time.Sleep(time.Second)
	// The engine goes, another attaches in its place, and the helper is asked to stop.
	stop()
	h.waitFor("the engine to be let go", func() bool { return !h.status().Attached })
	defer h.attach(nil)()
	defer h.attach(nil)()
	if _, err := control.Ask(h.socket, control.Request{Op: control.OpDown}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if ours, lost := system.routeState(); len(ours) != 0 || len(lost) != 0 || !system.stillThere("0.0.0.0/1") || !system.stillThere("128.0.0.0/1") {
		t.Fatalf("the helper's routes %v, taken from another VPN %v", ours, lost)
	}
}

// Once it has captured, it gives back all it added, and only that, each time.
func TestGivesBackEveryRouteItAdded(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true, others: map[string]bool{"10.0.0.0/8": true}}
	h := start(t, system, true)
	stop := h.attachWith(nil, tunnel.FullRoutes)
	h.waitFor("capture", h.captured)
	if ours, _ := system.routeState(); !reflect.DeepEqual(ours, []string{"0.0.0.0/1", "128.0.0.0/1", "8000::/1", "::/1"}) {
		t.Fatalf("the routes added: %v", ours)
	}
	stop()
	h.waitFor("stepping aside after the engine left", h.clean)
	if ours, lost := system.routeState(); len(ours) != 0 || len(lost) != 0 || !system.stillThere("10.0.0.0/8") {
		t.Fatalf("after stepping aside: the helper's routes %v, taken from another VPN %v", ours, lost)
	}
}

// The helper says which process is attached, so that phase down can stop an engine
// it didn't start itself.
func TestStatusNamesTheAttachedEnginesProcess(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true}
	h := start(t, system, true)
	if status := h.status(); status.Attached || status.EnginePID != 0 {
		t.Fatalf("with nothing attached: %+v", status)
	}
	stop := h.attach(nil)
	want := 0
	if runtime.GOOS == "darwin" {
		want = os.Getpid()
	}
	if status := h.status(); !status.Attached || status.EnginePID != want {
		t.Fatalf("the attached engine is process %d, and status says %d", want, status.EnginePID)
	}
	stop()
	h.waitFor("the engine to be let go", func() bool { status := h.status(); return !status.Attached && status.EnginePID == 0 })
}

// A route the helper couldn't remove when it stepped aside still sends what it covers
// into the tunnel. It stays on record: status says so, and the next step aside tries
// again. Forgotten, it would stay until the device went.
func TestARouteThatCouldNotBeRemovedIsNotForgotten(t *testing.T) {
	system := &fakeSystem{internetUp: true, tunnelWorks: true, stuck: map[string]bool{"128.0.0.0/1": true}}
	h := start(t, system, true)
	stop := h.attach(nil)
	h.waitFor("capture", h.captured)
	if status := h.status(); len(status.RoutesLeft) != 0 {
		t.Fatalf("while capturing, status says routes were left behind: %v", status.RoutesLeft)
	}
	stop()
	h.waitFor("stepping aside after the engine left", func() bool { status := h.status(); return !status.Capturing && !status.Attached })
	status := h.status()
	if ours, _ := system.routeState(); !reflect.DeepEqual(ours, []string{"128.0.0.0/1"}) || !reflect.DeepEqual(status.RoutesLeft, []string{"128.0.0.0/1"}) {
		t.Fatalf("the route still there is %v, and status says %v", ours, status.RoutesLeft)
	}
	if _, pinned, resolvers := system.state(); pinned || len(resolvers) != 0 {
		t.Fatalf("stepping aside stopped at the route: pinned %v, resolvers %v", pinned, resolvers)
	}

	t.Run("an engine that comes back takes it up again, and it goes with the rest", func(t *testing.T) {
		stop := h.attach(nil)
		h.waitFor("capture", h.captured)
		if ours, _ := system.routeState(); !reflect.DeepEqual(ours, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
			t.Fatalf("the routes: %v", ours)
		}
		system.set(func(f *fakeSystem) { f.stuck = nil })
		stop()
		h.waitFor("stepping aside after the engine left", h.clean)
		if status := h.status(); len(status.RoutesLeft) != 0 {
			t.Fatalf("status still says %v", status.RoutesLeft)
		}
	})

	t.Run("the next step aside tries again", func(t *testing.T) {
		system.set(func(f *fakeSystem) { f.stuck = map[string]bool{"0.0.0.0/1": true} })
		stop := h.attach(nil)
		h.waitFor("capture", h.captured)
		stop()
		h.waitFor("the route to be left", func() bool { return len(h.status().RoutesLeft) == 1 })
		system.mu.Lock()
		system.stuck = nil
		before := system.removals
		system.mu.Unlock()
		// Asked to stop, it steps aside again, and this time the route goes.
		if _, err := control.Ask(h.socket, control.Request{Op: control.OpDown}, 15*time.Second); err != nil {
			t.Fatal(err)
		}
		system.mu.Lock()
		asked := system.removals - before
		system.mu.Unlock()
		if ours, _ := system.routeState(); asked != 1 || len(ours) != 0 || !h.clean() {
			t.Fatalf("asked to remove routes %d more times, and %v is still there", asked, ours)
		}
		if status := h.status(); len(status.RoutesLeft) != 0 || status.Device != "" {
			t.Fatalf("status after down: %+v", status)
		}
	})
}
