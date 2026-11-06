package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
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
}

func (f *fakeSystem) note(entry string) { f.log = append(f.log, entry) }

func (f *fakeSystem) CheckRange() error { return nil }
func (f *fakeSystem) CreateDevice(int) (tun.Device, string, error) {
	return newFakeTun(), "utun99", nil
}
func (f *fakeSystem) Configure(string) error { return nil }
func (f *fakeSystem) AddRoutes(string, []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = true
	f.note("add routes")
	return nil
}
func (f *fakeSystem) RemoveRoutes(string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = false
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(test.socket); err == nil {
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
	_, public, _ := tunnel.NewKeyPair()
	conn, err := control.Dial(h.socket)
	if err != nil {
		h.t.Fatal(err)
	}
	reply, err := conn.Call(control.Request{Op: control.OpAttach, Attach: &control.Attach{
		EnginePublicKey: public, EnginePort: 40000, Domains: domains, Routes: []string{"0.0.0.0/1", "128.0.0.0/1"},
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
