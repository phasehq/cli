// Package helper is the privileged half of the tunnel. It owns the operating system's
// tunnel device, routes and DNS entries, and nothing else: it never sees a
// credential. Its one rule is that a fault in Phase must never cost the machine its
// network, so it steps aside the moment the engine stops or traffic stops getting
// through, and comes back when things recover.
package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
)

// Options configure the helper.
type Options struct {
	SocketPath string
	// AllowedUID is the only user, apart from root, who may use the helper.
	AllowedUID int
	Version    string
	System     System
	Logf       func(format string, args ...any)
	// Probe reports whether the internet is reachable with dialer, and EngineAnswers
	// whether the engine answers through the tunnel. Tests replace both.
	Probe         func(dialer *net.Dialer) error
	EngineAnswers func(wait time.Duration) bool
}

// ProbeTargets are reached to check the internet. Both sit inside every route set.
var ProbeTargets = []string{"1.1.1.1:443", "1.0.0.1:443"}

// Probe dials the probe targets.
func Probe(dialer *net.Dialer) error {
	var lastErr error
	for _, target := range ProbeTargets {
		conn, err := dialer.Dial("tcp", target)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// EngineAnswers checks the whole path through WireGuard, using the address that is
// always routed into the tunnel and the one host the engine answers itself.
func EngineAnswers(wait time.Duration) bool {
	address := net.JoinHostPort(tunnel.ProbeAddress.String(), strconv.Itoa(tunnel.ProbePort))
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			reply, readErr := io.ReadAll(conn)
			_ = conn.Close()
			if readErr == nil && string(reply) == tunnel.ProbeReply {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// Helper is the running helper.
type Helper struct {
	opts       Options
	privateKey string
	publicKey  string
	events     chan any

	// Everything below belongs to the event loop.
	tunDevice  tun.Device
	deviceName string
	wg         *device.Device
	engine     *control.Conn
	engineID   int
	enginePID  int
	attach     control.Attach
	// added are the capture routes this helper added and hasn't given back. They are
	// the only routes it ever removes.
	added     []string
	captured  atomic.Bool
	reason    string
	since     time.Time
	pathFails int
	heldUntil time.Time
	backoff   time.Duration
	lastTry   time.Time
	lastPin   time.Time
	pinned    string
	unpin     func()
}

type (
	attachEvent struct {
		conn   *control.Conn
		attach control.Attach
		// pid is the process on the other end of the connection, when the system says.
		pid    int
		result chan error
		id     chan int
	}
	detachEvent struct{ id int }
	updateEvent struct {
		id      int
		domains []string
	}
	statusEvent struct{ result chan control.Status }
	downEvent   struct{ result chan error }
	pathEvent   struct{ err error }
)

// New prepares a helper.
func New(opts Options) (*Helper, error) {
	if opts.System == nil {
		opts.System = Default()
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Probe == nil {
		opts.Probe = Probe
	}
	if opts.EngineAnswers == nil {
		opts.EngineAnswers = EngineAnswers
	}
	private, public, err := tunnel.NewKeyPair()
	if err != nil {
		return nil, err
	}
	return &Helper{opts: opts, privateKey: private, publicKey: public, events: make(chan any, 32), backoff: 30 * time.Second, unpin: func() {}}, nil
}

// Run serves until ctx ends, then leaves the machine as it found it.
func (h *Helper) Run(ctx context.Context) error {
	h.opts.System.RemoveResolvers()
	listener, err := listen(h.opts.SocketPath, h.opts.AllowedUID)
	if err != nil {
		return err
	}
	defer os.Remove(h.opts.SocketPath)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go h.accept(listener)
	go h.watchPath(ctx)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	defer h.shutdown("the helper stopped")
	h.opts.Logf("helper ready on %s", h.opts.SocketPath)
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-h.events:
			h.handle(event)
		case <-tick.C:
			h.retry()
			h.maintainPin()
		}
	}
}

func listen(path string, uid int) (net.Listener, error) {
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, uid, -1); err != nil && os.Geteuid() == 0 {
		listener.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (h *Helper) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go h.serve(conn)
	}
}

// serve handles one connection. An attach keeps it open for the engine's whole life.
func (h *Helper) serve(raw net.Conn) {
	defer raw.Close()
	if !peerAllowed(raw, h.opts.AllowedUID) {
		return
	}
	conn := control.Wrap(raw)
	var request control.Request
	if err := conn.Receive(&request, 5*time.Second); err != nil {
		return
	}
	switch request.Op {
	case control.OpStatus:
		result := make(chan control.Status, 1)
		h.events <- statusEvent{result: result}
		status := <-result
		_ = conn.Send(control.Reply{Status: &status})
	case control.OpDown:
		result := make(chan error, 1)
		h.events <- downEvent{result: result}
		err := <-result
		_ = conn.Send(replyFor(err))
	case control.OpAttach:
		if request.Attach == nil {
			_ = conn.Send(control.Reply{Error: "attach needs details"})
			return
		}
		if err := validateAttach(request.Attach); err != nil {
			_ = conn.Send(control.Reply{Error: err.Error()})
			return
		}
		result, ids := make(chan error, 1), make(chan int, 1)
		h.events <- attachEvent{conn: conn, attach: *request.Attach, pid: peerPID(raw), result: result, id: ids}
		if err := <-result; err != nil {
			_ = conn.Send(control.Reply{Error: err.Error()})
			return
		}
		id := <-ids
		if err := conn.Send(control.Reply{PeerPublicKey: h.publicKey}); err != nil {
			h.events <- detachEvent{id: id}
			return
		}
		// The engine sends a ping every second. Silence for three means it has hung.
		for {
			var next control.Request
			if err := conn.Receive(&next, 3*time.Second); err != nil {
				h.events <- detachEvent{id: id}
				return
			}
			if next.Op == control.OpUpdate {
				h.events <- updateEvent{id: id, domains: next.Domains}
			}
		}
	default:
		_ = conn.Send(control.Reply{Error: "unknown request"})
	}
}

func replyFor(err error) control.Reply {
	if err != nil {
		return control.Reply{Error: err.Error()}
	}
	return control.Reply{}
}

// validateAttach checks what an engine asks for, and writes its routes one way.
func validateAttach(attach *control.Attach) error {
	if !tunnel.ValidKey(attach.EnginePublicKey) {
		return errors.New("the engine's key is malformed")
	}
	if attach.EnginePort < 1024 || attach.EnginePort > 65535 {
		return errors.New("the engine's port is out of range")
	}
	routes, err := captureRoutes(attach.Routes)
	if err != nil {
		return err
	}
	attach.Routes = routes
	for _, domain := range attach.Domains {
		if !validDomain(domain) {
			return fmt.Errorf("domain %q is malformed", domain)
		}
	}
	return nil
}

// validDomain is the engine's own rule for the names it sends, so the two can't
// come to differ.
func validDomain(domain string) bool { return tunnel.CapturableDomain(domain) }

func (h *Helper) handle(event any) {
	switch e := event.(type) {
	case attachEvent:
		e.result <- h.attachEngine(e.conn, e.attach, e.pid)
		e.id <- h.engineID
		h.reconcile("an engine attached")
	case detachEvent:
		if e.id == h.engineID && h.engine != nil {
			h.engine, h.enginePID = nil, 0
			h.stepAside("the engine stopped")
		}
	case updateEvent:
		if e.id == h.engineID && h.engine != nil {
			valid := e.domains[:0]
			for _, domain := range e.domains {
				if validDomain(domain) {
					valid = append(valid, domain)
				}
			}
			h.attach.Domains = valid
			if h.captured.Load() {
				if err := h.opts.System.InstallResolvers(valid); err != nil {
					h.opts.Logf("couldn't update the DNS entries: %v", err)
				}
				h.opts.System.FlushDNS()
			}
		}
	case statusEvent:
		e.result <- h.status()
	case downEvent:
		h.shutdown("asked to stop")
		e.result <- nil
	case pathEvent:
		h.notePath(e.err)
	}
}

func (h *Helper) status() control.Status {
	status := control.Status{
		Protocol: control.ProtocolVersion, Version: h.opts.Version, Device: h.deviceName,
		Attached: h.engine != nil, EnginePID: h.enginePID, Capturing: h.captured.Load(), Reason: h.reason, Since: h.since,
		Pinned: h.pinned, Domains: h.attach.Domains, Routes: h.attach.Routes, Retry: h.heldUntil,
	}
	// While it isn't capturing, any route still on record is one it couldn't remove.
	if !status.Capturing {
		status.RoutesLeft = append([]string(nil), h.added...)
	}
	return status
}

// attachEngine sets up the device the first time, and points WireGuard at the engine.
func (h *Helper) attachEngine(conn *control.Conn, attach control.Attach, pid int) error {
	if h.engine != nil {
		_ = h.engine.Close()
		h.engine, h.enginePID = nil, 0
		h.stepAside("another engine attached")
	}
	if h.wg == nil {
		if err := h.openDevice(); err != nil {
			return err
		}
	}
	config := fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=5\n",
		attach.EnginePublicKey, attach.EnginePort)
	if err := h.wg.IpcSet(config); err != nil {
		return fmt.Errorf("point WireGuard at the engine: %w", err)
	}
	if len(attach.Routes) == 0 {
		attach.Routes = tunnel.FullRoutes
	}
	h.attach = attach
	h.engine, h.enginePID = conn, pid
	h.engineID++
	h.heldUntil = time.Time{}
	h.backoff = 30 * time.Second
	return nil
}

func (h *Helper) openDevice() error {
	if err := h.opts.System.CheckRange(); err != nil {
		return err
	}
	tunDevice, name, err := h.opts.System.CreateDevice(tunnel.MTU)
	if err != nil {
		return fmt.Errorf("create the tunnel device: %w", err)
	}
	wg := device.NewDevice(tunDevice, &tunnel.LoopbackBind{}, device.NewLogger(device.LogLevelError, "phase helper: "))
	if err := h.opts.System.Configure(name); err != nil {
		wg.Close()
		return err
	}
	if err := wg.IpcSet("private_key=" + h.privateKey + "\n"); err != nil {
		wg.Close()
		return err
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		return err
	}
	h.tunDevice, h.deviceName, h.wg = tunDevice, name, wg
	return nil
}

// retry comes back once whatever made the helper step aside has passed.
func (h *Helper) retry() {
	if h.captured.Load() || h.engine == nil || time.Now().Before(h.heldUntil) || time.Since(h.lastTry) < 2*time.Second {
		return
	}
	h.reconcile("trying again")
}

// reconcile captures when there's an engine and nothing says not to. Each step can
// fail, and each failure leaves the machine as it would be without Phase.
func (h *Helper) reconcile(reason string) {
	if h.captured.Load() || h.engine == nil || time.Now().Before(h.heldUntil) {
		return
	}
	h.lastTry = time.Now()
	if !h.opts.EngineAnswers(6 * time.Second) {
		h.reason = "the engine isn't answering through the tunnel yet"
		return
	}
	// The only time a direct check means anything is before the routes change.
	if err := h.opts.Probe(&net.Dialer{Timeout: 4 * time.Second}); err != nil {
		h.reason = "waiting for the internet: " + err.Error()
		return
	}
	if err := h.engage(); err != nil {
		h.opts.Logf("couldn't capture: %v", err)
		h.holdOff()
		h.stepAside("couldn't capture: " + err.Error())
		return
	}
	// After that, only a check through the tunnel can be trusted.
	if err := h.confirm(8 * time.Second); err != nil {
		h.holdOff()
		h.stepAside("traffic didn't get through: " + err.Error())
		return
	}
	h.backoff = 30 * time.Second
	h.reason = reason
	h.since = time.Now()
	h.opts.Logf("capturing (%s)", reason)
}

func (h *Helper) engage() error {
	if err := h.opts.System.InstallResolvers(h.attach.Domains); err != nil {
		return err
	}
	h.opts.System.FlushDNS()
	h.pin()
	// What was added is kept even when not all of it could be: another VPN may hold
	// the very same route, and that one isn't this helper's to give back. A route
	// that couldn't be given back earlier is still on record, and isn't kept twice.
	added, err := h.opts.System.AddRoutes(h.deviceName, h.attach.Routes)
	for _, route := range added {
		if !slices.Contains(h.added, route) {
			h.added = append(h.added, route)
		}
	}
	if err != nil {
		return err
	}
	h.pathFails = 0
	h.captured.Store(true)
	return nil
}

func (h *Helper) confirm(wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var err error
	for time.Now().Before(deadline) {
		if err = h.opts.Probe(&net.Dialer{Timeout: 3 * time.Second}); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

// stepAside leaves the machine exactly as it would be without Phase. The device
// stays, so coming back needs no new step from anyone.
//
// Only the routes this helper added are removed. The system removes a route by where
// it goes to, whoever added it, so asking for one that was never added here would
// take away another VPN's route to the same place.
//
// A route that couldn't be removed stays on record: it still sends what it covers
// into the tunnel, so the next step aside tries again, and status says so meanwhile.
func (h *Helper) stepAside(reason string) {
	var left []string
	if h.deviceName != "" && len(h.added) > 0 {
		if left = h.opts.System.RemoveRoutes(h.deviceName, h.added); len(left) > 0 {
			h.opts.Logf("couldn't remove the routes %s from %s; they are tried again at the next step aside, and phase down removes them with the device", strings.Join(left, ", "), h.deviceName)
		}
	}
	h.added = left
	h.unpinNow()
	h.opts.System.RemoveResolvers()
	h.opts.System.FlushDNS()
	wasCaptured := h.captured.Swap(false)
	h.reason = reason
	h.since = time.Now()
	if wasCaptured {
		h.opts.Logf("stepped aside: %s", reason)
	}
}

// shutdown also closes the device and lets go of the engine.
func (h *Helper) shutdown(reason string) {
	h.stepAside(reason)
	if h.engine != nil {
		_ = h.engine.Close()
		h.engine, h.enginePID = nil, 0
	}
	if h.wg != nil {
		h.wg.Close()
		h.wg, h.tunDevice, h.deviceName = nil, nil, ""
	}
	// A device's routes go with it, the ones that couldn't be removed included.
	h.added = nil
}

// holdOff waits longer each time, so a lasting fault costs a moment of network every
// few minutes rather than every few seconds.
func (h *Helper) holdOff() {
	h.heldUntil = time.Now().Add(h.backoff)
	h.backoff = min(h.backoff*2, 5*time.Minute)
}

func (h *Helper) pin() {
	name, undo, err := h.opts.System.PinPhysical()
	if err != nil {
		h.opts.Logf("couldn't keep a way out for the engine on %s: %v", name, err)
		return
	}
	h.unpinNow()
	h.pinned, h.unpin = name, undo
	h.lastPin = time.Now()
}

func (h *Helper) unpinNow() {
	h.unpin()
	h.unpin, h.pinned = func() {}, ""
}

// maintainPin follows the engine to a new interface, such as Ethernet being plugged in.
func (h *Helper) maintainPin() {
	if !h.captured.Load() || time.Since(h.lastPin) < 2*time.Second {
		return
	}
	h.lastPin = time.Now()
	if name, _ := tunnel.DefaultRouteInterface(); name != "" && name != h.pinned {
		h.pin()
	}
}

func (h *Helper) watchPath(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if h.captured.Load() {
			h.events <- pathEvent{err: h.opts.Probe(&net.Dialer{Timeout: 3 * time.Second})}
		}
	}
}

// notePath steps aside after two failures in a row, so a fault in Phase costs the
// machine its network for ten seconds or so, and never longer.
func (h *Helper) notePath(err error) {
	if err == nil || !h.captured.Load() {
		h.pathFails = 0
		return
	}
	h.pathFails++
	if h.pathFails >= 2 {
		h.holdOff()
		h.stepAside("traffic stopped getting through: " + err.Error())
	}
}
