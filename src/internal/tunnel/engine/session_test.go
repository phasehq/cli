package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel"
)

// A command on this machine finds the proxy through the state the engine writes, and
// registers the secret values it hands out there. When the state can't be written no
// value is registered, so the engine doesn't say it is ready, and doesn't hand the
// helper anything to capture: it says what went wrong instead.
func TestTheEngineIsNotReadyWhenItsProxyStateCannotBeWritten(t *testing.T) {
	e := startEngineWith(t, engineSetup{unattached: true, before: func(t *testing.T, directory string) {
		// Something in the state's place that a file can't replace.
		if err := os.MkdirAll(filepath.Join(ProxyStatePath(directory), "in the way"), 0o700); err != nil {
			t.Fatal(err)
		}
	}})
	status := e.status(t, func(status Status) bool { return status.LastError != "" })
	if status.Ready || status.HelperLinked || !strings.Contains(status.LastError, "couldn't write the proxy's state") {
		t.Fatalf("status: %+v", status)
	}
	select {
	case attach := <-e.attaches:
		t.Fatalf("the engine attached to the helper with %v", attach.Domains)
	case <-time.After(1500 * time.Millisecond):
	}
	if state, err := ReadProxyState(e.directory); err == nil {
		t.Fatalf("a proxy state was read: %+v", state)
	}
	if status := e.status(t, func(Status) bool { return true }); status.Ready {
		t.Fatalf("the engine says it is ready: %+v", status)
	}
}

// oneSession hands the engine a single session, which lasts until end is closed, and
// then no other.
type oneSession struct {
	inner Runtime
	end   chan struct{}
	ended chan struct{}
	once  sync.Once
}

func (r *oneSession) ServeManaged(ctx context.Context, engine airuntime.Engine) error {
	first := false
	r.once.Do(func() { first = true })
	if !first {
		<-ctx.Done()
		return ctx.Err()
	}
	session, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-r.end:
			cancel()
		case <-session.Done():
		}
	}()
	_ = r.inner.ServeManaged(session, engine)
	cancel()
	close(r.ended)
	return airuntime.ErrSessionExpired
}

// When a session stops, the proxy that served it is gone, and with it the address it
// listened on. The router forgets that address and the capability it presented
// there: kept, the capability would go to whatever listened on that port next. The
// engine isn't ready either, until it serves a session again.
func TestAStoppedSessionLeavesTheRouterNothingToPresent(t *testing.T) {
	gate := &oneSession{end: make(chan struct{}), ended: make(chan struct{})}
	e := startEngineWith(t, engineSetup{runtime: func(inner Runtime) Runtime {
		gate.inner = inner
		return gate
	}})
	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(e.proxyCert)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: e.program.DialContext, TLSClientConfig: &tls.Config{RootCAs: proxyRoots}, DisableKeepAlives: true,
	}}
	reach := func() error {
		request, _ := http.NewRequestWithContext(e.ctx, http.MethodGet, "https://"+apiHost+"/whoami", nil)
		request.Header.Set("Authorization", "Bearer "+decoy)
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		return nil
	}
	if err := reach(); err != nil {
		t.Fatalf("while the session ran, the Connection's host: %v", err)
	}
	state, err := ReadProxyState(e.directory)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := url.Parse(state.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	e.status(t, func(status Status) bool { return status.Ready })

	close(gate.end)
	select {
	case <-gate.ended:
	case <-time.After(20 * time.Second):
		t.Fatal("the session never stopped")
	}

	// Another program takes the port the proxy has left.
	var listener net.Listener
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if listener, err = net.Listen("tcp", proxy.Host); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy's port was never free again: %v", err)
		}
	}
	defer listener.Close()
	arrived := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			request, _ := http.ReadRequest(bufio.NewReader(conn))
			said := "a connection that said nothing"
			if request != nil {
				said = request.Method + " " + request.Host + ", with a capability: " + request.Header.Get("Proxy-Authorization")
			}
			arrived <- said
			conn.Close()
		}
	}()

	if err := reach(); err == nil {
		t.Fatal("with no session, a Connection's host was still reached")
	}
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: e.program.DialContext, DisableKeepAlives: true}}
	if response, err := plain.Get("http://" + tunnel.ControlHost + "/v1/status"); err == nil {
		response.Body.Close()
		t.Fatalf("with no session, the control API answered %d", response.StatusCode)
	}
	select {
	case said := <-arrived:
		t.Fatalf("the program on the proxy's old port was sent %s", said)
	case <-time.After(500 * time.Millisecond):
	}
	if status := e.status(t, func(status Status) bool { return !status.Ready }); status.Ready {
		t.Fatalf("status: %+v", status)
	}
	if _, err := os.Lstat(ProxyStatePath(e.directory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the proxy's state outlived its session: %v", err)
	}
}
