package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/tunnel"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A certificate authority whose key is kept in memory is new in every process, so
// nothing behind the tunnel could trust it. The engine stops before it tells the
// helper about any host, rather than capture hosts it would only break.
func TestEngineStopsWhenTheCertificateAuthorityIsKeptInMemory(t *testing.T) {
	socketDirectory, err := os.MkdirTemp("", "pe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDirectory) })
	_, peerPublic, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDirectory, "s")
	attached, _ := fakeHelper(t, socket, peerPublic)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	directory := t.TempDir()
	err = Run(ctx, Config{
		Runtime:    fakeRuntime{session: testSession(t), paths: phaseproxy.CAPaths{MemoryOnly: true}},
		SocketPath: socket, StateDirectory: directory,
		ProxyAddress:    fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		PostgresAddress: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		WireGuardPort:   freePort(t, "udp"), Upstream: &tunnel.Upstream{Servers: []string{"127.0.0.1"}}, Logf: t.Logf,
	})
	if !errors.Is(err, ErrNoKeystore) {
		t.Fatalf("the engine returned %v", err)
	}
	select {
	case attach := <-attached:
		t.Fatalf("the engine attached to the helper with %v", attach.Domains)
	default:
	}
}
