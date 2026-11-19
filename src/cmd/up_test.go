package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
	"github.com/phasehq/cli/internal/tunnel/engine"
	gokeyring "github.com/zalando/go-keyring"
)

// A certificate authority whose key lives in one process can never be trusted by the
// programs behind the tunnel, so phase up refuses before it changes anything.
func TestUpRefusesACertificateAuthorityKeptInMemory(t *testing.T) {
	t.Run("no keystore answers", func(t *testing.T) {
		withAICAKeystore(t, errors.New("no keystore"))
		var out bytes.Buffer
		if err := ensureTunnelCATrust(&out); !errors.Is(err, errTunnelNeedsKeystore) {
			t.Fatalf("err = %v, output %q", err, out.String())
		}
		if _, err := os.Stat(filepath.Join(aiCAStore.Directory, "ca.pem")); err == nil {
			t.Fatal("a certificate was published for a certificate authority nothing can trust")
		}
	})
	t.Run("the keystore will not keep the key", func(t *testing.T) {
		withAICAKeystore(t, gokeyring.ErrNotFound)
		var out bytes.Buffer
		if err := ensureTunnelCATrust(&out); !errors.Is(err, errTunnelNeedsKeystore) {
			t.Fatalf("err = %v, output %q", err, out.String())
		}
	})
}

func TestRoutesFlag(t *testing.T) {
	for _, test := range []struct {
		value string
		want  []string
	}{
		{"", nil},
		{" , ", nil},
		{"0.0.0.0/7", []string{"0.0.0.0/7"}},
		// A host's address is written as its network, and a repeat counts once.
		{"192.0.2.9/24, 198.51.100.0/24,192.0.2.0/24", []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{"2001:db8::1/32", []string{"2001:db8::/32"}},
		// Everything, written out, is still everything.
		{"0.0.0.0/1,128.0.0.0/1,::/1,8000::/1", nil},
		{"::/1, 8000::/1, 128.0.0.0/1, 0.0.0.0/1", nil},
	} {
		got, err := parseTunnelRoutes(test.value)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Errorf("%q: %v, %v", test.value, got, err)
		}
	}
	for _, value := range []string{"everything", "192.0.2.0", "192.0.2.0/33", "0.0.0.0/0", "::/0", "192.0.2.0/24,nope"} {
		if got, err := parseTunnelRoutes(value); err == nil {
			t.Errorf("%q was taken as %v", value, got)
		}
	}
	if flag := upCmd.Flags().Lookup("routes"); flag == nil || !flag.Hidden {
		t.Error("--routes should be there, and hidden")
	}
}

func TestRoutesThatCaptureEverything(t *testing.T) {
	reordered := []string{"8000::/1", "128.0.0.0/1", "::/1", "0.0.0.0/1"}
	if !capturesEverything(nil) || !capturesEverything(tunnel.FullRoutes) || !capturesEverything(reordered) {
		t.Error("the routes that capture everything weren't recognised")
	}
	if capturesEverything([]string{"0.0.0.0/7"}) || capturesEverything(tunnel.FullRoutes[:2]) {
		t.Error("part of the network was taken for all of it")
	}
	if !sameTunnelRoutes(nil, reordered) || !sameTunnelRoutes([]string{"192.0.2.0/24", "0.0.0.0/7"}, []string{"0.0.0.0/7", "192.0.2.0/24"}) {
		t.Error("the same routes in another order looked different")
	}
	if sameTunnelRoutes(nil, []string{"0.0.0.0/7"}) || sameTunnelRoutes([]string{"0.0.0.0/7"}, []string{"0.0.0.0/8"}) {
		t.Error("different routes looked the same")
	}
}

func TestStatusSaysWhatGoesThroughPhaseAndWhatIsRead(t *testing.T) {
	since := time.Date(2026, 11, 19, 15, 4, 0, 0, time.Local)
	capturing := func(routes []string) *control.Status {
		return &control.Status{Protocol: control.ProtocolVersion, Device: "utun7", Attached: true, Capturing: true, Since: since, Routes: routes}
	}
	running := &engine.Status{
		PID: 4242, Ready: true, Interface: "en0", Connections: []string{"GitHub"}, Domains: []string{"api.github.com", "phase.invalid"},
		ReadTools: map[string][]string{"codex": {"api.openai.com", "chatgpt.com"}, "claude": {"api.anthropic.com"}, "cursor": nil},
		Counts: map[string]int{
			"proxy": 3, "proxy_by_tls_name": 1, "postgres": 1, "tcp": 40, "udp": 2,
			"read": 12, "unread_not_tool": 7, "owner_lookup_failed": 2,
		},
	}
	print := func(helperStatus *control.Status, status *engine.Status) string {
		var out bytes.Buffer
		printTunnelStatus(&out, helperStatus, 4242, status, since.Add(time.Minute))
		return out.String()
	}

	t.Run("everything", func(t *testing.T) {
		got := print(capturing(tunnel.FullRoutes), running)
		want := "🚇 Everything goes through Phase, by utun7, since 15:04.\n" +
			"   Engine: running as you (pid 4242), leaving by en0.\n" +
			"   Connections: GitHub\n" +
			"   Names sent to Phase: api.github.com, phase.invalid\n" +
			"   Flows: 5 to Connection hosts, 42 passed through unread.\n" +
			"   Model traffic is read for each tool's own processes: claude (api.anthropic.com); codex (api.openai.com, chatgpt.com)\n" +
			"   Model flows: 12 read, 7 left unread for other programs, 2 left unread because the program wasn't found in time.\n"
		if got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("part of the network", func(t *testing.T) {
		got := print(capturing([]string{"0.0.0.0/7", "192.0.2.0/24"}), running)
		if !strings.HasPrefix(got, "🚇 Only 0.0.0.0/7, 192.0.2.0/24, and the names sent to Phase, go through it, by utun7, since 15:04. Everything else is untouched.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if strings.Contains(got, "Everything goes through Phase") {
			t.Fatalf("part of the network was reported as all of it:\n%s", got)
		}
	})

	t.Run("flows the proxy couldn't take", func(t *testing.T) {
		missed := *running
		missed.Counts = map[string]int{"read": 1, "unread_no_proxy": 3}
		got := print(capturing(nil), &missed)
		if !strings.HasSuffix(got, "   Model flows: 1 read, 0 left unread for other programs, 0 left unread because the program wasn't found in time.\n"+
			"   3 more went on unread because Phase's proxy couldn't take them.\n") {
			t.Fatalf("got:\n%s", got)
		}
	})

	t.Run("nothing is read", func(t *testing.T) {
		unread := *running
		unread.ReadTools = nil
		got := print(capturing(nil), &unread)
		if !strings.Contains(got, "   Model traffic: not read.\n") || strings.Contains(got, "Model flows") {
			t.Fatalf("got:\n%s", got)
		}
	})

	t.Run("not capturing", func(t *testing.T) {
		waiting := &control.Status{Reason: "traffic stopped getting through: timeout", Retry: since.Add(2 * time.Minute)}
		got := print(waiting, nil)
		want := "🚇 Phase isn't in the path: traffic stopped getting through: timeout.\n   It tries again at 15:06:00.\n   Engine: not running.\n"
		if got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
		if got := print(nil, nil); got != "🚇 Phase isn't in the path: the helper isn't running. Run phase up to start.\n   Engine: not running.\n" {
			t.Fatalf("got:\n%s", got)
		}
	})
}
