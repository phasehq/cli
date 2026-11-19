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
		return &control.Status{
			Protocol: control.ProtocolVersion, Device: "utun7", Attached: true, Capturing: true, Since: since, Routes: routes,
			Domains: []string{"api.github.com", "phase.invalid"},
		}
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
		want := "🚇 Connections opened since 15:04 go through Phase, by utun7.\n" +
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
		if !strings.HasPrefix(got, "🚇 Only connections to 0.0.0.0/7, 192.0.2.0/24, and to the names sent to Phase, opened since 15:04 go through it, by utun7. Everything else is untouched.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if strings.Contains(got, "go through Phase, by") {
			t.Fatalf("part of the network was reported as all of it:\n%s", got)
		}
	})

	t.Run("flows the proxy couldn't take", func(t *testing.T) {
		missed := *running
		missed.Counts = map[string]int{"read": 1, "unread_no_proxy": 3, "unread_not_noted": 2}
		got := print(capturing(nil), &missed)
		if !strings.HasSuffix(got, "   Model flows: 1 read, 0 left unread for other programs, 0 left unread because the program wasn't found in time.\n"+
			"   5 more went on unread because Phase's proxy couldn't take them.\n") {
			t.Fatalf("got:\n%s", got)
		}
	})

	// What status never says: that everything goes through Phase. A connection that
	// was open before phase up keeps the path it had.
	t.Run("nothing it doesn't do", func(t *testing.T) {
		for _, got := range []string{print(capturing(nil), running), print(capturing([]string{"0.0.0.0/7"}), running)} {
			if strings.Contains(got, "Everything goes") || strings.Contains(got, "everything goes") {
				t.Fatalf("got:\n%s", got)
			}
		}
	})

	t.Run("host names that couldn't be sent by name", func(t *testing.T) {
		odd := *running
		odd.SkippedNames = 1
		if got := print(capturing(nil), &odd); !strings.Contains(got, "   Names sent to Phase: api.github.com, phase.invalid\n"+
			"   1 Connection host has a name a DNS entry can't hold, so it isn't captured by name: only by the name in a TLS hello, where its traffic goes through Phase.\n") {
			t.Fatalf("got:\n%s", got)
		}
		odd.SkippedNames = 3
		if got := print(capturing(nil), &odd); !strings.Contains(got, "   3 Connection hosts have names a DNS entry can't hold, so they aren't captured by name: only by the name in a TLS hello, where their traffic goes through Phase.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "DNS entry") {
			t.Fatalf("got:\n%s", got)
		}
	})

	t.Run("what was refused", func(t *testing.T) {
		refused := *running
		refused.Counts = map[string]int{"tcp": 4, "loop_refused": 9, "control_refused": 2}
		got := print(capturing(nil), &refused)
		if !strings.Contains(got, "   Flows: 0 to Connection hosts, 4 passed through unread.\n"+
			"   9 were refused because their route led back into Phase: another VPN's range, while that VPN is down.\n"+
			"   2 requests to phase.invalid were refused because they named another host.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "refused") {
			t.Fatalf("got:\n%s", got)
		}
	})

	// A flow the proxy took and only relayed isn't among the ones that were read.
	t.Run("flows the proxy only relayed", func(t *testing.T) {
		relayed := *running
		relayed.Counts = map[string]int{"read": 4, "unread_by_proxy": 3}
		got := print(capturing(nil), &relayed)
		if !strings.HasSuffix(got, "   Model flows: 4 read, 0 left unread for other programs, 0 left unread because the program wasn't found in time.\n"+
			"   3 more went through Phase's proxy unread: it stops reading a host for a while when the tool keeps refusing Phase's certificate there.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "proxy unread") {
			t.Fatalf("got:\n%s", got)
		}
	})

	// A flow let go before its hello came is a read that may have been missed, and is
	// said apart from the flows that passed through as they should.
	t.Run("flows whose hello never came", func(t *testing.T) {
		late := *running
		late.Counts = map[string]int{"tcp": 9, "unread_no_hello": 2}
		got := print(capturing(nil), &late)
		if !strings.Contains(got, "   Flows: 0 to Connection hosts, 9 passed through unread.\n"+
			"   2 of those went to port 443 and sent no TLS hello in time, so Phase never learned which host they were for.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "TLS hello in time") {
			t.Fatalf("got:\n%s", got)
		}
	})

	t.Run("HTTP/3 that was refused", func(t *testing.T) {
		refused := *running
		refused.Counts = map[string]int{"tcp": 4, "udp": 1, "udp_443_refused": 6}
		got := print(capturing(nil), &refused)
		if !strings.Contains(got, "   Flows: 0 to Connection hosts, 5 passed through unread.\n"+
			"   6 UDP packets to port 443 were refused: that is HTTP/3, whose host Phase can't tell, so the program falls back to TCP.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "HTTP/3") {
			t.Fatalf("got:\n%s", got)
		}
	})

	// The engine asks for names and the helper writes their entries. A name the
	// helper has no entry for isn't said to be captured by name.
	t.Run("names with no DNS entry in place", func(t *testing.T) {
		more := *running
		more.Domains = []string{"api.github.com", "b.example.com", "c.example.com", "phase.invalid"}
		got := print(capturing(nil), &more)
		if !strings.Contains(got, "   Names sent to Phase: api.github.com, b.example.com, c.example.com, phase.invalid\n"+
			"   ⚠️  No DNS entry is in place for b.example.com, c.example.com, so they aren't captured by name: only by the name in a TLS hello, where their traffic goes through Phase.\n") {
			t.Fatalf("got:\n%s", got)
		}
		if got := print(capturing(nil), running); strings.Contains(got, "No DNS entry") {
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

	// A route the helper couldn't remove still leads into the tunnel, and status
	// says so, with what removes it.
	t.Run("routes that couldn't be removed", func(t *testing.T) {
		left := &control.Status{Reason: "the engine stopped", RoutesLeft: []string{"128.0.0.0/1", "8000::/1"}}
		got := print(left, nil)
		want := "🚇 Phase isn't in the path: the engine stopped.\n" +
			"   ⚠️  The helper couldn't remove its routes for 128.0.0.0/1, 8000::/1, so connections there still go into Phase's tunnel and may fail. Run phase down, which removes them.\n" +
			"   Engine: not running.\n"
		if got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})
}

// phase up says what it has done, and no more: new connections go through Phase, and
// the ones that were open stay as they are. It doesn't say that everything does.
func TestUpSaysWhatIsTrue(t *testing.T) {
	helperStatus := control.Status{Protocol: control.ProtocolVersion, Device: "utun7", Attached: true, Capturing: true}
	engineStatus := engine.Status{
		Ready: true, Connections: []string{"GitHub", "Postgres"},
		ReadTools: map[string][]string{"codex": {"api.openai.com"}, "claude": {"api.anthropic.com"}, "cursor": nil},
	}
	print := func(routes []string, engineStatus engine.Status) string {
		var out bytes.Buffer
		status := helperStatus
		status.Routes = routes
		printUpResult(&out, status, engineStatus)
		return out.String()
	}
	next := "\nNext steps\n" +
		"   phase status   see what's going through Phase\n" +
		"   phase down     stop\n"

	everything := print(tunnel.FullRoutes, engineStatus)
	want := "   ✅ New connections on this Mac now go through Phase, by utun7.\n" +
		"   Connections that were already open stay as they are.\n" +
		"   QUIC (HTTP/3) is turned off for this Mac while phase up runs; programs fall back to TCP on their own.\n" +
		"   Connections: GitHub, Postgres\n" +
		"   Model traffic is read for claude, codex, each for its own processes only.\n" +
		"   Your local network and other VPNs, such as Tailscale, keep their own routes.\n" +
		"   If the engine stops, Phase steps aside and your network works as it did before.\n" + next
	if everything != want {
		t.Fatalf("got:\n%s\nwant:\n%s", everything, want)
	}
	if again := print(nil, engineStatus); again != everything {
		t.Fatalf("no routes means everything:\n%s", again)
	}

	part := print([]string{"0.0.0.0/7"}, engine.Status{Ready: true})
	want = "   ✅ New connections to 0.0.0.0/7, and to the names sent to Phase, now go through it, by utun7. Everything else is untouched.\n" +
		"   Connections that were already open stay as they are.\n" +
		"   Your local network and other VPNs, such as Tailscale, keep their own routes.\n" +
		"   If the engine stops, Phase steps aside and your network works as it did before.\n" + next
	if part != want {
		t.Fatalf("got:\n%s\nwant:\n%s", part, want)
	}
	// With part of the network captured UDP is left as it was, and nothing is said of it.
	if strings.Contains(part, "QUIC") {
		t.Fatalf("it says QUIC is off when it isn't:\n%s", part)
	}
	for _, said := range []string{everything, part} {
		if strings.Contains(said, "Everything on this Mac") || strings.Contains(said, "verything goes") || strings.Contains(said, "all traffic") {
			t.Fatalf("it claims what the tunnel doesn't do:\n%s", said)
		}
	}
}
