package engine

import (
	"testing"

	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/owner"
)

// The tunnel asks the proxy what is read, and keeps no table of its own. The tools
// are the ones it can recognise a process as.
func TestProxyReaderAsksTheProxy(t *testing.T) {
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "censor")
	reader := ProxyReader(aiproxy.New())
	for host, read := range map[string]bool{
		"api.anthropic.com": true, "API.Anthropic.com.": true, "chatgpt.com": true, "api.openai.com": true,
		"example.com": false, "anthropic.com": false, "": false,
	} {
		if got := reader.ReadsHost(host); got != read {
			t.Errorf("ReadsHost(%q) = %v", host, got)
		}
	}
	for _, test := range []struct {
		tool, host string
		read       bool
	}{
		{"claude", "api.anthropic.com", true},
		{"codex", "api.anthropic.com", false},
		{"codex", "chatgpt.com", true},
		{"claude", "chatgpt.com", false},
		{"", "api.anthropic.com", false},
		{"browser", "api.anthropic.com", false},
	} {
		if got := reader.ShouldRead(test.tool, test.host); got != test.read {
			t.Errorf("ShouldRead(%q, %q) = %v", test.tool, test.host, got)
		}
	}

	hosts := reader.ToolHosts()
	if !contains(hosts["claude"], "api.anthropic.com") || contains(hosts["codex"], "api.anthropic.com") || !contains(hosts["codex"], "chatgpt.com") {
		t.Fatalf("hosts: %v", hosts)
	}
	// Every tool the tunnel recognises is one the proxy answers for by that name,
	// and a host listed for a tool is a host that is read for it.
	recognised := map[string]bool{}
	for _, tool := range owner.Tools {
		recognised[tool.Name] = true
		for _, host := range hosts[tool.Name] {
			if !reader.ShouldRead(tool.Name, host) || !reader.ReadsHost(host) {
				t.Errorf("%s is listed for %s, and isn't read for it", host, tool.Name)
			}
		}
	}
	for tool := range hosts {
		if !recognised[tool] {
			t.Errorf("hosts are listed for %q, which the tunnel can't recognise a process as", tool)
		}
	}
	for _, tool := range []string{"claude", "codex", "opencode"} {
		if len(hosts[tool]) == 0 {
			t.Errorf("nothing is read for %s: the tunnel and the proxy may know it by different names", tool)
		}
	}
	// The names to capture by DNS when less than everything is routed in.
	if domains := tunnel.ReadDomains(hosts); !contains(domains, "api.anthropic.com") || !contains(domains, "chatgpt.com") {
		t.Fatalf("domains: %v", domains)
	}

	// The proxy is told of a flow by the loopback address its CONNECT comes from.
	closed, err := reader.NoteFlow("127.0.0.1:50200", tunnel.LocalPeer, "claude", nil)
	if err != nil || closed == nil {
		t.Fatalf("a flow wasn't noted: %v", err)
	}
	closed()
	// One it can't keep is an error, and there is still something to call.
	for _, test := range []struct{ from, tool string }{{"192.0.2.1:50200", "claude"}, {"127.0.0.1:50201", "not a tool's id"}} {
		closed, err := reader.NoteFlow(test.from, tunnel.LocalPeer, test.tool, nil)
		if err == nil || closed == nil {
			t.Fatalf("NoteFlow(%q, %q): %v", test.from, test.tool, err)
		}
		closed()
	}
}

func TestProxyReaderReadsNothingWhenLeakProtectionIsOff(t *testing.T) {
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "off")
	reader := ProxyReader(aiproxy.New())
	if reader.ReadsHost("api.anthropic.com") || reader.ShouldRead("claude", "api.anthropic.com") || len(reader.ToolHosts()) != 0 {
		t.Fatal("the tunnel was told to hand flows to a proxy that reads nothing")
	}
}

// With no reader set, the engine's own stand-in reads nothing and still tells the
// proxy about each flow.
func TestWithoutAReaderNothingIsReadAndTheProxyIsStillTold(t *testing.T) {
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "censor")
	reader := tunnel.Reader(proxyReader{proxy: aiproxy.New()})
	if reader.ReadsHost("api.anthropic.com") || reader.ShouldRead("claude", "api.anthropic.com") || len(reader.ToolHosts()) != 0 {
		t.Fatal("something is read with no reader set")
	}
	closed, err := reader.NoteFlow("127.0.0.1:50202", tunnel.LocalPeer, "claude", nil)
	if err != nil || closed == nil {
		t.Fatalf("the proxy wasn't told of the flow: %v", err)
	}
	closed()
}

// The proxy keeps what it remembers under the peer a flow came from. So the tunnel
// and the proxy call this machine by one name, and a peer's id reaches the proxy.
func TestTheProxyIsToldTheFlowsPeer(t *testing.T) {
	if tunnel.LocalPeer != aiproxy.PeerLocal {
		t.Fatalf("the tunnel calls this machine %q and the proxy %q", tunnel.LocalPeer, aiproxy.PeerLocal)
	}
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "censor")
	reader := ProxyReader(aiproxy.New())
	for _, peer := range []string{tunnel.LocalPeer, "sandbox-1"} {
		closed, err := reader.NoteFlow("127.0.0.1:50210", peer, "claude", nil)
		if err != nil || closed == nil {
			t.Fatalf("a flow of %q wasn't noted: %v", peer, err)
		}
		closed()
	}
	// An id the proxy can't keep things under is refused, and the flow isn't read.
	closed, err := reader.NoteFlow("127.0.0.1:50211", "not a peer's id", "claude", nil)
	if err == nil || closed == nil {
		t.Fatalf("a flow was noted for a peer with no usable id: %v", err)
	}
	closed()
}
