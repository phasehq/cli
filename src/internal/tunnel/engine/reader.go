package engine

import (
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/owner"
)

// ProxyReader gives the tunnel the proxy's own say on model traffic: the hosts leak
// protection reads, each for the processes of the tool it is listed under. It is what
// `phase up` sets as Config.Reader.
//
// The tools are the ones the tunnel can recognise a process as. A tool the proxy
// lists and the tunnel can't recognise is never read behind the tunnel, since no flow
// could be said to be its own.
func ProxyReader(proxy *aiproxy.Engine) tunnel.Reader {
	return proxyReader{proxy: proxy, reads: true}
}

// proxyReader asks the proxy what is read, and tells it whose flow each CONNECT
// carries. With reads off it reads nothing and still tells the proxy: that is what
// keeps the proxy from taking the tunnel's flows for its own clients'.
type proxyReader struct {
	proxy *aiproxy.Engine
	reads bool
}

func (p proxyReader) ReadsHost(host string) bool {
	if !p.reads {
		return false
	}
	for _, tool := range owner.Tools {
		if p.proxy.ShouldRead(tool.Name, host) {
			return true
		}
	}
	return false
}

func (p proxyReader) ShouldRead(tool, host string) bool {
	return p.reads && p.proxy.ShouldRead(tool, host)
}

func (p proxyReader) ToolHosts() map[string][]string {
	hosts := map[string][]string{}
	if !p.reads {
		return hosts
	}
	for _, tool := range owner.Tools {
		for _, host := range p.proxy.ReadHosts(tool.Name) {
			hosts[tool.Name] = append(hosts[tool.Name], host.Host)
			if host.Subdomains {
				hosts[tool.Name] = append(hosts[tool.Name], "*."+host.Host)
			}
		}
	}
	return hosts
}

// NoteFlow tells the proxy that the connection from connectFrom is the tunnel's, and
// which peer's and tool's flow it carries. The first holds while the connection is
// open and can't fail, so even a flow whose note the proxy couldn't keep is never
// read as a client of the proxy environment. What it returns ends both: the proxy
// forgets the connection, and with it what was said of a flow whose CONNECT never came.
func (p proxyReader) NoteFlow(connectFrom, peer, tool string) (func(), error) {
	closed := p.proxy.TunnelConnection(connectFrom)
	if !p.reads {
		tool = ""
	}
	return closed, p.proxy.NoteFlow(connectFrom, aiproxy.FlowContext{Capture: aiproxy.CaptureTunnel, Tool: tool, Peer: peer})
}
