package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/tunnel/owner"
)

// Reader says which model hosts are read, and for which AI coding tool. The proxy
// implements it: the proxy does the reading, and the router only decides which flows
// it is handed.
//
// Every program's traffic reaches the router, a browser's included. Each tool has its
// own model hosts, and a host is read only for that tool's own processes. Any other
// program's traffic to the same host passes through untouched.
type Reader interface {
	// ReadsHost reports whether host is read for any tool. It's asked about every TLS
	// flow, so it has to be cheap. A flow it says no to costs nothing more.
	ReadsHost(host string) bool
	// ShouldRead reports whether host is read for tool.
	ShouldRead(tool, host string) bool
	// NoteFlow says who opened a flow, before its CONNECT is sent from connectFrom,
	// the router's own loopback address for it. tool is the tool the flow is read
	// for, or "" when it isn't to be read: a Connection's host goes to the proxy for
	// its credential whoever opened the flow.
	//
	// The router calls it for every CONNECT it sends. One the proxy was told nothing
	// about would be taken for a program that was given the proxy through its
	// environment, where any model host is read. An error means the proxy couldn't
	// keep what it was told. closed is never nil, and is called once the connection
	// from connectFrom is closed, whatever became of it.
	NoteFlow(connectFrom, tool string) (closed func(), err error)
	// ToolHosts lists the hosts read for each tool, for status and for capturing them
	// by name. A host that covers its subdomains is written "*.name".
	ToolHosts() map[string][]string
}

// OwnerFunc finds the program that opened a connection, from the port it left by and
// where it goes. owner.Lookup is the one used outside tests.
type OwnerFunc func(ctx context.Context, localPort int, remote netip.AddrPort) (owner.Process, error)

const (
	// ownerWait is the longest a flow to a model host is held to learn which program
	// opened it. Past that it's left unread: a slow answer must never stall traffic.
	ownerWait = owner.Wait
	// ownerLookups is how many lookups run at once. Each starts a process, and a
	// program opening connections in a burst must not start one for each at once.
	ownerLookups = 8
)

// Read turns on reading model hosts as the reader says. byName also captures those
// hosts by DNS, which is how they reach the router when not everything is routed
// into the tunnel.
func (r *Router) Read(reader Reader, byName bool) {
	r.mu.Lock()
	r.reader, r.readNames = reader, byName
	r.mu.Unlock()
}

// FindOwnersWith replaces how a flow's program is found, and how long a flow waits
// for it; a wait of zero leaves that as it is. Tests use it.
func (r *Router) FindOwnersWith(find OwnerFunc, wait time.Duration) {
	r.mu.Lock()
	r.owner = find
	if wait > 0 {
		r.ownerWait = wait
	}
	r.mu.Unlock()
}

func (r *Router) reading() (Reader, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reader, r.readNames
}

// ReadTools lists the tools whose model hosts are read, with those hosts.
func (r *Router) ReadTools() map[string][]string {
	reader, _ := r.reading()
	if reader == nil {
		return nil
	}
	tools := map[string][]string{}
	for tool, hosts := range reader.ToolHosts() {
		if tool == "" || len(hosts) == 0 {
			continue
		}
		hosts = append([]string(nil), hosts...)
		sort.Strings(hosts)
		tools[tool] = hosts
	}
	return tools
}

// readByName reports whether name is a model host that is captured by DNS.
func (r *Router) readByName(name string) bool {
	reader, byName := r.reading()
	return byName && reader != nil && reader.ReadsHost(name)
}

// handOver decides whether the proxy takes a TLS flow to host, and what the proxy is
// told of it: tool is the tool the flow is read for, or "" when it isn't to be read.
// A Connection's host goes to the proxy whoever opened the flow. A model host goes
// only when the program that opened the flow is the tool that host is read for.
func (r *Router) handOver(flow Flow, host string, connection bool) (toProxy bool, tool string) {
	reader, _ := r.reading()
	// Nearly all traffic stops here, having cost one question about its host.
	if host == "" || reader == nil || !reader.ReadsHost(host) {
		return connection, ""
	}
	tool = r.toolFor(flow, host, reader)
	return connection || tool != "", tool
}

// errNotNoted means the proxy couldn't keep what it was told about a flow, so the
// flow wasn't handed to it.
var errNotNoted = errors.New("the proxy couldn't be told whose flow this is")

// unreadBecause names the count for a model flow that went on unread because the
// proxy didn't take it.
func unreadBecause(err error) string {
	if errors.Is(err, errNotNoted) {
		return "unread_not_noted"
	}
	return "unread_no_proxy"
}

// toolFor names the tool a flow to host is read for. It's "" when the program that
// opened the flow isn't that host's tool, and when the program can't be found in
// time: not knowing means not reading.
func (r *Router) toolFor(flow Flow, host string, reader Reader) string {
	process, err := r.ownerOf(flow)
	if err != nil {
		r.count("owner_lookup_failed")
		return ""
	}
	tool := owner.Identify(process)
	if tool == "" || !reader.ShouldRead(tool, host) {
		r.count("unread_not_tool")
		return ""
	}
	return tool
}

// ownerOf finds the program that opened a flow, by the port the flow left from. A
// flow reaches the tunnel with the program's own port, so the port names its socket.
// It never takes longer than the router's wait, whatever the lookup does.
//
// It only means something for a program on this machine. A remote peer's flows will
// need the peer to say who opened them.
func (r *Router) ownerOf(flow Flow) (owner.Process, error) {
	r.mu.RLock()
	find, wait := r.owner, r.ownerWait
	r.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	select {
	case r.lookups <- struct{}{}:
	case <-ctx.Done():
		return owner.Process{}, ctx.Err()
	}
	type answer struct {
		process owner.Process
		err     error
	}
	found := make(chan answer, 1)
	go func() {
		defer func() { <-r.lookups }()
		process, err := find(ctx, int(flow.Source.Port()), flow.Dest)
		found <- answer{process, err}
	}()
	select {
	case result := <-found:
		return result.process, result.err
	case <-ctx.Done():
		return owner.Process{}, ctx.Err()
	}
}

// ReadDomains are the names to capture by DNS for the hosts a reader lists. An entry
// covers a name's subdomains, so "*.name" and "name" are one entry.
func ReadDomains(hosts map[string][]string) []string {
	seen := map[string]bool{}
	for _, names := range hosts {
		for _, name := range names {
			name = strings.Trim(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*."), ".")
			if CapturableDomain(name) {
				seen[name] = true
			}
		}
	}
	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

// CapturableDomain is the rule for a name the helper will write a DNS entry for: the
// helper applies it, and the engine leaves out any name that breaks it, because the
// helper refuses a whole attach over one that does.
func CapturableDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return false
	}
	for _, r := range domain {
		if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
