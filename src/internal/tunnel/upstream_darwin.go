//go:build darwin

package tunnel

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	nameserverLine = regexp.MustCompile(`nameserver\[\d+\] : (\S+)`)
	// A resolver for one domain says so on a line of its own. The search domains of
	// an ordinary resolver are written "search domain[0]", and don't match.
	domainLine = regexp.MustCompile(`(?m)^\s*domain\s+: (\S+)`)
	portLine   = regexp.MustCompile(`(?m)^\s*port\s+: (\d+)`)
)

// upstreamResolvers reads the system's DNS servers: the ones an ordinary lookup would
// use, and the ones it keeps for one domain each.
func upstreamResolvers() (servers []string, scoped map[string][]string) {
	// Lookups wait on this, so it is never waited on for long.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil, nil
	}
	return parseResolvers(string(output))
}

// parseResolvers reads what scutil --dns prints. servers are those of the resolvers
// with no domain, in the order printed, which is the order the system asks them in.
// scoped are those of the resolvers for one domain, by that domain. The tunnel's own
// entries are resolvers for one domain too, and are left out: asking them would be
// the engine asking itself.
func parseResolvers(listing string) (servers []string, scoped map[string][]string) {
	scoped = map[string][]string{}
	seen := map[string]bool{}
	for _, block := range strings.Split(listing, "resolver #") {
		port := "53"
		if match := portLine.FindStringSubmatch(block); match != nil {
			port = match[1]
		}
		var found []string
		own := false
		for _, match := range nameserverLine.FindAllStringSubmatch(block, -1) {
			addr, err := netip.ParseAddr(match[1])
			if err != nil || !addr.Is4() {
				continue
			}
			own = own || addr == DNSAddress
			server := addr.String()
			if port != "53" {
				server = net.JoinHostPort(server, port)
			}
			found = append(found, server)
		}
		if own || len(found) == 0 {
			continue
		}
		if match := domainLine.FindStringSubmatch(block); match != nil {
			// The system prints a domain's resolver once for each way of reaching it.
			// The first is the one it prefers.
			if domain := strings.Trim(strings.ToLower(match[1]), "."); domain != "" && scoped[domain] == nil {
				scoped[domain] = found
			}
			continue
		}
		for _, server := range found {
			if !seen[server] {
				seen[server] = true
				servers = append(servers, server)
			}
		}
	}
	return servers, scoped
}
