//go:build darwin

package tunnel

import (
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

var nameserverLine = regexp.MustCompile(`nameserver\[\d+\] : (\S+)`)

// upstreamNameservers lists the servers an ordinary lookup would use. Scoped resolvers,
// including the tunnel's own entries, are skipped.
func upstreamNameservers() []string {
	output, err := exec.Command("/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	for _, block := range strings.Split(string(output), "resolver #") {
		if strings.Contains(block, "domain   :") {
			continue
		}
		for _, match := range nameserverLine.FindAllStringSubmatch(block, -1) {
			addr, err := netip.ParseAddr(match[1])
			if err == nil && addr.Is4() && !seen[match[1]] {
				seen[match[1]] = true
				servers = append(servers, match[1])
			}
		}
	}
	return servers
}
