//go:build !darwin

package tunnel

import (
	"os"
	"regexp"
)

var nameserverLine = regexp.MustCompile(`(?m)^nameserver\s+(\S+)`)

// upstreamResolvers reads the system's DNS servers. None is kept for one domain here.
func upstreamResolvers() (servers []string, scoped map[string][]string) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, nil
	}
	for _, match := range nameserverLine.FindAllStringSubmatch(string(content), -1) {
		if match[1] != DNSAddress.String() {
			servers = append(servers, match[1])
		}
	}
	return servers, nil
}
