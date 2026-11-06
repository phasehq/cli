//go:build !darwin

package tunnel

import (
	"os"
	"regexp"
)

var nameserverLine = regexp.MustCompile(`(?m)^nameserver\s+(\S+)`)

func upstreamNameservers() []string {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, match := range nameserverLine.FindAllStringSubmatch(string(content), -1) {
		servers = append(servers, match[1])
	}
	return servers
}
