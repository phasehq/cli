package proxy

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

func MatchHostRule(rule agentapi.HostRule, hostname string, port int, requestPath string) bool {
	hostname = normalizeHostname(hostname)
	value := normalizeHostname(rule.Value)
	if hostname == "" || value == "" || port < 1 || port > 65535 {
		return false
	}
	matched := false
	switch rule.Match {
	case "exact":
		matched = hostname == value
	case "suffix":
		value = strings.TrimPrefix(value, ".")
		matched = hostname == value || strings.HasSuffix(hostname, "."+value)
	default:
		return false
	}
	if !matched || (rule.Port != 0 && rule.Port != port) {
		return false
	}
	if rule.Path != "" {
		canonical, err := canonicalHTTPPath(requestPath)
		if err != nil || !globMatch(rule.Path, canonical) {
			return false
		}
	}
	return true
}

func MatchHostOnly(rule agentapi.HostRule, hostname string, port int) bool {
	copy := rule
	copy.Path = ""
	return MatchHostRule(copy, hostname, port, "/")
}

func ParseAuthority(authority string, defaultPort int) (string, int, error) {
	if strings.ContainsAny(authority, "\r\n\x00") || strings.Contains(authority, "@") {
		return "", 0, errors.New("invalid authority")
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return "", 0, errors.New("invalid authority")
	}
	host := normalizeHostname(parsed.Hostname())
	port := defaultPort
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("invalid authority port")
		}
	}
	if net.ParseIP(host) == nil && !validDNSHostname(host) {
		return "", 0, errors.New("invalid authority host")
	}
	return host, port, nil
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func validDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
