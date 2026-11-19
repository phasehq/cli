package aiproxy

import (
	"sort"
	"strings"
)

// Leak protection reads only the model traffic of known harnesses. The table
// is per harness so a later stage can lock each entry to that harness's
// processes, and so the Console can serve it instead of the binary.

const (
	leakTreatmentInspect = "inspect"
	leakTreatmentUnread  = "unread"
)

// leakHostRule is one host (or a domain and its subdomains) of a harness.
type leakHostRule struct {
	Host       string `json:"host"`
	Subdomains bool   `json:"subdomains,omitempty"`
	// PathPrefix limits inspection to requests under it; other requests on the
	// host are forwarded unread through the same tunnel.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// ConversationPaths are the path prefixes that carry conversation content.
	// Every pattern rule applies there; on any other path of the host only
	// indexed values and Phase's own token formats are looked for.
	ConversationPaths []string `json:"conversationPaths,omitempty"`
	Treatment         string   `json:"treatment"`
	// MirrorHello marks an inspected host whose service accepts only its own
	// client's TLS. Requests to it are re-sent over connections that open with
	// a copy of the ClientHello the client sent, never with Go's own; a
	// connection whose hello cannot be copied is passed through unread.
	MirrorHello bool `json:"mirrorHello,omitempty"`
	// Reason says why an unread host is not inspected.
	Reason string `json:"reason,omitempty"`
}

type leakHarness struct {
	Harness string         `json:"harness"`
	Hosts   []leakHostRule `json:"hosts"`
}

type leakHostTable []leakHarness

var defaultLeakHosts = leakHostTable{
	{Harness: "claude", Hosts: []leakHostRule{
		{Host: "api.anthropic.com", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/v1/messages"}},
	}},
	{Harness: "codex", Hosts: []leakHostRule{
		{Host: "chatgpt.com", PathPrefix: "/backend-api/", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/backend-api/codex/responses"}},
		{Host: "api.openai.com", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/v1/responses", "/v1/chat/completions", "/v1/completions"}},
	}},
	{Harness: "opencode", Hosts: []leakHostRule{
		{Host: "openrouter.ai", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/api/v1/chat/completions", "/api/v1/responses", "/api/v1/completions"}},
		{Host: "opencode.ai", Treatment: leakTreatmentInspect, MirrorHello: true, ConversationPaths: []string{"/inference/", "/zen/"}},
	}},
	{Harness: "cursor", Hosts: []leakHostRule{
		{Host: "cursor.sh", Subdomains: true, Treatment: leakTreatmentUnread, Reason: "binary streams; the client refuses inspection"},
	}},
}

// leakHostMatch is what the table says about one host.
type leakHostMatch struct {
	harness string
	rule    leakHostRule
}

func (m *leakHostMatch) inspected() bool {
	return m != nil && m.rule.Treatment == leakTreatmentInspect
}

// inspectsPath reports whether a request to this host with this path is read.
func (m *leakHostMatch) inspectsPath(path string) bool {
	return m.inspected() && (m.rule.PathPrefix == "" || strings.HasPrefix(path, m.rule.PathPrefix))
}

// conversation reports whether a path carries conversation content.
func (m *leakHostMatch) conversation(path string) bool {
	if m == nil {
		return false
	}
	for _, prefix := range m.rule.ConversationPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// lookup finds a host. An exact entry wins over a domain entry; names compare
// without case and without a trailing dot.
func (t leakHostTable) lookup(host string) *leakHostMatch {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return nil
	}
	var domain *leakHostMatch
	for _, harness := range t {
		for _, rule := range harness.Hosts {
			if host == rule.Host {
				return &leakHostMatch{harness: harness.Harness, rule: rule}
			}
			if rule.Subdomains && domain == nil && strings.HasSuffix(host, "."+rule.Host) {
				domain = &leakHostMatch{harness: harness.Harness, rule: rule}
			}
		}
	}
	return domain
}

// hostNames lists the table's hosts by treatment, a domain written as *.name.
func (t leakHostTable) hostNames(treatment string) []string {
	var names []string
	for _, harness := range t {
		for _, rule := range harness.Hosts {
			if rule.Treatment != treatment {
				continue
			}
			name := rule.Host
			if rule.Subdomains {
				names = append(names, name, "*."+name)
				continue
			}
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
