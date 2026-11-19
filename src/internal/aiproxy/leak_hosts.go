package aiproxy

import (
	"slices"
	"sort"
	"strings"
)

// Leak protection reads only the model traffic of known AI tools. The table
// has one list per tool, holding every model host that tool talks to. Behind
// the environment proxy every program runs in an AI tool's process tree, so
// any listed host is read there. A tunnel sees every program on the machine,
// so there a host is read for a tool's own processes only, and another
// program's traffic to the same host is left alone. The shape lets the
// Console serve the table instead of the binary.

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
	// Harness is the tool's id: what a flow's Tool holds, and what an event
	// names as the harness.
	Harness string `json:"harness"`
	// Labels are the other names the tool goes by where a session is started,
	// such as the harness label phase ai run resolves.
	Labels []string       `json:"labels,omitempty"`
	Hosts  []leakHostRule `json:"hosts"`
}

type leakHostTable []leakHarness

// A provider's API is the same host with the same paths whichever tool calls
// it, so its rule is written once and listed under each tool that uses it.
var (
	anthropicAPIHost = leakHostRule{Host: "api.anthropic.com", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/v1/messages"}}
	openAIAPIHost    = leakHostRule{Host: "api.openai.com", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/v1/responses", "/v1/chat/completions", "/v1/completions"}}
)

// The order of the tools matters only where the tool is not known: a host is
// then read as its first entry says.
var defaultLeakHosts = leakHostTable{
	{Harness: "claude", Labels: []string{"claude-code"}, Hosts: []leakHostRule{
		anthropicAPIHost,
	}},
	{Harness: "codex", Hosts: []leakHostRule{
		{Host: "chatgpt.com", PathPrefix: "/backend-api/", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/backend-api/codex/responses"}},
		openAIAPIHost,
	}},
	{Harness: "opencode", Hosts: []leakHostRule{
		{Host: "openrouter.ai", Treatment: leakTreatmentInspect, ConversationPaths: []string{"/api/v1/chat/completions", "/api/v1/responses", "/api/v1/completions"}},
		{Host: "opencode.ai", Treatment: leakTreatmentInspect, MirrorHello: true, ConversationPaths: []string{"/inference/", "/zen/"}},
		// OpenCode also calls the providers' own APIs.
		anthropicAPIHost,
		openAIAPIHost,
	}},
	{Harness: "cursor", Labels: []string{"cursor-agent"}, Hosts: []leakHostRule{
		{Host: "cursor.sh", Subdomains: true, Treatment: leakTreatmentUnread, Reason: "binary streams; the client refuses inspection"},
	}},
}

// leakStateKey is what leak protection remembers things under: a tool and a
// host. The tool is the one the flow is named as (a match's harness), so
// what one tool does on a host says nothing about another tool there.
type leakStateKey struct {
	tool, host string
}

// leakHostMatch is what the table says about one host for one flow.
type leakHostMatch struct {
	// harness is the tool the flow is named as in events: the flow's own tool
	// when that tool's list holds the host, otherwise the tool the host is
	// first listed under.
	harness string
	rule    leakHostRule
	flow    FlowContext
	key     leakStateKey
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

// leakHostName is a host name as the table compares it: without case and
// without a trailing dot.
func leakHostName(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// lookup finds a host whatever tool it is listed under, as the first entry
// that names it says: what the proxy does for a client it cannot attribute. An
// exact entry wins over a domain entry.
func (t leakHostTable) lookup(host string) *leakHostMatch {
	return t.find("", host)
}

// lookupTool finds a host among one tool's entries only.
func (t leakHostTable) lookupTool(tool, host string) *leakHostMatch {
	if tool == "" {
		return nil
	}
	return t.find(tool, host)
}

func (t leakHostTable) find(tool, host string) *leakHostMatch {
	host = leakHostName(host)
	if host == "" {
		return nil
	}
	var domain *leakHostMatch
	for _, harness := range t {
		if tool != "" && harness.Harness != tool {
			continue
		}
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

// lookupFlow finds a host for a flow:
//   - a client that was given the proxy through its environment: any listed
//     host, whichever tool the proxy serves. A tool started inside another
//     tool's session (Codex run from a Claude Code shell) sends conversation
//     content through the same proxy and is read like its host. The tool only
//     names the flow better: its own entry is used when its list holds the
//     host, otherwise the first entry that names the host;
//   - a tunnel's flow from a known tool: only that tool's entries;
//   - a tunnel's flow from a program that is not a listed tool: nothing.
func (t leakHostTable) lookupFlow(flow FlowContext, host string) *leakHostMatch {
	match := t.lookupTool(flow.Tool, host)
	if match == nil && flow.capture() != CaptureTunnel {
		match = t.lookup(host)
	}
	if match != nil {
		match.flow = FlowContext{Capture: flow.capture(), Tool: flow.Tool}
		match.key = leakStateKey{tool: match.harness, host: leakHostName(host)}
	}
	return match
}

// rulesOf returns one tool's entries.
func (t leakHostTable) rulesOf(tool string) []leakHostRule {
	for _, harness := range t {
		if harness.Harness == tool {
			return harness.Hosts
		}
	}
	return nil
}

// toolFor returns the tool a harness label names, or "" for a label that
// names none of the listed tools.
func (t leakHostTable) toolFor(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return ""
	}
	for _, harness := range t {
		if harness.Harness == label || slices.Contains(harness.Labels, label) {
			return harness.Harness
		}
	}
	return ""
}

// hostNames lists the table's hosts by treatment, a domain written as *.name.
// A host listed under several tools is named once.
func (t leakHostTable) hostNames(treatment string) []string {
	var names []string
	for _, harness := range t {
		for _, rule := range harness.Hosts {
			if rule.Treatment != treatment {
				continue
			}
			names = append(names, rule.Host)
			if rule.Subdomains {
				names = append(names, "*."+rule.Host)
			}
		}
	}
	sort.Strings(names)
	return slices.Compact(names)
}
