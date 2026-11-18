package ai

import (
	"embed"
	"strings"
)

// The skill stays short because a harness loads it whole; the detail lives in
// these guides, which `phase ai guide <topic>` prints on demand.
//
//go:embed guides/*.md
var guideFiles embed.FS

// GuideTopic is one topic `phase ai guide` can print.
type GuideTopic struct {
	Name    string
	Summary string
}

var guideTopics = []GuideTopic{
	{"connections", "Discovering services, requesting a Connection or a credential update, phase ai exec, what an approval does to the session"},
	{"custom-http", "Connections to any HTTP service: definitions, presets, hosts without a Connection"},
	{"access-rules", "Allowed, ask and blocked calls, the secret guard, time-limited access and renewal"},
	{"app-secrets", "Requesting app access, the secrets commands, refusals, secret placeholders"},
	{"workflow-context", "The Workflow notes members keep, and asking to change them"},
	{"troubleshooting", "Recognising Phase failures, event IDs, provider limits, choosing one Connection, leak protection"},
}

// GuideTopics lists the topics in the order the skill names them.
func GuideTopics() []GuideTopic {
	return append([]GuideTopic(nil), guideTopics...)
}

// Guide returns the text of one topic.
func Guide(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, topic := range guideTopics {
		if topic.Name == name {
			payload, err := guideFiles.ReadFile("guides/" + name + ".md")
			return string(payload), err == nil
		}
	}
	return "", false
}
