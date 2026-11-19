package agentapi

import "strings"

// The kinds of login the Console tells apart, named as a session's principal
// type names them: a session and a command then say the same of one login.
const (
	IdentityUser           = "user"
	IdentityServiceAccount = "service_account"
	IdentityAgent          = "agent"
)

// IdentityKind is the kind of login a token of this type is, or "" for a
// type that has none.
func (t TokenType) IdentityKind() string {
	switch t {
	case TokenAgent:
		return IdentityAgent
	case TokenUser:
		return IdentityUser
	case TokenServiceAccount:
		return IdentityServiceAccount
	}
	return ""
}

// publicAPIPaths are the paths of the public API a host may be given with,
// longest first: what stands before one is where the Console is served.
var publicAPIPaths = []string{"/service/public/v1/agents", "/service/public"}

// DeploymentPath is the path a Console is served under, of the path of a host
// as NewClient reads it: "" at an origin's root, "/phase" for a Console at
// https://example.com/phase however much of its API's path was written after.
func DeploymentPath(hostPath string) string {
	hostPath = strings.TrimSuffix(hostPath, "/")
	for _, api := range publicAPIPaths {
		if strings.HasSuffix(hostPath, api) {
			return strings.TrimSuffix(hostPath, api)
		}
	}
	return hostPath
}

// Host is the Console this client talks to: its scheme, host and port, and
// the path it is served under. Two Consoles of one origin differ by that path.
func (c *Client) Host() string {
	console := *c.baseURL
	console.Path, console.RawPath, console.RawQuery, console.Fragment = c.deployment, "", "", ""
	return console.String()
}
