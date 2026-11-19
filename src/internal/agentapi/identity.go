package agentapi

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

// Host is the Phase host this client talks to, as it was given.
func (c *Client) Host() string {
	origin := *c.baseURL
	origin.Path, origin.RawQuery, origin.Fragment = "", "", ""
	return origin.String()
}
