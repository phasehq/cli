package agentapi

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"
)

// The kinds of login the Console tells apart, as an identity names them.
const (
	IdentityUser           = "user"
	IdentityServiceAccount = "service-account"
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

// TokenIdentity is who the Console says a token is: its organisation, and
// the Agent or account it belongs to. Nothing here is read from the token.
type TokenIdentity struct {
	OrganizationID string
	// Kind is the token's IdentityKind, and ID that Agent's or account's id.
	Kind, ID string
}

// Host is the Phase host this client talks to, as it was given.
func (c *Client) Host() string {
	origin := *c.baseURL
	origin.Path, origin.RawQuery, origin.Fragment = "", "", ""
	return origin.String()
}

// TokenIdentity asks the Console who this client's token is: the Agent
// identity route, or the route a user's or service account's login is saved from.
func (c *Client) TokenIdentity(ctx context.Context) (*TokenIdentity, error) {
	kind := c.tokenType.IdentityKind()
	switch c.tokenType {
	case TokenAgent:
		identity, err := c.Identity(ctx)
		if err != nil {
			return nil, err
		}
		return &TokenIdentity{OrganizationID: identity.Organization.ID, Kind: kind, ID: identity.Agent.ID}, nil
	case TokenUser, TokenServiceAccount:
		var account struct {
			UserID       string `json:"user_id"`
			AccountID    string `json:"account_id"`
			Organisation *struct {
				ID string `json:"id"`
			} `json:"organisation"`
		}
		if err := c.do(ctx, http.MethodGet, c.accountEndpoint(), nil, &account, ""); err != nil {
			return nil, err
		}
		id := account.UserID
		if c.tokenType == TokenServiceAccount {
			id = account.AccountID
		}
		if account.Organisation == nil || account.Organisation.ID == "" || id == "" {
			return nil, errors.New("the Console's answer names no organisation or account for this token")
		}
		return &TokenIdentity{OrganizationID: account.Organisation.ID, Kind: kind, ID: id}, nil
	}
	return nil, errors.New("this kind of token has no identity the Console names")
}

// accountEndpoint is the route a User or Service Account login is saved
// from: a sibling of the public API under the same host.
func (c *Client) accountEndpoint() string {
	u := *c.baseURL
	u.Path = path.Join(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/public/v1/agents"), "secrets", "tokens") + "/"
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}
