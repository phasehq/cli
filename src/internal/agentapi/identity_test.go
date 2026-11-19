package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func identityToken(prefix string) string {
	return prefix + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

// The Console says who a token is on one route per kind of token, and the
// client reads the organisation and the Agent's or account's id, nothing else.
func TestTokenIdentityIsTheConsolesAnswerForTheTokensKind(t *testing.T) {
	var paths, authorizations []string
	account := `{"user_id":"user-1","account_id":"service-account-1","organisation":{"id":"org-1","name":"an organisation"},"wrapped_key_share":"a-key-share","apps":[{"id":"an-app"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths, authorizations = append(paths, r.Method+" "+r.URL.Path), append(authorizations, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/service/secrets/tokens/":
			_, _ = w.Write([]byte(account))
		case "/service/public/v1/agents/identity/":
			_, _ = w.Write([]byte(`{"schemaVersion":1,"principalType":"agent","agent":{"id":"agent-1","name":"an Agent"},"workflow":{"id":"w-1","name":"a Workflow"},"organization":{"id":"org-1","name":"an organisation"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	for name, c := range map[string]struct {
		token, path, authorization string
		want                       TokenIdentity
	}{
		"a user's":            {identityToken("pss_user:v1:"), "GET /service/secrets/tokens/", "Bearer User ", TokenIdentity{"org-1", IdentityUser, "user-1"}},
		"a service account's": {identityToken("pss_service:v2:"), "GET /service/secrets/tokens/", "Bearer ServiceAccount ", TokenIdentity{"org-1", IdentityServiceAccount, "service-account-1"}},
		"an Agent's":          {identityToken("pss_agent:v1:"), "GET /service/public/v1/agents/identity/", "Bearer Agent ", TokenIdentity{"org-1", IdentityAgent, "agent-1"}},
	} {
		// However the host was given, the routes are the same host's.
		for _, host := range []string{server.URL, server.URL + "/", server.URL + "/service/public", server.URL + "/service/public/v1/agents"} {
			paths, authorizations = nil, nil
			client, err := NewClient(host, c.token, server.Client())
			if err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			got, err := client.TokenIdentity(context.Background())
			if err != nil || *got != c.want {
				t.Fatalf("%s at %s: %+v %v", name, host, got, err)
			}
			if len(paths) != 1 || paths[0] != c.path || !strings.HasPrefix(authorizations[0], c.authorization) {
				t.Fatalf("%s at %s asked %v", name, host, paths)
			}
			if client.Host() != server.URL {
				t.Fatalf("%s at %s: the client's host is %q", name, host, client.Host())
			}
		}
	}
	// An answer that names no organisation or no account of the token's kind
	// is no identity: nothing is filled in from the other fields.
	for name, answer := range map[string]string{
		"no organisation":            `{"user_id":"user-1"}`,
		"an empty organisation":      `{"user_id":"user-1","organisation":{"id":""}}`,
		"another kind's id":          `{"account_id":"service-account-1","organisation":{"id":"org-1"}}`,
		"an empty answer":            `{}`,
		"an answer that is not JSON": `<html>`,
	} {
		account = answer
		client, err := NewClient(server.URL, identityToken("pss_user:v1:"), server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := client.TokenIdentity(context.Background()); err == nil {
			t.Fatalf("%s gave an identity: %+v", name, got)
		}
	}
	legacy, err := NewClient(server.URL, identityToken("pss_service:v1:"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	paths = nil
	if got, err := legacy.TokenIdentity(context.Background()); err == nil || len(paths) != 0 {
		t.Fatalf("a legacy service token gave an identity: %+v, after asking %v", got, paths)
	}
}
