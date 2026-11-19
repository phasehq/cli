package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func identityToken(prefix string) string {
	return prefix + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

// The session the Console opens says whose it is, and so does its config.
// The client asks no other route for it, and an older Console's says nothing.
func TestSessionPayloadNamesItsOrganisationAndPrincipal(t *testing.T) {
	var paths []string
	identity := `,"organisation":{"id":"org-1"},"principal":{"type":"user","id":"member-1"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		body := `{"schemaVersion":1,"sessionUid":"session-1","expiresAt":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","configGeneration":1,"configEnv":{},"connections":[]` + identity
		if r.Method == http.MethodPost {
			body += `,"sessionCredential":"a-session-capability"`
		}
		_, _ = w.Write([]byte(body + "}"))
	}))
	defer server.Close()
	for _, named := range []bool{true, false} {
		if !named {
			identity = ""
		}
		paths = nil
		// However the host was given, the client's host is the same one.
		client, err := NewClient(server.URL+"/service/public", identityToken("pss_user:v1:"), server.Client())
		if err != nil || client.Host() != server.URL {
			t.Fatalf("the client's host is %q: %v", client.Host(), err)
		}
		opened, err := client.OpenSession(context.Background(), OpenSessionRequest{WorkflowID: "workflow-1"})
		if err != nil {
			t.Fatal(err)
		}
		config, err := client.RefreshSession(context.Background(), opened.SessionUID, opened.SessionCredential)
		if err != nil {
			t.Fatal(err)
		}
		for where, session := range map[string]SessionConfig{"open": opened.SessionConfig, "config": *config} {
			if !named {
				if session.Organisation != nil || session.Principal != nil {
					t.Fatalf("%s: an older Console's session was given an identity", where)
				}
				continue
			}
			if session.Organisation == nil || session.Organisation.ID != "org-1" || session.Principal == nil || *session.Principal != (SessionPrincipal{Type: IdentityUser, ID: "member-1"}) {
				t.Fatalf("%s: %+v %+v", where, session.Organisation, session.Principal)
			}
		}
		if len(paths) != 2 || paths[0] != "POST /service/public/v1/agents/sessions/" || paths[1] != "GET /service/public/v1/agents/sessions/session-1/config/" {
			t.Fatalf("the client asked %v", paths)
		}
	}
	// The kinds are a session's principal types, by the token's own kind.
	for prefix, kind := range map[string]string{"pss_user:v1:": "user", "pss_agent:v1:": "agent", "pss_service:v2:": "service_account", "pss_service:v1:": ""} {
		client, err := NewClient(server.URL, identityToken(prefix), server.Client())
		if err != nil || client.TokenType().IdentityKind() != kind {
			t.Fatalf("a %s token is a %q: %v", prefix, client.TokenType().IdentityKind(), err)
		}
	}
}
