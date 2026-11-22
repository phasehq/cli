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

// A client's host is where its Console is served, path and all, however much
// of the API's own path the host was given with: its requests go under it.
func TestClientHostIsWhereItsConsoleIsServed(t *testing.T) {
	var asked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-1","sessionCredential":"a-session-capability","expiresAt":"` +
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","configGeneration":1,"configEnv":{},"connections":[]}`))
	}))
	defer server.Close()
	for given, served := range map[string]string{
		"": "", "/": "", "/service/public": "", "/service/public/": "", "/service/public/v1/agents": "", "/service/public/v1/agents/": "",
		"/phase": "/phase", "/phase/": "/phase", "/phase/service/public": "/phase", "/phase/service/public/v1/agents/": "/phase",
		"/one/two": "/one/two", "/two": "/two", "/a%20b/service/public": "/a%20b",
	} {
		client, err := NewClient(server.URL+given, identityToken("pss_agent:v1:"), server.Client())
		if err != nil {
			t.Fatalf("%q: %v", given, err)
		}
		if client.Host() != server.URL+served {
			t.Errorf("given %q, the client's host is %q, want %q", given, client.Host(), server.URL+served)
		}
		if _, err := client.OpenSession(context.Background(), OpenSessionRequest{}); err != nil {
			t.Fatalf("%q: %v", given, err)
		}
		if want := strings.ReplaceAll(served, "%20", " ") + "/service/public/v1/agents/sessions/"; asked != want {
			t.Errorf("given %q, the client asked %q: its host %q is not where it asks", given, asked, client.Host())
		}
	}
	for path, served := range map[string]string{"/phase/": "/phase", "/phase/service/public": "/phase", "/service/public/v1/agents": "", "/service/publicity": "/service/publicity", "/v1/agents": "/v1/agents"} {
		if got := DeploymentPath(path); got != served {
			t.Errorf("DeploymentPath(%q) = %q, want %q", path, got, served)
		}
	}
}
