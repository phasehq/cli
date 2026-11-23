package aiproxy

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// An S3 call dressed with a selector that names a read is judged by its
// method, so the policy still stops it, and nothing is re-signed or sent.
func TestAWSDecoySelectorIsStoppedByThePolicy(t *testing.T) {
	policy := policyDocument("block", []any{classRule("read", "allow")})
	_, proxy, upstream := policyProxy(t, awsPolicyConnection(policy))
	const bucket = "https://bucket.s3.aws.example.test"

	read := signedAWSRequest(t, http.MethodGet, bucket+"/reports/2026.csv", "s3", "", nil)
	if result := processThrough(proxy, read); result.failure != nil || upstream.calls.Load() != 1 {
		t.Fatalf("an allowed read did not go through: %+v", result.failure)
	}
	for name, request := range map[string]*http.Request{
		"DELETE with a target that names a read":  signedAWSRequest(t, http.MethodDelete, bucket+"/reports/2026.csv", "s3", "", map[string]string{"X-Amz-Target": "x.GetObject"}),
		"DELETE with an action that names a read": signedAWSRequest(t, http.MethodDelete, bucket+"/reports/2026.csv?Action=GetObject", "s3", "", nil),
		"PUT ?policy with a target":               signedAWSRequest(t, http.MethodPut, bucket+"/?policy", "s3", `{"Version":"2012-10-17"}`, map[string]string{"X-Amz-Target": "x.GetBucketPolicy", "Content-Type": "application/json"}),
		"PUT ?policy with an action":              signedAWSRequest(t, http.MethodPut, bucket+"/?policy&Action=GetBucketPolicy", "s3", `{"Version":"2012-10-17"}`, map[string]string{"Content-Type": "application/json"}),
		"POST ?delete with a target":              signedAWSRequest(t, http.MethodPost, bucket+"/?delete", "s3", "<Delete/>", map[string]string{"X-Amz-Target": "x.ListObjects", "Content-Type": "application/xml"}),
		"POST ?delete with an action":             signedAWSRequest(t, http.MethodPost, bucket+"/?delete&Action=ListObjects", "s3", "<Delete/>", map[string]string{"Content-Type": "application/xml"}),
	} {
		result := processThrough(proxy, request)
		if result.failure == nil || result.failure.code != codeAccessPolicyBlocked || result.event.ProxyDecision != "block" {
			t.Errorf("%s was not blocked: %+v", name, result.failure)
		}
		if class := result.failure.details["class"]; class == "read" {
			t.Errorf("%s: stopped as %v", name, class)
		}
	}
	if upstream.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want only the read", upstream.calls.Load())
	}
}

// A POST that asks to be run as a DELETE is judged as a DELETE as well, and
// the request it offers names the method that would run.
func TestMethodOverrideIsAskedAboutAsTheMethodItNames(t *testing.T) {
	policy := policyDocument("allow", []any{classRule("delete", "ask")})
	state, proxy, upstream := policyProxy(t, customPolicyConnection(policy))

	plain, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items/42", nil)
	if result := processThrough(proxy, plain); result.failure != nil || upstream.calls.Load() != 1 {
		t.Fatalf("a plain POST was stopped: %+v", result.failure)
	}
	overridden, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items/42", nil)
	overridden.Header.Set("X-HTTP-Method-Override", "DELETE")
	result := processThrough(proxy, overridden)
	if result.failure == nil || result.failure.code != codeAccessPolicyAsk || upstream.calls.Load() != 1 {
		t.Fatalf("a POST run as DELETE was not asked about: %+v", result.failure)
	}
	if !strings.Contains(result.failure.message, "this POST, which asks to be run as DELETE (a delete call)") {
		t.Fatalf("message = %s", result.failure.message)
	}
	if result.failure.details["class"] != "delete" || result.failure.details["method"] != "POST" {
		t.Fatalf("details = %v", result.failure.details)
	}
	var request struct {
		Title  string `json:"title"`
		Action struct {
			Allow       map[string]any `json:"allow"`
			BlockedCall map[string]any `json:"blockedCall"`
		} `json:"action"`
	}
	if err := json.Unmarshal(result.failure.details["request"].(json.RawMessage), &request); err != nil {
		t.Fatal(err)
	}
	wantAllow := map[string]any{"match": map[string]any{"methods": []any{"DELETE"}, "path": "/v1/items/42"}}
	if !reflect.DeepEqual(request.Action.Allow, wantAllow) || request.Title != "Allow DELETE /v1/items/42 on Example API" ||
		request.Action.BlockedCall["method"] != "DELETE" || request.Action.BlockedCall["class"] != "delete" {
		t.Fatalf("request = %+v", request)
	}

	// Once that allow is in place the same call goes through.
	allowed := customPolicyConnection(policyDocument("allow", []any{classRule("delete", "ask")}, map[string]any{
		"id": "allow-1", "match": map[string]any{"methods": []string{"DELETE"}, "path": "/v1/items/42"},
		"expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}))
	session := decodeTestSession(t, customSessionPayload("", 2, allowed))
	if err := state.replaceConfig(&session.SessionConfig); err != nil {
		t.Fatal(err)
	}
	retried, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items/42", nil)
	retried.Header.Set("X-HTTP-Method-Override", "DELETE")
	if result := processThrough(proxy, retried); result.failure != nil || upstream.calls.Load() != 2 {
		t.Fatalf("the allowed call was stopped again: %+v", result.failure)
	}
}

// A block of a POST that asks to be run as a DELETE names both methods.
func TestBlockedMethodOverrideNamesTheMethodItAsksFor(t *testing.T) {
	_, proxy, upstream := policyProxy(t, customPolicyConnection(policyDocument("allow", []any{classRule("delete", "block")})))
	overridden, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items/42", nil)
	overridden.Header.Set("X-HTTP-Method-Override", "DELETE")
	result := processThrough(proxy, overridden)
	if result.failure == nil || result.failure.code != codeAccessPolicyBlocked || upstream.calls.Load() != 0 ||
		!strings.HasPrefix(result.failure.message, "Phase blocked POST /v1/items/42, which asks to be run as DELETE, on Example API: it is a delete call, and this Connection's Delete row is set to Block.") {
		t.Fatalf("failure = %+v", result.failure)
	}
}

// A WebSocket handshake inside a tunnel is a GET whose traffic the proxy does
// not see afterwards, so a policy that stops updates stops it too.
func TestWebSocketUpgradeIsJudgedAsAnUpdate(t *testing.T) {
	handshake := func(path string) *http.Request {
		request, _ := http.NewRequest(http.MethodGet, "https://api.example.test"+path, nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return request
	}
	policy := policyDocument("allow", []any{classRule("update", "ask")})
	_, proxy, upstream := policyProxy(t, customPolicyConnection(policy))
	tunnel := &tunnelAuthentication{}

	result := proxy.process(handshake("/v1/stream"), tunnel)
	if result.failure == nil || result.failure.code != codeAccessPolicyAsk || result.failure.details["class"] != "update" || upstream.calls.Load() != 0 {
		t.Fatalf("an upgrade was not asked about: %+v", result.failure)
	}
	// An ordinary GET on the same path is a read.
	plain, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/stream", nil)
	if result := proxy.process(plain, tunnel); result.failure != nil {
		t.Fatalf("a plain GET was stopped: %+v", result.failure)
	} else {
		result.response.Body.Close()
	}

}
