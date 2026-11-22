package aiproxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// echoingUpstream answers with a redirect that keeps the query, and echoes the
// request's credential headers back in a header and in the body.
type echoingUpstream struct{}

func (echoingUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	header := make(http.Header)
	header.Set("Location", req.URL.Path+"/?"+req.URL.RawQuery)
	header.Set("X-Echo-Authorization", req.Header.Get("Authorization"))
	header.Set("Content-Type", "application/json")
	body := `{"query":"` + req.URL.RawQuery + `","authorization":"` + req.Header.Get("Authorization") +
		`","raw":"` + req.Header.Get("X-Raw-Echo") + `"}`
	// A query-key request gets a body of unknown length, read as it streams;
	// the others one of known length, read whole.
	length := int64(len(body))
	if req.URL.RawQuery != "" {
		length = -1
	}
	return &http.Response{StatusCode: http.StatusMovedPermanently, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: length, Request: req}, nil
}

func TestInjectedLiveValuesNeverComeBackInTheResponse(t *testing.T) {
	const livePassword = "live-password-0123456789"
	const decoyPassword = "password-decoy-0123456789"
	queryInjection := map[string]any{"action": "set_param", "name": "api_key", "valueFormat": "{value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}
	basicInjection := map[string]any{"action": "basic_auth", "name": "Authorization",
		"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"}
	for name, injections := range map[string][]any{
		"query":  {queryInjection},
		"header": {bearerAttachInjection()},
		"basic":  {basicInjection},
	} {
		t.Run(name, func(t *testing.T) {
			connection := customConnectionPayload(customDecoyToken, customLiveToken)
			connection["injections"] = injections
			connection["decoyMaterial"] = map[string]string{"token": customDecoyToken, "password": decoyPassword}
			connection["secretMaterial"] = map[string]string{"token": customLiveToken, "password": livePassword}
			_, proxy, _ := policyProxy(t, connection)
			proxy.transport = echoingUpstream{}
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
			result := proxy.process(req, nil)
			if result.failure != nil {
				t.Fatalf("failure: %+v", result.failure)
			}
			body, err := io.ReadAll(result.response.Body)
			result.response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			returned := string(body)
			for key, values := range result.response.Header {
				returned += "\n" + key + ": " + strings.Join(values, ",")
			}
			basicLive := base64.StdEncoding.EncodeToString([]byte("alice:" + livePassword))
			for _, live := range []string{customLiveToken, url.QueryEscape(customLiveToken), livePassword, basicLive} {
				if strings.Contains(returned, live) {
					t.Fatalf("a live value came back to the Agent:\n%s", returned)
				}
			}
			want := map[string]string{
				"query":  "api_key=" + customDecoyToken,
				"header": "Bearer " + customDecoyToken,
				"basic":  "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+decoyPassword)),
			}[name]
			if !strings.Contains(string(body), want) {
				t.Fatalf("the body does not carry the decoy %q:\n%s", want, body)
			}
			if name == "query" && result.response.Header.Get("Location") != "/v1/items/?api_key="+customDecoyToken {
				t.Fatalf("Location = %q", result.response.Header.Get("Location"))
			}
			if name != "query" && !strings.Contains(result.response.Header.Get("X-Echo-Authorization"), strings.TrimPrefix(want, "Bearer ")) {
				t.Fatalf("reflected header = %q", result.response.Header.Get("X-Echo-Authorization"))
			}
		})
	}
}

// encodedUpstream answers with a body the proxy cannot read.
type encodedUpstream struct{ acceptEncoding *string }

func (u encodedUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	*u.acceptEncoding = req.Header.Get("Accept-Encoding")
	header := http.Header{"Content-Encoding": {"br"}}
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader("opaque")), Request: req}, nil
}

func TestInjectedResponseInAnUnreadableEncodingIsRefused(t *testing.T) {
	_, proxy, _ := policyProxy(t, customConnectionPayload(customDecoyToken, customLiveToken))
	var acceptEncoding string
	proxy.transport = encodedUpstream{acceptEncoding: &acceptEncoding}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	req.Header.Set("Accept-Encoding", "br")
	result := processThrough(proxy, req)
	if acceptEncoding != "identity" {
		t.Fatalf("upstream was asked for Accept-Encoding %q", acceptEncoding)
	}
	if result.failure == nil || result.failure.code != "unsafe_upstream_response" {
		t.Fatalf("an unreadable response was returned: %+v", result.failure)
	}
}
