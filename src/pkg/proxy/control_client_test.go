package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The control client sends every request to the proxy it was made for, with
// the proxy's main capability, and is made only for a proxy on this machine.
func TestControlClientReachesOnlyALoopbackProxy(t *testing.T) {
	var mu sync.Mutex
	var targets, authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.URL.String())
		authorizations = append(authorizations, r.Header.Get("Proxy-Authorization"))
		mu.Unlock()
		if r.URL.Path == "/v1/elsewhere" {
			http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")

	// A URL that selects a Connection still makes control calls with the main
	// capability: they do not depend on that Connection.
	for _, user := range []string{"phase", "phase.connection-1"} {
		client, err := ControlClient("http://"+user+":capability@"+address, time.Second, time.Second)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		response, err := client.Get(ControlURL + "/v1/status")
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		_ = response.Body.Close()
		// A redirect is the proxy's answer, not somewhere to go.
		response, err = client.Get(ControlURL + "/v1/elsewhere")
		if err != nil || response.StatusCode != http.StatusFound {
			t.Fatalf("%s: a redirect was followed: %v", user, err)
		}
		_ = response.Body.Close()
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("phase:capability"))
	if len(targets) != 4 || targets[0] != ControlURL+"/v1/status" {
		t.Fatalf("the proxy was asked for %v", targets)
	}
	for _, authorization := range authorizations {
		if authorization != want {
			t.Fatalf("a control call carried %q", authorization)
		}
	}

	for name, raw := range map[string]string{
		"nothing":                "",
		"not a URL":              "://",
		"https":                  "https://phase:capability@" + address,
		"no credential":          "http://" + address,
		"no password":            "http://phase@" + address,
		"an empty password":      "http://phase:@" + address,
		"another user":           "http://someone:capability@" + address,
		"a path":                 "http://phase:capability@" + address + "/v1",
		"a query":                "http://phase:capability@" + address + "?x=1",
		"a fragment":             "http://phase:capability@" + address + "#x",
		"a host off the machine": "http://phase:capability@proxy.example.com:9543",
		"an address off it":      "http://phase:capability@192.0.2.10:9543",
	} {
		if client, err := ControlClient(raw, time.Second, time.Second); err == nil || client != nil {
			t.Errorf("%s: a client was made for %q", name, raw)
		}
	}
	// The call is bounded by the time it was given.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	client, err := ControlClient("http://phase:capability@"+strings.TrimPrefix(slow.URL, "http://"), time.Second, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := client.Get(ControlURL + "/v1/status"); err == nil || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("a call outlived its limit: %v after %v", err, time.Since(started))
	}
}
