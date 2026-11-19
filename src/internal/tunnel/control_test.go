package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// controlProxy stands in for the credential proxy's control API: it answers whoever
// presents the proxy's password with something only the control API would say.
type controlProxy struct {
	mu   sync.Mutex
	seen []string
}

const controlSecret = `{"GITHUB_TOKEN":"a Connection's environment"}`

func startControlProxy(t *testing.T) (*controlProxy, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &controlProxy{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == "" || !r.URL.IsAbs() {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		proxy.mu.Lock()
		proxy.seen = append(proxy.seen, r.Method+" "+r.URL.String())
		proxy.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, controlSecret)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return proxy, listener.Addr().String()
}

func (p *controlProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// askControl sends one request to the control address as a program would, with the
// request line and Host it is given, and returns the status and the body.
func askControl(t *testing.T, router *Router, port uint16, target, host string) (int, string) {
	t.Helper()
	found := answers(t, router.AnswerDNS(query(t, ControlHost+".", dnsmessage.TypeA)))
	if len(found) != 1 {
		t.Fatal("the control host didn't resolve")
	}
	address := netip.AddrFrom4(found[0].Body.(*dnsmessage.AResource).A)
	program, routerEnd := net.Pipe()
	defer program.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer routerEnd.Close()
		router.HandleTCP(routerEnd, Flow{Source: netip.AddrPortFrom(LocalAddress, 50100), Dest: netip.AddrPortFrom(address, port)})
	}()
	_ = program.SetDeadline(time.Now().Add(10 * time.Second))
	request := fmt.Sprintf("GET %s HTTP/1.1\r\n", target)
	if host != "" {
		request += "Host: " + host + "\r\n"
	}
	if _, err := io.WriteString(program, request+"Connection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(program), nil)
	if err != nil {
		t.Fatalf("%s as %q: %v", target, host, err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	program.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the router never let go of the connection")
	}
	return response.StatusCode, string(body)
}

// The control address presents the proxy's password for whoever reaches it, so it
// answers only as its own name. A browser reads whatever a page's own origin answers:
// a page whose name is pointed at this address must get nothing.
func TestTheControlAPIAnswersOnlyForItsOwnName(t *testing.T) {
	proxy, address := startControlProxy(t)
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true}, nil)
	if err := router.Update("http://phase:secret@"+address, "", nil); err != nil {
		t.Fatal(err)
	}
	const path = "/v1/connections/api/environment"

	for name, test := range map[string]struct {
		port   uint16
		target string
		host   string
	}{
		"its name":                        {80, path, ControlHost},
		"its name with the port":          {80, path, ControlHost + ":80"},
		"its name in another case":        {80, path, strings.ToUpper(ControlHost)},
		"its name as a full name":         {80, path, ControlHost + "."},
		"another port, named":             {8080, path, ControlHost + ":8080"},
		"its name in the request's line":  {80, "http://" + ControlHost + path, ControlHost},
		"the line's name over the header": {80, "http://" + ControlHost + path, "rebound.example"},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(proxy.requests())
			status, body := askControl(t, router, test.port, test.target, test.host)
			if status != http.StatusOK || body != controlSecret {
				t.Fatalf("%d: %q", status, body)
			}
			if sent := proxy.requests(); len(sent) != before+1 || sent[before] != "GET http://"+ControlHost+path {
				t.Fatalf("the proxy was asked %q", sent[before:])
			}
		})
	}

	refused := map[string]struct {
		port   uint16
		target string
		host   string
	}{
		"a page's own name":                  {80, path, "rebound.example"},
		"a page's own name and port":         {80, path, "rebound.example:80"},
		"a name that starts like it":         {80, path, ControlHost + ".rebound.example"},
		"a name that ends like it":           {80, path, "rebound." + ControlHost},
		"the address itself":                 {80, path, "198.19.249.1"},
		"a port the program didn't come to":  {80, path, ControlHost + ":8080"},
		"the default port on another":        {8080, path, ControlHost + ":80"},
		"no name":                            {80, path, ""},
		"a page's name in the request line":  {80, "http://rebound.example" + path, ControlHost},
		"a name with its own password":       {80, path, "phase:secret@" + ControlHost},
		"a name that isn't one":              {80, path, ControlHost + ":80:80"},
		"another name before it, as a list":  {80, path, "rebound.example, " + ControlHost},
		"an IPv6 address":                    {80, path, "[::1]:80"},
		"its name with a port that is none":  {80, path, ControlHost + ":http"},
		"its name with an empty port":        {80, path, ControlHost + ":"},
		"its name with a longer port number": {80, path, ControlHost + ":080"},
	}
	before := len(proxy.requests())
	for name, test := range refused {
		t.Run(name, func(t *testing.T) {
			status, body := askControl(t, router, test.port, test.target, test.host)
			if status < 400 || status > 499 {
				t.Fatalf("answered %d", status)
			}
			if strings.Contains(body, "GITHUB_TOKEN") || strings.Contains(body, "environment") {
				t.Fatalf("answered with %q", body)
			}
		})
	}
	if sent := proxy.requests(); len(sent) != before {
		t.Fatalf("the proxy was asked %q on behalf of a request that wasn't for the control host", sent[before:])
	}
	// Go's server turns some of these away itself, before the name is looked at.
	counts := router.Counts()
	if counts["control_refused"] == 0 || counts["control_refused"] > len(refused) || counts["control"] != 7+len(refused) {
		t.Fatalf("counts: %v", counts)
	}
}

func TestControlAuthority(t *testing.T) {
	for authority, ok := range map[string]bool{
		ControlHost: true, ControlHost + ":80": true, "PHASE.invalid": true, ControlHost + ".": true, ControlHost + ".:80": true,
		"": false, ":80": false, ControlHost + ":81": false, ControlHost + ":": false, ControlHost + ":080": false,
		"evil." + ControlHost: false, ControlHost + ".evil.example": false, "198.19.249.1": false, "[::1]:80": false,
		ControlHost + "@evil.example": false, "evil.example#" + ControlHost: false, ControlHost + " ": false,
	} {
		if got := controlAuthority(authority, 80); got != ok {
			t.Errorf("controlAuthority(%q, 80) = %v", authority, got)
		}
	}
	if !controlAuthority(ControlHost+":8443", 8443) || controlAuthority(ControlHost+":80", 8443) || !controlAuthority(ControlHost, 8443) {
		t.Error("the port a program came to isn't the one its request may name")
	}
}
