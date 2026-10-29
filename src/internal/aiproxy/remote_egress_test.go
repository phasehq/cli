package aiproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

type staticIPResolver map[string][]net.IPAddr

func (r staticIPResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	addresses, ok := r[host]
	if !ok {
		return nil, errors.New("test host did not resolve")
	}
	return append([]net.IPAddr(nil), addresses...), nil
}

func TestRemoteHTTPTransportCannotBypassGuardWithTLSDialHooks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	guard := newRemoteEgressGuard(staticIPResolver{
		"public.example": {{IP: net.ParseIP("93.184.216.34")}},
	})
	baseDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == net.JoinHostPort("93.184.216.34", port) {
			address = server.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	var hookCalls atomic.Int32
	bypass := func(context.Context, string, string) (net.Conn, error) {
		hookCalls.Add(1)
		return (&net.Dialer{}).DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	}
	base := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server uses a private test CA
		DialTLSContext:  bypass,
		DialTLS: func(network, address string) (net.Conn, error) {
			return bypass(context.Background(), network, address)
		},
	}
	transport := guardedRemoteHTTPTransport(base, guard.guardedDial(baseDial))
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		t.Fatal("guarded transport retained an HTTPS bypass hook")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://"+net.JoinHostPort("public.example", port), nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || hookCalls.Load() != 0 {
		t.Fatalf("status=%d TLS hook calls=%d", response.StatusCode, hookCalls.Load())
	}
}

func TestRemoteEgressGuardBlocksSpecialAndMixedDNSAnswers(t *testing.T) {
	guard := newRemoteEgressGuard(staticIPResolver{
		"public.example":   {{IP: net.ParseIP("93.184.216.34")}},
		"rebind.example":   {{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}},
		"metadata.example": {{IP: net.ParseIP("100.100.100.200")}},
	})
	for _, host := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "168.63.129.16", "169.254.169.254",
		"172.16.0.1", "192.168.0.1", "224.0.0.1", "::", "::1", "64:ff9b::7f00:1", "fc00::1", "fec0::1", "fe80::1", "ff02::1",
		"rebind.example", "metadata.example",
	} {
		if _, err := guard.resolvePublic(context.Background(), host); !errors.Is(err, errUnsafeRemoteDestination) {
			t.Errorf("resolvePublic(%q) error = %v, want unsafe destination", host, err)
		}
	}
	addresses, err := guard.resolvePublic(context.Background(), "public.example")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "93.184.216.34" {
		t.Fatalf("public resolution = %v, %v", addresses, err)
	}
}

func TestRemoteEgressGuardPinsValidatedDNSAddress(t *testing.T) {
	guard := newRemoteEgressGuard(staticIPResolver{
		"public.example": {{IP: net.ParseIP("93.184.216.34")}},
	})
	var dialed []string
	dial := guard.guardedDial(func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})
	connection, err := dial(context.Background(), "tcp", "public.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if want := []string{"93.184.216.34:443"}; !reflect.DeepEqual(dialed, want) {
		t.Fatalf("dialed = %v, want %v", dialed, want)
	}
}
