package aiproxy

import (
	"net"
	"strconv"
	"testing"
)

// unusedTestListenAddresses reserves all requested ports together so a single
// test never receives duplicate ephemeral ports, then releases them for the
// Engine. Production Engine configuration still rejects port zero.
func unusedTestListenAddresses(t *testing.T, hosts ...string) []string {
	t.Helper()
	listeners := make([]net.Listener, 0, len(hosts))
	addresses := make([]string, 0, len(hosts))
	for _, host := range hosts {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			for _, held := range listeners {
				_ = held.Close()
			}
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		port := listener.Addr().(*net.TCPAddr).Port
		addresses = append(addresses, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return addresses
}
