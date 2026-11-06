package tunnel

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestPeekClientHelloFindsTheNameAndKeepsTheBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: "api.example.test", InsecureSkipVerify: true})
		_ = conn.Handshake()
	}()
	name, head := peekClientHello(server)
	if name != "api.example.test" {
		t.Fatalf("name = %q", name)
	}
	if len(head) == 0 || head[0] != 0x16 {
		t.Fatalf("the hello's bytes weren't kept: %d bytes", len(head))
	}
}

func TestPeekClientHelloPassesOtherTrafficThrough(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }()
	name, head := peekClientHello(server)
	if name != "" || len(head) == 0 {
		t.Fatalf("name = %q, %d bytes kept", name, len(head))
	}
}

func TestPeekClientHelloDoesNotWaitForASilentProgram(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	start := time.Now()
	name, head := peekClientHello(server)
	if name != "" || len(head) != 0 {
		t.Fatalf("name = %q, %d bytes kept", name, len(head))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s", elapsed)
	}
}

func TestEchoReplyHasValidChecksums(t *testing.T) {
	v4 := EchoReply(netip.MustParseAddr("1.1.1.1"), LocalAddress, 7, 9, []byte("payload"))
	if InternetChecksum(v4[:20]) != 0 || InternetChecksum(v4[20:]) != 0 {
		t.Fatal("bad IPv4 checksums")
	}
	v6 := EchoReply(netip.MustParseAddr("2001:db8::1"), LocalAddress6, 7, 9, []byte("odd"))
	pseudo := make([]byte, 40, len(v6))
	copy(pseudo, v6[8:40])
	pseudo[35] = byte(len(v6) - 40)
	pseudo[39] = 58
	if InternetChecksum(append(pseudo, v6[40:]...)) != 0 {
		t.Fatal("bad ICMPv6 checksum")
	}
}

func TestPinningLeavesOtherInterfacesAlone(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "100.100.100.100", "fd7a:115c:a1e0::53"} {
		if !staysOnItsRoute(netip.MustParseAddr(host)) {
			t.Errorf("%s would have been pinned", host)
		}
	}
	if staysOnItsRoute(netip.MustParseAddr("1.1.1.1")) {
		t.Error("1.1.1.1 would have been left to the routing table, and looped")
	}
}

func TestPinningRefusesRatherThanLoops(t *testing.T) {
	path := &PhysicalPath{enabled: true}
	called := false
	err := path.Bind("1.1.1.1:443", func(bool, string, int) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("with no interface to leave by: err = %v, called = %v", err, called)
	}
}

func TestDomainsCoverEveryHostOnce(t *testing.T) {
	rules := []Rule{
		{Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: "api.github.com", Port: 443}},
		{Protocol: "http", Host: agentapi.HostRule{Match: "suffix", Value: ".amazonaws.com"}},
		{Protocol: "postgres", Host: agentapi.HostRule{Match: "exact", Value: "db.internal.example", Port: 5432}},
		{Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: "API.GITHUB.COM."}},
	}
	got := Domains(rules)
	want := []string{"amazonaws.com", "api.github.com", "db.internal.example", ControlHost}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

func query(t *testing.T, name string, kind dnsmessage.Type) []byte {
	t.Helper()
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}},
	}
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func answers(t *testing.T, reply []byte) []dnsmessage.Resource {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	return message.Answers
}

func TestDNSAnswersForConnectionHostsOnly(t *testing.T) {
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}}, nil)
	if err := router.Update("http://phase:secret@127.0.0.1:1", "", []Rule{
		{Protocol: "http", Host: agentapi.HostRule{Match: "suffix", Value: "github.com", Port: 443}},
	}); err != nil {
		t.Fatal(err)
	}
	reply := answers(t, router.AnswerDNS(query(t, "api.github.com.", dnsmessage.TypeA)))
	if len(reply) != 1 {
		t.Fatalf("%d answers", len(reply))
	}
	addr := netip.AddrFrom4(reply[0].Body.(*dnsmessage.AResource).A)
	if !TunnelPrefix.Contains(addr) || addr == LocalAddress || addr == DNSAddress || addr == ProbeAddress {
		t.Fatalf("api.github.com got %s", addr)
	}
	if name, ok := router.names.name(addr); !ok || name != "api.github.com" {
		t.Fatalf("%s maps back to %q", addr, name)
	}
	if again := answers(t, router.AnswerDNS(query(t, "api.github.com.", dnsmessage.TypeA))); netip.AddrFrom4(again[0].Body.(*dnsmessage.AResource).A) != addr {
		t.Fatal("the same name got a different address")
	}
	if got := answers(t, router.AnswerDNS(query(t, "api.github.com.", dnsmessage.TypeAAAA))); len(got) != 0 {
		t.Fatal("an IPv6 address was handed out, which would skip the proxy")
	}
	if got := answers(t, router.AnswerDNS(query(t, ControlHost+".", dnsmessage.TypeA))); len(got) != 1 {
		t.Fatal("the control host didn't resolve")
	}
}

func TestNameTableReusesTheOldestAddress(t *testing.T) {
	pool := netip.MustParsePrefix("198.19.249.0/29")
	table := newNameTable(pool)
	seen := map[netip.Addr]bool{}
	first := table.address("a.example")
	for i := 0; i < 5; i++ {
		addr := table.address(string(rune('b'+i)) + ".example")
		if !pool.Contains(addr) || addr == pool.Addr() || addr == lastAddress(pool) {
			t.Fatalf("%s is outside the usable pool", addr)
		}
		seen[addr] = true
	}
	if _, ok := table.name(first); ok {
		if reused := table.address("z.example"); reused != first {
			t.Fatalf("expected the oldest address back, got %s", reused)
		}
		if _, ok := table.name(first); !ok {
			t.Fatal("reused address lost its new name")
		}
	}
}
