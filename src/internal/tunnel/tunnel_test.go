package tunnel

import (
	"crypto/tls"
	"net"
	"net/netip"
	"reflect"
	"strings"
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
	name, head, late := peekClientHello(server, helloWait)
	if name != "api.example.test" || late {
		t.Fatalf("name = %q, late = %v", name, late)
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
	start := time.Now()
	name, head, late := peekClientHello(server, helloWait)
	if name != "" || len(head) == 0 || late {
		t.Fatalf("name = %q, %d bytes kept, late = %v", name, len(head), late)
	}
	// What isn't a hello is known at once, and isn't held for one.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s", elapsed)
	}
}

// A program that says nothing is held for the wait and no longer, and its flow is
// known as one nothing was learned of.
func TestPeekClientHelloGivesUpOnASilentProgram(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	const wait = 200 * time.Millisecond
	start := time.Now()
	name, head, late := peekClientHello(server, wait)
	if name != "" || len(head) != 0 || !late {
		t.Fatalf("name = %q, %d bytes kept, late = %v", name, len(head), late)
	}
	if elapsed := time.Since(start); elapsed < wait || elapsed > wait+time.Second {
		t.Fatalf("took %s, with %s to wait", elapsed, wait)
	}
}

// A program that goes away without a word isn't one whose hello was late.
func TestPeekClientHelloDoesNotWaitForAProgramThatLeft(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	client.Close()
	start := time.Now()
	if name, head, late := peekClientHello(server, helloWait); name != "" || len(head) != 0 || late {
		t.Fatalf("name = %q, %d bytes kept, late = %v", name, len(head), late)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s", elapsed)
	}
}

// A hello that comes a moment after the connection is still read for its name: a
// program under load, or one that does something else first, takes that long. Let go
// at once, its flow would be relayed unread for as long as the program kept it.
func TestPeekClientHelloWaitsForAHelloThatComesLate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(400 * time.Millisecond)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = tls.Client(conn, &tls.Config{ServerName: "api.example.test", InsecureSkipVerify: true}).Handshake()
	}()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	name, head, late := peekClientHello(server, helloWait)
	if name != "api.example.test" || late || len(head) == 0 || head[0] != 0x16 {
		t.Fatalf("name = %q, %d bytes kept, late = %v", name, len(head), late)
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
	got, skipped := Domains(rules)
	want := []string{"amazonaws.com", "api.github.com", "db.internal.example", ControlHost}
	if len(got) != len(want) || skipped != 0 {
		t.Fatalf("%v, %d skipped", got, skipped)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

// The helper refuses a whole attach over one name it can't write a DNS entry for, so
// one odd host name would keep every Connection out of the tunnel. Such a name is
// left out, and counted.
func TestDomainsLeaveOutNamesADNSEntryCannotHold(t *testing.T) {
	host := func(value string) Rule {
		return Rule{Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: value, Port: 443}}
	}
	rules := []Rule{
		host("api.github.com"), host(" API.Example.Test. "),
		host("under_score.example.test"), host("UNDER_SCORE.example.test."), host("*.wild.example.test"),
		host("localhost"), host("bücher.example.test"), host("two words.example.test"), host("../../etc/hosts"),
		host("fd00::1"), host("::ffff:192.0.2.1"), host("api.example.test:8443"), host(strings.Repeat("a.", 127) + "test"),
		host(""), host(" "), host("."),
	}
	got, skipped := Domains(rules)
	if want := []string{"api.example.test", "api.github.com", ControlHost}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Each name once, however often and however it is written; nothing at all isn't
	// a name.
	if skipped != 10 {
		t.Fatalf("%d names were counted as left out", skipped)
	}
	for _, domain := range got {
		if !CapturableDomain(domain) {
			t.Errorf("%q is sent to the helper, which refuses it", domain)
		}
	}
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}}, nil)
	if err := router.Update("http://phase:secret@127.0.0.1:1", "", rules); err != nil {
		t.Fatal(err)
	}
	if captured, left := router.CapturedDomains(); !reflect.DeepEqual(captured, got) || left != skipped {
		t.Fatalf("the router sends %v and leaves out %d", captured, left)
	}
	// A name that was left out is still a Connection's host when a flow names it.
	if captured, protocol := router.captured("under_score.example.test", 443); !captured || protocol != "http" {
		t.Fatal("a host whose name was left out is no longer a Connection's")
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
