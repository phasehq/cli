package tunnel

import (
	"crypto/tls"
	"errors"
	"fmt"
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
	// Everything is captured, so the route out leads into the tunnel.
	path := &PhysicalPath{enabled: true, route: func(netip.Addr) (netip.Addr, error) { return LocalAddress, nil }}
	called := false
	err := path.Bind("1.1.1.1:443", func(bool, string, int) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("with no interface to leave by: err = %v, called = %v", err, called)
	}
}

// A socket is pinned to the physical interface only where its route would lead into
// the tunnel, or already leaves by that interface. One whose route goes by another
// VPN, to its resolver or its hosts, is left on it.
func TestPinningLeavesAnotherVPNsRoutesAlone(t *testing.T) {
	wifi := netip.MustParseAddr("192.168.1.20")
	vpn := netip.MustParseAddr("10.8.0.2")
	for name, test := range map[string]struct {
		source netip.Addr
		err    error
		index  int
		pinned bool
	}{
		"into the tunnel":                  {LocalAddress, nil, 5, true},
		"into the tunnel, over IPv6":       {LocalAddress6, nil, 5, true},
		"by the physical interface":        {wifi, nil, 5, true},
		"by another VPN":                   {vpn, nil, 5, false},
		"a route that can't be told":       {netip.Addr{}, errors.New("no route to host"), 5, true},
		"by another VPN, with no Wi-Fi":    {vpn, nil, 0, false},
		"into the tunnel, with no network": {LocalAddress, nil, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := &PhysicalPath{
				enabled: true, name: "en0", index: test.index,
				route: func(netip.Addr) (netip.Addr, error) { return test.source, test.err },
				addresses: func(index int) ([]netip.Addr, error) {
					if index != 5 {
						return nil, errors.New("no such interface")
					}
					return []netip.Addr{netip.MustParseAddr("fe80::1"), wifi}, nil
				},
			}
			called := false
			err := path.Bind("10.8.0.53:53", func(bool, string, int) error {
				called = true
				return nil
			})
			if test.index == 0 && test.source == LocalAddress {
				// It would loop, and there is nowhere to pin it: refused.
				if err == nil || called {
					t.Fatalf("err = %v, pinned = %v", err, called)
				}
				return
			}
			if err != nil || called != test.pinned {
				t.Fatalf("err = %v, pinned = %v, want %v", err, called, test.pinned)
			}
		})
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
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	table.clock = func() time.Time { return now }
	first, ok := table.address("a.example")
	if !ok {
		t.Fatal("the first name got no address")
	}
	for i := 0; i < 5; i++ {
		addr, ok := table.address(string(rune('b'+i)) + ".example")
		if !ok || !pool.Contains(addr) || addr == pool.Addr() || addr == lastAddress(pool) {
			t.Fatalf("%s is outside the usable pool", addr)
		}
	}
	// Every address was given out just now: a program may still use any of them.
	if addr, ok := table.address("y.example"); ok {
		t.Fatalf("an address given out moments ago went to another name: %s", addr)
	}
	now = now.Add(addressHold / 2)
	// Asked again, a name keeps its address, and the hold starts over.
	if again, ok := table.address("a.example"); !ok || again != first {
		t.Fatalf("a.example moved to %s", again)
	}
	now = now.Add(addressHold/2 + time.Second)
	reused, ok := table.address("z.example")
	if !ok || reused == first {
		t.Fatalf("expected the oldest address not asked about since, got %s (%v)", reused, ok)
	}
	if name, ok := table.name(reused); !ok || name != "z.example" {
		t.Fatal("the reused address lost its new name")
	}
	if name, ok := table.name(first); !ok || name != "a.example" {
		t.Fatalf("a.example lost its address to %q", name)
	}
}

// When the pool holds nothing old enough to take back, a new name gets an answer
// that says so, never an address a program may still use for another name.
func TestANameIsRefusedWhenNoAddressIsFree(t *testing.T) {
	router := NewRouter(&Upstream{OnlyOverrides: true}, nil)
	router.names = newNameTable(netip.MustParsePrefix("198.19.249.0/29"))
	var rules []Rule
	for i := 0; i < 7; i++ {
		rules = append(rules, Rule{ConnectionID: "api", Protocol: "http", Host: agentapi.HostRule{Match: "exact", Value: fmt.Sprintf("host-%d.example.test", i), Port: 443}})
	}
	router.SetRules(rules)
	for i := 0; i < 6; i++ {
		if got := answers(t, router.AnswerDNS(query(t, fmt.Sprintf("host-%d.example.test.", i), dnsmessage.TypeA))); len(got) != 1 {
			t.Fatalf("host-%d got no address", i)
		}
	}
	reply := router.AnswerDNS(query(t, "host-6.example.test.", dnsmessage.TypeA))
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	if message.Header.RCode != dnsmessage.RCodeServerFailure || len(message.Answers) != 0 {
		t.Fatalf("answered %v with %v", message.Header.RCode, message.Answers)
	}
	if router.Counts()["dns_no_address"] != 1 {
		t.Fatalf("counts %v", router.Counts())
	}
}
