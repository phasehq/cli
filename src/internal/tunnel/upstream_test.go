package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsStandIn is a DNS server on this machine. It counts what it is asked, and answers
// every name with one address, says no name exists, or says nothing.
type dnsStandIn struct {
	address string
	asked   atomic.Int32
	answer  netip.Addr
	missing bool
	silent  bool
}

func startDNS(t *testing.T, server *dnsStandIn) *dnsStandIn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	server.address = conn.LocalAddr().String()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			server.asked.Add(1)
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil || server.silent {
				continue
			}
			question, err := parser.Question()
			if err != nil {
				continue
			}
			reply := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{question},
			}
			switch {
			case server.missing:
				reply.Header.RCode = dnsmessage.RCodeNameError
			case question.Type == dnsmessage.TypeA:
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10},
					Body:   &dnsmessage.AResource{A: server.answer.As4()},
				}}
			}
			if packed, err := reply.Pack(); err == nil {
				_, _ = conn.WriteTo(packed, from)
			}
		}
	}()
	return server
}

func answering(t *testing.T, address string) *dnsStandIn {
	return startDNS(t, &dnsStandIn{answer: netip.MustParseAddr(address)})
}

// notThere is the address of a DNS server that isn't running.
func notThere(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func lookupOne(t *testing.T, upstream *Upstream, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addresses, err := upstream.lookup(ctx, name)
	if err != nil || len(addresses) != 1 {
		t.Fatalf("%s resolved to %v, %v", name, addresses, err)
	}
	return addresses[0].String()
}

// The network's own servers are asked first, in their order, every time. A public
// server asked in their place knows nothing of a private name, and knows another
// address for one that is public as well.
func TestLookupAsksTheNetworksOwnServersInOrder(t *testing.T) {
	first, second, public := answering(t, "10.0.0.1"), answering(t, "10.0.0.2"), answering(t, "203.0.113.9")
	upstream := &Upstream{Servers: []string{first.address, second.address}, Fallback: []string{public.address}}
	for range 6 {
		if got := lookupOne(t, upstream, "db.internal.example.test"); got != "10.0.0.1" {
			t.Fatalf("the name resolved to %s", got)
		}
	}
	if second.asked.Load() != 0 || public.asked.Load() != 0 {
		t.Fatalf("with the first server answering, the second was asked %d times and the public one %d", second.asked.Load(), public.asked.Load())
	}
}

// A name the network's server says doesn't exist doesn't exist. Nobody else is asked.
func TestLookupTakesNoForAnAnswer(t *testing.T) {
	first := startDNS(t, &dnsStandIn{missing: true})
	second, public := answering(t, "10.0.0.2"), answering(t, "203.0.113.9")
	upstream := &Upstream{Servers: []string{first.address, second.address}, Fallback: []string{public.address}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addresses, err := upstream.lookup(ctx, "nothing.example.test")
	var answer *net.DNSError
	if err == nil || !errors.As(err, &answer) || !answer.IsNotFound {
		t.Fatalf("a name that doesn't exist resolved to %v, %v", addresses, err)
	}
	if second.asked.Load() != 0 || public.asked.Load() != 0 {
		t.Fatalf("the second server was asked %d times and the public one %d", second.asked.Load(), public.asked.Load())
	}
}

// A server that doesn't answer is passed over for the next of the network's own, and
// a public one is asked only when none of those answers.
func TestLookupFallsBackOnlyWhenNoServerAnswers(t *testing.T) {
	t.Run("the next of the network's own answers", func(t *testing.T) {
		quiet := startDNS(t, &dnsStandIn{silent: true})
		second, public := answering(t, "10.0.0.2"), answering(t, "203.0.113.9")
		upstream := &Upstream{Servers: []string{quiet.address, notThere(t), second.address}, Fallback: []string{public.address}, wait: 200 * time.Millisecond}
		if got := lookupOne(t, upstream, "db.internal.example.test"); got != "10.0.0.2" {
			t.Fatalf("the name resolved to %s", got)
		}
		if quiet.asked.Load() == 0 || public.asked.Load() != 0 {
			t.Fatalf("the quiet server was asked %d times and the public one %d", quiet.asked.Load(), public.asked.Load())
		}
	})
	t.Run("none of them answers", func(t *testing.T) {
		quiet, public := startDNS(t, &dnsStandIn{silent: true}), answering(t, "203.0.113.9")
		upstream := &Upstream{Servers: []string{quiet.address, notThere(t)}, Fallback: []string{public.address}, wait: 200 * time.Millisecond}
		if got := lookupOne(t, upstream, "www.example.test"); got != "203.0.113.9" {
			t.Fatalf("the name resolved to %s", got)
		}
	})
	t.Run("the network has none", func(t *testing.T) {
		public := answering(t, "203.0.113.9")
		if got := lookupOne(t, &Upstream{Fallback: []string{public.address}}, "www.example.test"); got != "203.0.113.9" {
			t.Fatalf("the name resolved to %s", got)
		}
	})
	t.Run("nobody at all", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if addresses, err := (&Upstream{}).lookup(ctx, "www.example.test"); err == nil {
			t.Fatalf("with no server to ask, the name resolved to %v", addresses)
		}
	})
}

// A name under a domain the system keeps servers for is asked of those first, as the
// system would, and no other name is.
func TestLookupAsksADomainsOwnServersForItsNames(t *testing.T) {
	general, wide, narrow := answering(t, "10.0.0.1"), answering(t, "10.1.0.1"), answering(t, "10.2.0.1")
	upstream := &Upstream{
		Servers: []string{general.address},
		Scoped:  map[string][]string{"example.test": {wide.address}, "corp.example.test": {narrow.address}},
	}
	for name, want := range map[string]string{
		"db.corp.example.test":      "10.2.0.1",
		"corp.example.test":         "10.2.0.1",
		"DB.Corp.Example.Test.":     "10.2.0.1",
		"www.example.test":          "10.1.0.1",
		"notcorp.example.test":      "10.1.0.1",
		"www.example.com":           "10.0.0.1",
		"corp.example.test.invalid": "10.0.0.1",
	} {
		if got := lookupOne(t, upstream, name); got != want {
			t.Errorf("%s resolved to %s, want %s", name, got, want)
		}
	}
	// When a domain's own server doesn't answer, the network's are still there.
	upstream.Scoped["corp.example.test"], upstream.wait = []string{notThere(t)}, 200*time.Millisecond
	if got := lookupOne(t, upstream, "db.corp.example.test"); got != "10.0.0.1" {
		t.Fatalf("with its domain's server gone, the name resolved to %s", got)
	}
}

// A raw query is taken to the servers in the same order, and the first answer is the
// answer, whatever it says.
func TestForwardAsksTheServersInTheSameOrder(t *testing.T) {
	rcode := func(reply []byte) dnsmessage.RCode {
		t.Helper()
		var message dnsmessage.Message
		if err := message.Unpack(reply); err != nil {
			t.Fatal(err)
		}
		return message.Header.RCode
	}
	t.Run("a name that doesn't exist", func(t *testing.T) {
		first, public := startDNS(t, &dnsStandIn{missing: true}), answering(t, "203.0.113.9")
		upstream := &Upstream{Servers: []string{first.address}, Fallback: []string{public.address}}
		reply := upstream.Forward("cdn.example.test", query(t, "cdn.example.test.", dnsmessage.TypeA))
		if rcode(reply) != dnsmessage.RCodeNameError || public.asked.Load() != 0 {
			t.Fatalf("the answer was %v, and the public server was asked %d times", rcode(reply), public.asked.Load())
		}
	})
	t.Run("a server that isn't there", func(t *testing.T) {
		second, public := answering(t, "10.0.0.2"), answering(t, "203.0.113.9")
		upstream := &Upstream{Servers: []string{notThere(t), second.address}, Fallback: []string{public.address}}
		found := answers(t, upstream.Forward("cdn.example.test", query(t, "cdn.example.test.", dnsmessage.TypeA)))
		if len(found) != 1 || netip.AddrFrom4(found[0].Body.(*dnsmessage.AResource).A) != netip.MustParseAddr("10.0.0.2") || public.asked.Load() != 0 {
			t.Fatalf("the answer was %v, and the public server was asked %d times", found, public.asked.Load())
		}
	})
	t.Run("a domain's own server", func(t *testing.T) {
		general, scoped := answering(t, "10.0.0.1"), answering(t, "10.2.0.1")
		upstream := &Upstream{Servers: []string{general.address}, Scoped: map[string][]string{"corp.example.test": {scoped.address}}}
		found := answers(t, upstream.Forward("db.corp.example.test", query(t, "db.corp.example.test.", dnsmessage.TypeA)))
		if len(found) != 1 || netip.AddrFrom4(found[0].Body.(*dnsmessage.AResource).A) != netip.MustParseAddr("10.2.0.1") || general.asked.Load() != 0 {
			t.Fatalf("the answer was %v, and the general server was asked %d times", found, general.asked.Load())
		}
	})
}

func TestServersForListsEachServerOnce(t *testing.T) {
	upstream := &Upstream{
		Servers: []string{"192.168.1.1", "100.100.100.100"}, Fallback: []string{"1.1.1.1", "192.168.1.1"},
		Scoped: map[string][]string{"ts.example.test": {"100.100.100.100"}},
	}
	if got, want := upstream.serversFor("host.ts.example.test."), []string{"100.100.100.100", "192.168.1.1", "1.1.1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, want := upstream.serversFor("www.example.test"), []string{"192.168.1.1", "100.100.100.100", "1.1.1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for server, want := range map[string]string{"192.168.1.1": "192.168.1.1:53", "192.168.1.1:5353": "192.168.1.1:5353", "fd00::53": "[fd00::53]:53", "[fd00::53]:5353": "[fd00::53]:5353"} {
		if got := serverAddress(server); got != want {
			t.Errorf("%s is asked at %s, want %s", server, got, want)
		}
	}
}
