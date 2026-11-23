//go:build darwin

package tunnel

import (
	"reflect"
	"testing"
)

// What scutil --dns prints on a Mac with another VPN that keeps a domain of its own,
// a company's split DNS on a port of its own, and Phase capturing one host.
const resolverListing = `DNS configuration

resolver #1
  search domain[0] : tail1234.ts.net
  search domain[1] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  nameserver[2] : 192.168.1.2
  if_index : 14 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : Tail1234.ts.net.
  nameserver[0] : 100.100.100.100
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 102600

resolver #3
  domain   : corp.example.com
  nameserver[0] : 10.8.0.53
  nameserver[1] : 10.8.0.54
  port     : 5353
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #4
  domain   : api.github.com
  nameserver[0] : 198.19.248.53
  port     : 53
  timeout  : 2
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #5
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #6
  domain   : corp.example.com
  nameserver[0] : 10.9.0.53
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 192.168.1.2
  if_index : 14 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

func TestParseResolversKeepsTheSystemsOrderAndEachDomainsServers(t *testing.T) {
	servers, scoped := parseResolvers(resolverListing)
	if want := []string{"192.168.1.1", "192.168.1.2"}; !reflect.DeepEqual(servers, want) {
		t.Fatalf("the network's servers: %v, want %v", servers, want)
	}
	want := map[string][]string{
		"tail1234.ts.net":  {"100.100.100.100"},
		"corp.example.com": {"10.8.0.53:5353", "10.8.0.54:5353"},
	}
	if !reflect.DeepEqual(scoped, want) {
		t.Fatalf("the servers kept for one domain: %v, want %v", scoped, want)
	}
	// The tunnel's own entry is nobody to ask, and neither is a resolver with no server.
	for _, domain := range []string{"api.github.com", "local", "lan"} {
		if _, kept := scoped[domain]; kept {
			t.Errorf("%s was kept", domain)
		}
	}
	if servers, scoped := parseResolvers(""); len(servers) != 0 || len(scoped) != 0 {
		t.Fatalf("nothing printed was read as %v, %v", servers, scoped)
	}
}
