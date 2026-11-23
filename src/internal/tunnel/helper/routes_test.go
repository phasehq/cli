package helper

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/tunnel"
)

// A routing table as netstat -rn prints it on macOS, with another VPN's routes in it.
const quietTable = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#24            UCSIg               utun4
0/1                utun6              USc                 utun6
128.0/1            utun6              USc                 utun6
10.8/16            10.8.0.1           UGSc                utun6
100.64/10          link#24            UCS                 utun4
100.100.100.100/32 link#24            UCS                 utun4
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#14            UCS                   en0      !
192.168.1          link#14            UCS                   en0      !
192.168.1.1/32     link#14            UCS                   en0      !
192.168.1.1        a0:b1:c2:d3:e4:f5  UHLWIir               en0   1193
198.18/16          link#30            UCS                 utun9
198.19.0/17        link#30            UCS                 utun9
198.19.247.255/32  link#30            UCS                 utun9
198.19.252/22      link#30            UCS                 utun9
224.0.0/4          link#14            UmCS                  en0      !
255.255.255.255/32 link#14            UCS                   en0      !

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
::1                                     ::1                                     UHL                   lo0
::/1                                    utun6                                   USc                 utun6
fc00::/7                                link#24                                 UCS                 utun4
fd70:7068:6172::/48                     link#30                                 UCS                 utun9
fd7a:115c:a1e0::/48                     link#24                                 UCS                 utun4
fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0
fe80::1%lo0                             link#1                                  UHLI                  lo0
fe80::%utun4/64                         fe80::ce81:b1c:bd2c:69e%utun4           UcI                 utun4
ff00::/8                                ::1                                     UmCI                  lo0
ff02::%en0/16                           link#14                                 UmCI                  en0
`

// Phase uses all of 198.19.248.0/22: its own addresses, and the pool that Connection
// hosts get theirs from. Something else routing any part of it is found, wherever in
// the range it is, and so is its IPv6 address.
func TestRangeConflictFindsARouteAnywhereInPhasesRanges(t *testing.T) {
	if used, line, found := rangeConflict(quietTable); found {
		t.Fatalf("a table that uses none of Phase's ranges: %s is used by %q", used, line)
	}
	own6 := netip.PrefixFrom(tunnel.LocalAddress6, 128)
	for route, used := range map[string]netip.Prefix{
		// The range itself, and what the old check looked for.
		"198.19.248/22": tunnel.TunnelPrefix, "198.19.248.1": tunnel.TunnelPrefix, "198.19.248/24": tunnel.TunnelPrefix,
		// The pool of addresses for Connection hosts, and the rest of the range.
		"198.19.249": tunnel.TunnelPrefix, "198.19.249/24": tunnel.TunnelPrefix, "198.19.249.17": tunnel.TunnelPrefix,
		"198.19.250/23": tunnel.TunnelPrefix, "198.19.251.255/32": tunnel.TunnelPrefix,
		// The block the range was picked from, or a part of it that takes the range in.
		"198.18/15": tunnel.TunnelPrefix, "198.19": tunnel.TunnelPrefix, "198.19.128/17": tunnel.TunnelPrefix, "198.19.240/20": tunnel.TunnelPrefix,
		// The same for IPv6.
		"fd70:7068:6173::1": own6, "fd70:7068:6173::/64": own6, "fd70:7068:6173::/48": own6, "fd70:7068:6173::%utun9/64": own6,
	} {
		table := strings.Replace(quietTable, "198.19.252/22      link#30", route+" link#30", 1)
		if strings.Contains(route, ":") {
			table = strings.Replace(quietTable, "fd70:7068:6172::/48", route, 1)
		}
		got, line, found := rangeConflict(table)
		if !found || got != used || !strings.HasPrefix(line, route+" ") {
			t.Errorf("a route for %s: found %v, %s, %q", route, found, got, line)
		}
	}
}

func TestListedRouteReadsNetstatsDestinations(t *testing.T) {
	for destination, want := range map[string]string{
		"127": "127.0.0.0/8", "169.254": "169.254.0.0/16", "192.168.1": "192.168.1.0/24", "192.168.1.1": "192.168.1.1/32",
		"192.168.1.1/32": "192.168.1.1/32", "198.19.248/22": "198.19.248.0/22", "0/1": "0.0.0.0/1", "128.0/1": "128.0.0.0/1",
		"224.0.0/4": "224.0.0.0/4", "10.8/16": "10.8.0.0/16", "100.64/10": "100.64.0.0/10",
		"::1": "::1/128", "::/1": "::/1", "fe80::%lo0/64": "fe80::/64", "fe80::1%lo0": "fe80::1/128",
		"fd70:7068:6173::1": "fd70:7068:6173::1/128", "ff02::%en0/16": "ff02::/16",
	} {
		got, ok := listedRoute(destination)
		if !ok || got.String() != want {
			t.Errorf("%q was read as %v (%v), want %s", destination, got, ok, want)
		}
	}
	for _, destination := range []string{
		"default", "Destination", "Internet:", "Internet6:", "Routing", "", "1.2.3.4.5", "1.2.3/33", "1.2.3/x", "300.1", "::1/129", "::ffff:1.2.3.4", "link#14",
	} {
		if got, ok := listedRoute(destination); ok {
			t.Errorf("%q was read as the route %s", destination, got)
		}
	}
}

// fakeTable is a routing table, and a route(8) that changes it.
type fakeTable struct {
	// routes maps a destination to the index of the interface it leaves by.
	routes map[netip.Prefix]int
	// unreadable makes every look at the table fail.
	unreadable bool
	// deaf makes route(8) report success and change nothing, as it can: for every
	// destination, or for the ones in quiet.
	deaf  bool
	quiet map[netip.Prefix]bool
	// taken is added by someone else just before route(8) runs.
	taken map[netip.Prefix]int
	// stubborn makes route(8) fail to remove anything, and say so.
	stubborn bool
	ran      []string
}

const (
	ownIndex   = 27
	otherIndex = 24
)

func (f *fakeTable) steps() routeSteps {
	return routeSteps{
		index: func(device string) (int, error) {
			if device != "utun7" {
				return 0, errors.New("route ip+net: no such network interface")
			}
			return ownIndex, nil
		},
		leaves: func(prefix netip.Prefix) (int, bool, error) {
			if f.unreadable {
				return 0, false, errors.New("the routing table can't be read")
			}
			index, found := f.routes[prefix]
			return index, found, nil
		},
		run: func(step ...string) error {
			f.ran = append(f.ran, strings.Join(step, " "))
			prefix := netip.MustParsePrefix(step[5])
			for destination, index := range f.taken {
				f.routes[destination] = index
			}
			if f.deaf || f.quiet[prefix] {
				return nil
			}
			switch step[3] {
			case "add":
				if _, found := f.routes[prefix]; found {
					return errors.New("route: writing to routing socket: File exists")
				}
				f.routes[prefix] = ownIndex
			case "delete":
				if f.stubborn {
					return errors.New("route: writing to routing socket: Operation not permitted")
				}
				// By destination, whoever added it.
				delete(f.routes, prefix)
			}
			return nil
		},
	}
}

func prefixes(routes ...string) map[netip.Prefix]int {
	table := map[netip.Prefix]int{}
	for _, route := range routes {
		table[netip.MustParsePrefix(route)] = otherIndex
	}
	return table
}

func TestRouteStepsTakeAndGiveBackTheirOwnRoutes(t *testing.T) {
	table := &fakeTable{routes: prefixes("10.8.0.0/16")}
	steps := table.steps()
	added, err := steps.add("utun7", tunnel.FullRoutes)
	if err != nil || !reflect.DeepEqual(added, tunnel.FullRoutes) {
		t.Fatalf("added %v: %v", added, err)
	}
	want := []string{
		"/sbin/route -q -n add -inet 0.0.0.0/1 -interface utun7", "/sbin/route -q -n add -inet 128.0.0.0/1 -interface utun7",
		"/sbin/route -q -n add -inet6 ::/1 -interface utun7", "/sbin/route -q -n add -inet6 8000::/1 -interface utun7",
	}
	if !reflect.DeepEqual(table.ran, want) || len(table.routes) != 5 {
		t.Fatalf("ran %q, table %v", table.ran, table.routes)
	}
	table.ran = nil
	steps.remove("utun7", tunnel.FullRoutes)
	if len(table.ran) != 4 || !strings.HasPrefix(table.ran[0], "/sbin/route -q -n delete -inet 0.0.0.0/1 -interface utun7") {
		t.Fatalf("ran %q", table.ran)
	}
	if !reflect.DeepEqual(table.routes, prefixes("10.8.0.0/16")) {
		t.Fatalf("the table after giving back: %v", table.routes)
	}
}

// Another VPN holds the very route a capture asks for. It is never replaced, and
// never removed: the system removes a route by where it goes to, whoever added it.
func TestRouteStepsLeaveAnotherVPNsRoutesAlone(t *testing.T) {
	theirs := prefixes("128.0.0.0/1", "10.8.0.0/16")
	t.Run("it is there before", func(t *testing.T) {
		// A capture is all of its routes or none: with one of them taken, nothing is
		// added, not even the half that could be.
		table := &fakeTable{routes: prefixes("128.0.0.0/1", "10.8.0.0/16")}
		added, err := table.steps().add("utun7", []string{"0.0.0.0/1", "128.0.0.0/1"})
		if err == nil || err.Error() != "128.0.0.0/1 is already routed by another interface (index 24), and was left alone" {
			t.Fatalf("adding over another VPN's route: %v", err)
		}
		if len(added) != 0 || len(table.ran) != 0 || !reflect.DeepEqual(table.routes, theirs) {
			t.Fatalf("added %v, ran %q, table %v", added, table.ran, table.routes)
		}
		named := table.steps()
		named.name = func(index int) string { return map[int]string{otherIndex: "utun4"}[index] }
		if _, err := named.add("utun7", []string{"128.0.0.0/1"}); err == nil || !strings.Contains(err.Error(), "by another interface (utun4)") {
			t.Fatalf("adding over another VPN's route: %v", err)
		}
		// The helper gives back what it added. Asked for more by mistake, the steps
		// still leave what isn't the device's.
		table.routes[netip.MustParsePrefix("0.0.0.0/1")] = ownIndex
		table.steps().remove("utun7", []string{"0.0.0.0/1", "128.0.0.0/1", "10.8.0.0/16", "192.0.2.0/24"})
		if !reflect.DeepEqual(table.ran, []string{"/sbin/route -q -n delete -inet 0.0.0.0/1 -interface utun7"}) || !reflect.DeepEqual(table.routes, theirs) {
			t.Fatalf("ran %q, table %v", table.ran, table.routes)
		}
	})
	// What was added before the one that couldn't be is said, so that it is given
	// back, and the other VPN's route is not among it.
	t.Run("it arrives as the route is added, and route says nothing", func(t *testing.T) {
		table := &fakeTable{routes: map[netip.Prefix]int{}, taken: prefixes("128.0.0.0/1"), quiet: map[netip.Prefix]bool{netip.MustParsePrefix("128.0.0.0/1"): true}}
		added, err := table.steps().add("utun7", []string{"0.0.0.0/1", "128.0.0.0/1"})
		if err == nil || !strings.Contains(err.Error(), "the route for 128.0.0.0/1 wasn't added") || !reflect.DeepEqual(added, []string{"0.0.0.0/1"}) {
			t.Fatalf("a route that went to another VPN was taken as added: %v, %v", added, err)
		}
		if len(table.ran) != 2 || table.routes[netip.MustParsePrefix("128.0.0.0/1")] != otherIndex {
			t.Fatalf("ran %q, table %v", table.ran, table.routes)
		}
		// And when route does say: the same.
		table = &fakeTable{routes: map[netip.Prefix]int{}, taken: prefixes("128.0.0.0/1")}
		added, err = table.steps().add("utun7", []string{"0.0.0.0/1", "128.0.0.0/1"})
		if err == nil || !strings.Contains(err.Error(), "File exists") || !reflect.DeepEqual(added, []string{"0.0.0.0/1"}) {
			t.Fatalf("added %v: %v", added, err)
		}
	})
	t.Run("route says it added one that isn't there", func(t *testing.T) {
		table := &fakeTable{routes: map[netip.Prefix]int{}, deaf: true}
		if added, err := table.steps().add("utun7", []string{"0.0.0.0/1"}); err == nil || !strings.Contains(err.Error(), "wasn't added") || len(added) != 0 {
			t.Fatalf("a route that isn't in the table was taken as added: %v, %v", added, err)
		}
	})
	t.Run("it replaced the helper's own since", func(t *testing.T) {
		table := &fakeTable{routes: map[netip.Prefix]int{}}
		if _, err := table.steps().add("utun7", []string{"0.0.0.0/1"}); err != nil {
			t.Fatal(err)
		}
		table.routes[netip.MustParsePrefix("0.0.0.0/1")] = otherIndex
		table.ran = nil
		table.steps().remove("utun7", []string{"0.0.0.0/1"})
		if len(table.ran) != 0 || len(table.routes) != 1 {
			t.Fatalf("ran %q, table %v", table.ran, table.routes)
		}
	})
}

func TestRouteStepsWhenTheTableSaysLittle(t *testing.T) {
	// The device's own route is already there, left from a capture that wasn't
	// cleaned up: it counts as added, so that it is given back.
	table := &fakeTable{routes: map[netip.Prefix]int{netip.MustParsePrefix("0.0.0.0/1"): ownIndex}}
	if added, err := table.steps().add("utun7", []string{"0.0.0.0/1"}); err != nil || len(table.ran) != 0 || len(added) != 1 {
		t.Fatalf("added %v: %v, ran %q", added, err, table.ran)
	}
	// A table that can't be read leaves route's own word, as before.
	table = &fakeTable{routes: map[netip.Prefix]int{}, unreadable: true}
	if added, err := table.steps().add("utun7", []string{"0.0.0.0/1"}); err != nil || len(table.ran) != 1 || len(added) != 1 {
		t.Fatalf("added %v: %v, ran %q", added, err, table.ran)
	}
	if added, err := table.steps().add("utun7", []string{"128.0.0.0/1", "0.0.0.0/1"}); err == nil || !reflect.DeepEqual(added, []string{"128.0.0.0/1"}) {
		t.Fatalf("route's own failure was lost: added %v, %v", added, err)
	}
	table.steps().remove("utun7", []string{"128.0.0.0/1"})
	table.ran = nil
	table.steps().remove("utun7", []string{"0.0.0.0/1"})
	if len(table.ran) != 1 || len(table.routes) != 0 {
		t.Fatalf("ran %q, table %v", table.ran, table.routes)
	}
	// With the device gone its routes went with it, and nothing is removed by
	// destination.
	table = &fakeTable{routes: prefixes("0.0.0.0/1")}
	table.steps().remove("utun9", []string{"0.0.0.0/1"})
	if len(table.ran) != 0 || len(table.routes) != 1 {
		t.Fatalf("ran %q, table %v", table.ran, table.routes)
	}
	if added, err := table.steps().add("utun9", []string{"0.0.0.0/1"}); err == nil || len(table.ran) != 0 || len(added) != 0 {
		t.Fatalf("a route was added for a device that isn't there: %v, %v", added, err)
	}
	odd := &fakeTable{routes: map[netip.Prefix]int{}}
	if added, err := odd.steps().add("utun7", []string{"0.0.0.0/1", "everything"}); err == nil || len(added) != 0 || len(odd.ran) != 0 {
		t.Fatalf("a route that isn't one was added: %v, %v", added, err)
	}
}

// A route that is still there after it was asked to go is said, so that it isn't
// taken for gone: it goes on sending what it covers into the tunnel.
func TestRouteStepsSayWhichRoutesTheyCouldNotGiveBack(t *testing.T) {
	both := []string{"0.0.0.0/1", "128.0.0.0/1"}
	held := func() map[netip.Prefix]int {
		return map[netip.Prefix]int{netip.MustParsePrefix("0.0.0.0/1"): ownIndex, netip.MustParsePrefix("128.0.0.0/1"): ownIndex}
	}
	t.Run("all of them go", func(t *testing.T) {
		table := &fakeTable{routes: held()}
		if left := table.steps().remove("utun7", both); len(left) != 0 || len(table.routes) != 0 {
			t.Fatalf("left %v, table %v", left, table.routes)
		}
	})
	t.Run("route says it failed", func(t *testing.T) {
		table := &fakeTable{routes: held(), stubborn: true}
		if left := table.steps().remove("utun7", both); !reflect.DeepEqual(left, both) || len(table.ran) != 2 {
			t.Fatalf("left %v, ran %q", left, table.ran)
		}
		// Asked again once it can, it removes them.
		table.stubborn = false
		if left := table.steps().remove("utun7", both); len(left) != 0 || len(table.routes) != 0 {
			t.Fatalf("left %v, table %v", left, table.routes)
		}
	})
	t.Run("route says nothing, and one is still there", func(t *testing.T) {
		table := &fakeTable{routes: held(), quiet: map[netip.Prefix]bool{netip.MustParsePrefix("128.0.0.0/1"): true}}
		if left := table.steps().remove("utun7", both); !reflect.DeepEqual(left, []string{"128.0.0.0/1"}) {
			t.Fatalf("left %v, table %v", left, table.routes)
		}
	})
	// With the table unreadable, what route reports is all there is to go by.
	t.Run("the table can't be read", func(t *testing.T) {
		table := &fakeTable{routes: held(), unreadable: true, stubborn: true}
		if left := table.steps().remove("utun7", both); !reflect.DeepEqual(left, both) {
			t.Fatalf("left %v", left)
		}
		table.stubborn = false
		if left := table.steps().remove("utun7", both); len(left) != 0 {
			t.Fatalf("left %v", left)
		}
	})
	// What isn't the device's any more isn't left behind by it, and neither is
	// anything once the device has gone.
	t.Run("nothing of the helper's", func(t *testing.T) {
		table := &fakeTable{routes: prefixes("0.0.0.0/1", "128.0.0.0/1"), stubborn: true}
		if left := table.steps().remove("utun7", both); len(left) != 0 || len(table.ran) != 0 {
			t.Fatalf("left %v, ran %q", left, table.ran)
		}
		if left := table.steps().remove("utun9", both); len(left) != 0 || len(table.ran) != 0 {
			t.Fatalf("with the device gone: left %v, ran %q", left, table.ran)
		}
	})
}
