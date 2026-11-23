//go:build darwin

package helper

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

// The kernel's own table is read, which needs no privileges and changes nothing.
// Every Mac routes loopback by lo0.
func TestRouteInterfaceReadsTheKernelsTable(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("no lo0 here")
	}
	for _, destination := range []string{"127.0.0.0/8", "127.0.0.1/32", "::1/128"} {
		index, found, err := routeInterface(netip.MustParsePrefix(destination))
		if err != nil || !found || index != loopback.Index {
			t.Errorf("%s: interface %d (found %v, %v), want lo0, %d", destination, index, found, err, loopback.Index)
		}
	}
	// A destination is found only as it is written in the table: a part of a route,
	// or more than it, is another destination.
	for _, destination := range []string{"127.0.0.0/9", "126.0.0.0/7", "203.0.113.128/25", "2001:db8:7068:6173::/64"} {
		if index, found, err := routeInterface(netip.MustParsePrefix(destination)); err != nil || found {
			t.Errorf("%s: found by interface %d (%v)", destination, index, err)
		}
	}
}

func TestRouteDestination(t *testing.T) {
	inet4 := func(a, b, c, d byte) *route.Inet4Addr { return &route.Inet4Addr{IP: [4]byte{a, b, c, d}} }
	entry := func(flags int, addrs ...route.Addr) *route.RouteMessage {
		padded := make([]route.Addr, syscall.RTAX_MAX)
		copy(padded, addrs)
		return &route.RouteMessage{Flags: flags | syscall.RTF_UP, Addrs: padded}
	}
	inet6 := func(text string) *route.Inet6Addr { return &route.Inet6Addr{IP: netip.MustParseAddr(text).As16()} }
	for want, message := range map[string]*route.RouteMessage{
		"0.0.0.0/1":             entry(0, inet4(0, 0, 0, 0), nil, inet4(128, 0, 0, 0)),
		"128.0.0.0/1":           entry(0, inet4(128, 0, 0, 0), nil, inet4(128, 0, 0, 0)),
		"0.0.0.0/0":             entry(0, inet4(0, 0, 0, 0), nil, inet4(0, 0, 0, 0)),
		"198.19.248.0/22":       entry(0, inet4(198, 19, 248, 0), nil, inet4(255, 255, 252, 0)),
		"192.168.1.7/32":        entry(syscall.RTF_HOST, inet4(192, 168, 1, 7)),
		"8000::/1":              entry(0, inet6("8000::"), nil, inet6("8000::")),
		"fd70:7068:6173::1/128": entry(syscall.RTF_HOST, inet6("fd70:7068:6173::1")),
		"fd7a:115c:a1e0::/48":   entry(0, inet6("fd7a:115c:a1e0::"), nil, inet6("ffff:ffff:ffff::")),
	} {
		got, ok := routeDestination(message)
		if !ok || got.String() != want {
			t.Errorf("read %v (%v), want %s", got, ok, want)
		}
	}
	for name, message := range map[string]*route.RouteMessage{
		"a network with no mask":      entry(0, inet4(10, 0, 0, 0)),
		"a mask with a hole in it":    entry(0, inet4(10, 0, 0, 0), nil, inet4(255, 0, 255, 0)),
		"a link-layer destination":    entry(0, &route.LinkAddr{Index: 4}),
		"a message with no addresses": {Flags: syscall.RTF_UP},
		"a mask of the other family":  entry(0, inet4(10, 0, 0, 0), nil, inet6("ffff::")),
	} {
		if got, ok := routeDestination(message); ok {
			t.Errorf("%s was read as %s", name, got)
		}
	}
}

// The entries are read back from the directory, so what is reported is what is
// there: the ones written before an entry of someone else's stopped the rest, and any
// of Phase's that were there already.
func TestInstallResolversReportsTheEntriesInPlace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "resolver")
	if err := installResolvers(dir, []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := phaseResolvers(dir); !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("in place: %v", got)
	}
	// Another VPN's entry for a name Phase is asked to take.
	theirs := filepath.Join(dir, "c.example.com")
	if err := os.WriteFile(theirs, []byte("nameserver 10.8.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := installResolvers(dir, []string{"a.example.com", "c.example.com", "d.example.com"})
	if err == nil || !strings.Contains(err.Error(), "c.example.com already exists and isn't Phase's") {
		t.Fatalf("writing over another VPN's entry: %v", err)
	}
	if got := phaseResolvers(dir); !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("in place after stopping at another VPN's entry: %v", got)
	}
	if content, _ := os.ReadFile(theirs); string(content) != "nameserver 10.8.0.53\n" {
		t.Fatalf("another VPN's entry was changed: %q", content)
	}
	// A list that can be written whole drops Phase's entries for every other name.
	if err := installResolvers(dir, []string{"d.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := phaseResolvers(dir); !reflect.DeepEqual(got, []string{"d.example.com"}) {
		t.Fatalf("in place: %v", got)
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("another VPN's entry was removed: %v", err)
	}
	if got := phaseResolvers(filepath.Join(dir, "none")); len(got) != 0 {
		t.Fatalf("a directory that isn't there holds %v", got)
	}
}

// sudo runs the program as root, and the helper is copied in from it, so a program
// that anyone but root and this user could replace is refused.
func TestCheckInstallSourceRefusesAProgramOthersCanChange(t *testing.T) {
	setup := func(t *testing.T, folderMode, fileMode os.FileMode) string {
		t.Helper()
		folder := filepath.Join(t.TempDir(), "bin")
		if err := os.Mkdir(folder, 0o755); err != nil {
			t.Fatal(err)
		}
		program := filepath.Join(folder, "phase")
		if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(program, fileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(folder, folderMode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(folder, 0o755) })
		return program
	}
	if err := CheckInstallSource(setup(t, 0o755, 0o755)); err != nil {
		t.Fatalf("a program only its owner can change was refused: %v", err)
	}
	for name, modes := range map[string][2]os.FileMode{
		"a program its group can change":       {0o755, 0o775},
		"a program anyone can change":          {0o755, 0o757},
		"a folder its group can change":        {0o775, 0o755},
		"a folder anyone can change":           {0o757, 0o755},
		"a folder anyone can add to, stickily": {0o755 | os.ModeSticky | 0o002, 0o755},
	} {
		t.Run(name, func(t *testing.T) {
			program := setup(t, modes[0], modes[1])
			err := CheckInstallSource(program)
			if err == nil || !strings.Contains(err.Error(), "chmod go-w") {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("a link to a program others can change", func(t *testing.T) {
		target := setup(t, 0o755, 0o777)
		link := filepath.Join(t.TempDir(), "phase")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := CheckInstallSource(link); err == nil || !strings.Contains(err.Error(), target) {
			t.Fatalf("got %v", err)
		}
	})
}
