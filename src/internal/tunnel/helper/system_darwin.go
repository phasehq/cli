//go:build darwin

package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/phasehq/cli/internal/tunnel"
)

const (
	resolverDir    = "/etc/resolver"
	resolverMarker = "# Phase tunnel: removed when Phase steps aside"
)

// Darwin is the macOS system.
type Darwin struct{}

func run(steps ...[]string) error {
	for _, step := range steps {
		if output, err := exec.Command(step[0], step[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

// CheckRange reads the routing table of both families, and refuses when a route in
// it uses any of the ranges Phase uses for itself: the whole of the tunnel's range,
// the pool of addresses for Connection hosts included, and its IPv6 address.
func (Darwin) CheckRange() error {
	output, err := exec.Command("/usr/sbin/netstat", "-rn").Output()
	if err != nil {
		return nil
	}
	if used, line, found := rangeConflict(string(output)); found {
		return fmt.Errorf("%s, which Phase uses, is already routed (%s): another VPN or container network is using it", used, line)
	}
	return nil
}

func (Darwin) CreateDevice(mtu int) (tun.Device, string, error) {
	device, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, "", err
	}
	name, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	return device, name, nil
}

func (Darwin) Configure(device string) error {
	local := tunnel.LocalAddress.String()
	return run(
		[]string{"/sbin/ifconfig", device, "inet", local + "/32", local, "alias"},
		[]string{"/sbin/ifconfig", device, "inet6", tunnel.LocalAddress6.String() + "/128", "alias"},
		[]string{"/sbin/ifconfig", device, "up"},
		[]string{"/sbin/route", "-q", "-n", "add", "-inet", tunnel.TunnelPrefix.String(), "-interface", device},
	)
}

// darwinRoutes changes this machine's routes, and reads its routing table to see
// what each change did.
var darwinRoutes = routeSteps{
	index: func(device string) (int, error) {
		found, err := net.InterfaceByName(device)
		if err != nil {
			return 0, err
		}
		return found.Index, nil
	},
	leaves: routeInterface,
	run:    func(step ...string) error { return run(step) },
	name: func(index int) string {
		if found, err := net.InterfaceByIndex(index); err == nil {
			return found.Name
		}
		return ""
	},
}

func (Darwin) AddRoutes(device string, prefixes []string) ([]string, error) {
	return darwinRoutes.add(device, prefixes)
}

func (Darwin) RemoveRoutes(device string, prefixes []string) []string {
	return darwinRoutes.remove(device, prefixes)
}

// routeInterface finds the route for exactly this destination in the kernel's table,
// among the routes that aren't scoped to one interface, and returns the interface it
// leaves by. Reading the table needs no privileges and changes nothing.
func routeInterface(prefix netip.Prefix) (index int, found bool, err error) {
	prefix = prefix.Masked()
	family := syscall.AF_INET
	if prefix.Addr().Is6() {
		family = syscall.AF_INET6
	}
	rib, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, false, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, false, err
	}
	for _, message := range messages {
		entry, ok := message.(*route.RouteMessage)
		if !ok || entry.Flags&syscall.RTF_UP == 0 || entry.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		if listed, ok := routeDestination(entry); ok && listed == prefix {
			return entry.Index, true, nil
		}
	}
	return 0, false, nil
}

// routeDestination is where one entry of the table goes to. A host's entry has no
// mask, and is the address alone.
func routeDestination(entry *route.RouteMessage) (netip.Prefix, bool) {
	if len(entry.Addrs) <= syscall.RTAX_NETMASK {
		return netip.Prefix{}, false
	}
	var addr netip.Addr
	var mask []byte
	switch dest := entry.Addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		addr = netip.AddrFrom4(dest.IP)
		if found, ok := entry.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok {
			mask = found.IP[:]
		}
	case *route.Inet6Addr:
		addr = netip.AddrFrom16(dest.IP)
		if found, ok := entry.Addrs[syscall.RTAX_NETMASK].(*route.Inet6Addr); ok {
			mask = found.IP[:]
		}
	default:
		return netip.Prefix{}, false
	}
	bits := addr.BitLen()
	if entry.Flags&syscall.RTF_HOST == 0 {
		if mask == nil {
			return netip.Prefix{}, false
		}
		ones, size := net.IPMask(mask).Size()
		if size == 0 {
			// Not a run of ones followed by zeros: no destination a capture asks for.
			return netip.Prefix{}, false
		}
		bits = ones
	}
	prefix, err := addr.Prefix(bits)
	return prefix, err == nil
}

// InstallResolvers writes scoped resolver files. They sit beside other VPNs' DNS
// settings, and a longer domain match wins, so Tailscale keeps answering for
// everything else.
func (Darwin) InstallResolvers(domains []string) error {
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("%s\nnameserver %s\nport 53\ntimeout 2\n", resolverMarker, tunnel.DNSAddress)
	wanted := map[string]bool{}
	for _, domain := range domains {
		if strings.ContainsAny(domain, "/\\") || strings.HasPrefix(domain, ".") || domain == "" {
			continue
		}
		wanted[domain] = true
		path := filepath.Join(resolverDir, domain)
		if existing, err := os.ReadFile(path); err == nil && !strings.Contains(string(existing), resolverMarker) {
			return fmt.Errorf("%s already exists and isn't Phase's, so it was left alone", path)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	// Drop entries for domains no longer in the list.
	entries, _ := os.ReadDir(resolverDir)
	for _, entry := range entries {
		if wanted[entry.Name()] {
			continue
		}
		path := filepath.Join(resolverDir, entry.Name())
		if existing, err := os.ReadFile(path); err == nil && strings.Contains(string(existing), resolverMarker) {
			_ = os.Remove(path)
		}
	}
	return nil
}

func (Darwin) RemoveResolvers() {
	entries, err := os.ReadDir(resolverDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(resolverDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(content), resolverMarker) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
	}
	if remaining, err := os.ReadDir(resolverDir); err == nil && len(remaining) == 0 {
		_ = os.Remove(resolverDir)
	}
}

func (Darwin) FlushDNS() {
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// PinPhysical gives the interface holding the system's default route a default route
// of its own scope. The capture routes share the default route's key, and without one
// a socket pinned to that interface finds no route at all: "network is unreachable".
func (Darwin) PinPhysical() (string, func(), error) {
	name, index := tunnel.DefaultRouteInterface()
	if index == 0 {
		return "", func() {}, errors.New("there's no default route")
	}
	var gateway netip.Addr
	for _, found := range tunnel.DefaultRoutes() {
		if found.Index != index {
			continue
		}
		if found.Scoped {
			return name, func() {}, nil
		}
		gateway = found.Gateway
	}
	if !gateway.IsValid() {
		return name, func() {}, nil
	}
	if err := run([]string{"/sbin/route", "-q", "-n", "add", "-inet", "-ifscope", name, "default", gateway.String()}); err != nil {
		return "", func() {}, err
	}
	return name, func() {
		// Only while the interface still holds the system's default route. Otherwise
		// the system has put in its own scoped default, which isn't Phase's to remove.
		if current, _ := tunnel.DefaultRouteInterface(); current == name {
			_ = exec.Command("/sbin/route", "-q", "-n", "delete", "-inet", "-ifscope", name, "default", gateway.String()).Run()
		}
	}, nil
}

// Default is this machine's system.
func Default() System { return Darwin{} }
