//go:build darwin

package helper

import (
	"errors"
	"fmt"
	"io/fs"

	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func (Darwin) CheckRange() error {
	output, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil
	}
	prefix := strings.Join(strings.Split(tunnel.TunnelPrefix.Addr().String(), ".")[:3], ".")
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], prefix) {
			return fmt.Errorf("%s is already routed (%s): another VPN or container network is using it", tunnel.TunnelPrefix, strings.Join(fields, " "))
		}
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

func familyFlag(prefix string) string {
	if strings.Contains(prefix, ":") {
		return "-inet6"
	}
	return "-inet"
}

func (Darwin) AddRoutes(device string, prefixes []string) error {
	steps := make([][]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		steps = append(steps, []string{"/sbin/route", "-q", "-n", "add", familyFlag(prefix), prefix, "-interface", device})
	}
	return run(steps...)
}

func (Darwin) RemoveRoutes(device string, prefixes []string) {
	for _, prefix := range prefixes {
		_ = exec.Command("/sbin/route", "-q", "-n", "delete", familyFlag(prefix), prefix, "-interface", device).Run()
	}
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
