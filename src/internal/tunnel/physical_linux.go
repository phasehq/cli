//go:build linux

package tunnel

import (
	"net"
	"os/exec"
	"regexp"

	"golang.org/x/sys/unix"
)

// DefaultRouteInterface is the interface of the default route.
func DefaultRouteInterface() (string, int) {
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", 0
	}
	match := regexp.MustCompile(`dev (\S+)`).FindSubmatch(output)
	if match == nil {
		return "", 0
	}
	iface, err := net.InterfaceByName(string(match[1]))
	if err != nil {
		return "", 0
	}
	return iface.Name, iface.Index
}

func bindSocket(fd int, _ bool, name string, _ int) error {
	return unix.BindToDevice(fd, name)
}
