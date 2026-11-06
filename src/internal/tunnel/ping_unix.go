//go:build !windows

package tunnel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// PingOnce asks the real destination, using the unprivileged ICMP socket.
func PingOnce(dest netip.Addr, sequence uint16, payload []byte) bool {
	family, protocol, request, reply := syscall.AF_INET, syscall.IPPROTO_ICMP, byte(8), byte(0)
	if dest.Is6() {
		family, protocol, request, reply = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, 128, 129
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, protocol)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	pinned := Physical.Bind(netip.AddrPortFrom(dest, 0).String(), func(ipv6 bool, name string, index int) error {
		return bindSocket(fd, ipv6, name, index)
	})
	if pinned != nil {
		return false
	}
	timeout := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	message := make([]byte, 8+len(payload))
	message[0] = request
	binary.BigEndian.PutUint16(message[4:], uint16(os.Getpid()))
	binary.BigEndian.PutUint16(message[6:], sequence)
	copy(message[8:], payload)
	var target syscall.Sockaddr
	if dest.Is4() {
		binary.BigEndian.PutUint16(message[2:], InternetChecksum(message))
		target = &syscall.SockaddrInet4{Addr: dest.As4()}
	} else {
		target = &syscall.SockaddrInet6{Addr: dest.As16()}
	}
	if err := syscall.Sendto(fd, message, 0, target); err != nil {
		return false
	}
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return false
		}
		got := buf[:n]
		// Darwin includes the IPv4 header, and Linux doesn't.
		if dest.Is4() && len(got) > 20 && got[0]>>4 == 4 {
			got = got[int(got[0]&0x0f)*4:]
		}
		if len(got) < 8 || got[0] != reply || binary.BigEndian.Uint16(got[6:]) != sequence {
			continue
		}
		switch source := from.(type) {
		case *syscall.SockaddrInet4:
			if netip.AddrFrom4(source.Addr) == dest {
				return true
			}
		case *syscall.SockaddrInet6:
			if netip.AddrFrom16(source.Addr) == dest {
				return true
			}
		}
	}
	return false
}
