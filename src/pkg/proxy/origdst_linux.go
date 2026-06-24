//go:build linux

package proxy

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// soOriginalDst is SO_ORIGINAL_DST for IPv4 (recover the pre-REDIRECT destination).
const soOriginalDst = 80

// originalDst recovers the pre-REDIRECT destination of a locally-redirected
// connection via getsockopt(SO_ORIGINAL_DST). IPv4 only.
func originalDst(c *net.TCPConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var dst string
	var sockErr error
	if cerr := raw.Control(func(fd uintptr) {
		mreq, e := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, soOriginalDst)
		if e != nil {
			sockErr = e
			return
		}
		// mreq.Multiaddr holds a sockaddr_in: [0:2]=family, [2:4]=port(BE), [4:8]=IPv4.
		ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
		port := int(mreq.Multiaddr[2])<<8 | int(mreq.Multiaddr[3])
		dst = net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	}); cerr != nil {
		return "", cerr
	}
	if sockErr != nil {
		return "", sockErr
	}
	return dst, nil
}
