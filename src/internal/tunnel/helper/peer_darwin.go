//go:build darwin

package helper

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerAllowed checks who is on the other end of the socket, as well as the socket's
// own permissions.
func peerAllowed(conn net.Conn, uid int) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		allowed = err == nil && (int(cred.Uid) == uid || cred.Uid == 0)
	})
	return allowed
}
