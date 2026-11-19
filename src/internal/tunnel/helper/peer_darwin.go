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

// peerPID is the process on the other end of the socket, or 0 when the system can't
// say. It's for telling the user what is attached, and decides nothing here.
func peerPID(conn net.Conn) int {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) {
		if found, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil && found > 0 {
			pid = found
		}
	})
	return pid
}
