//go:build !darwin

package helper

import "net"

// peerAllowed relies on the socket's permissions here.
func peerAllowed(net.Conn, int) bool { return true }
