//go:build !darwin

package helper

import "net"

// peerAllowed relies on the socket's permissions here.
func peerAllowed(net.Conn, int) bool { return true }

// peerPID isn't known here.
func peerPID(net.Conn) int { return 0 }
