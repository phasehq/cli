//go:build !linux

package proxy

import (
	"fmt"
	"net"
)

// originalDst is Linux-only (SO_ORIGINAL_DST). Transparent redirect isn't
// supported off Linux, so this always errors; the explicit-proxy (CONNECT) path
// — the cross-platform default — never calls it.
func originalDst(_ *net.TCPConn) (string, error) {
	return "", fmt.Errorf("SO_ORIGINAL_DST not supported on this OS")
}
