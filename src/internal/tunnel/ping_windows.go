//go:build windows

package tunnel

import "net/netip"

// PingOnce isn't supported here, so pings get no reply rather than a false one.
func PingOnce(netip.Addr, uint16, []byte) bool { return false }
