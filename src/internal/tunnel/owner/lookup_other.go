//go:build !darwin

package owner

import (
	"context"
	"net/netip"
)

// Lookup isn't available here yet, so every flow is left unread.
func Lookup(context.Context, int, netip.AddrPort) (Process, error) {
	return Process{}, ErrUnsupported
}
