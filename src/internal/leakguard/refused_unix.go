//go:build !windows

package leakguard

import (
	"errors"
	"syscall"
)

// connectionRefused reports a connection nothing accepted: no process
// listens at the address.
func connectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
