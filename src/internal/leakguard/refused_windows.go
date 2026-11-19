//go:build windows

package leakguard

import (
	"errors"

	"golang.org/x/sys/windows"
)

// connectionRefused reports a connection nothing accepted: no process
// listens at the address.
func connectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
