//go:build !darwin && !linux

package tunnel

import "errors"

// DefaultRouteInterface isn't known here, which leaves pinning off.
func DefaultRouteInterface() (string, int) { return "", 0 }

// defaultRouteGateway isn't known here either.
func defaultRouteGateway() string { return "" }

func bindSocket(int, bool, string, int) error {
	return errors.New("pinning a socket to an interface isn't supported on this system")
}
