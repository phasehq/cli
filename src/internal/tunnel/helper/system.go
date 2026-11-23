package helper

import "golang.zx2c4.com/wireguard/tun"

// System is everything the helper changes on the machine. It's an interface so the
// rules about when to change it can be tested without root.
type System interface {
	// CheckRange refuses to start if something else already routes one of the ranges
	// Phase uses for itself.
	CheckRange() error
	// CreateDevice opens a tunnel device.
	CreateDevice(mtu int) (tun.Device, string, error)
	// Configure gives the device its addresses, and routes the tunnel's own range to it.
	Configure(device string) error
	// AddRoutes takes capture routes, and returns the ones it added: fewer than it
	// was asked for when one can't be added. It never replaces a route that is
	// already there. RemoveRoutes gives back routes that AddRoutes added, and returns
	// the ones it couldn't: those are still in place. The helper never asks it for a
	// route AddRoutes didn't add, because the system removes a route by where it goes
	// to, whoever put it there.
	AddRoutes(device string, prefixes []string) (added []string, err error)
	RemoveRoutes(device string, prefixes []string) (left []string)
	// InstallResolvers sends DNS for exactly these domains to the tunnel. It returns
	// the domains that are sent there once it is done, which are fewer than it was
	// asked for when it fails part of the way.
	InstallResolvers(domains []string) (installed []string, err error)
	// RemoveResolvers removes only what InstallResolvers wrote.
	RemoveResolvers()
	FlushDNS()
	// PinPhysical makes sure a socket pinned to the physical interface still has a way
	// out once the capture routes exist, and returns how to undo whatever it changed.
	PinPhysical() (pinned string, undo func(), err error)
}
