package helper

import "golang.zx2c4.com/wireguard/tun"

// System is everything the helper changes on the machine. It's an interface so the
// rules about when to change it can be tested without root.
type System interface {
	// CheckRange refuses to start if something else already routes the tunnel's range.
	CheckRange() error
	// CreateDevice opens a tunnel device.
	CreateDevice(mtu int) (tun.Device, string, error)
	// Configure gives the device its addresses, and routes the tunnel's own range to it.
	Configure(device string) error
	// AddRoutes and RemoveRoutes take and give back the capture routes.
	AddRoutes(device string, prefixes []string) error
	RemoveRoutes(device string, prefixes []string)
	// InstallResolvers sends DNS for exactly these domains to the tunnel.
	InstallResolvers(domains []string) error
	// RemoveResolvers removes only what InstallResolvers wrote.
	RemoveResolvers()
	FlushDNS()
	// PinPhysical makes sure a socket pinned to the physical interface still has a way
	// out once the capture routes exist, and returns how to undo whatever it changed.
	PinPhysical() (pinned string, undo func(), err error)
}
