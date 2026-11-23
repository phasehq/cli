//go:build !darwin

package helper

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// ErrUnsupported means this system doesn't have a helper yet.
var ErrUnsupported = errors.New("phase up is only available on macOS for now")

type unsupported struct{}

func (unsupported) CheckRange() error                            { return ErrUnsupported }
func (unsupported) CreateDevice(int) (tun.Device, string, error) { return nil, "", ErrUnsupported }
func (unsupported) Configure(string) error                       { return ErrUnsupported }
func (unsupported) AddRoutes(string, []string) ([]string, error) { return nil, ErrUnsupported }
func (unsupported) RemoveRoutes(string, []string) []string       { return nil }
func (unsupported) InstallResolvers([]string) ([]string, error)  { return nil, ErrUnsupported }
func (unsupported) RemoveResolvers()                             {}
func (unsupported) FlushDNS()                                    {}
func (unsupported) PinPhysical() (string, func(), error)         { return "", func() {}, ErrUnsupported }

// Default is this machine's system.
func Default() System { return unsupported{} }
