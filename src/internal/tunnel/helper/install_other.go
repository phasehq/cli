//go:build !darwin

package helper

// The helper isn't available here yet.
const (
	InstalledPath = ""
	SocketPath    = ""
	LogPath       = ""
)

// Supported reports whether this system has a helper.
func Supported() bool { return false }

func Install(int) error { return ErrUnsupported }
func Uninstall() error  { return ErrUnsupported }
func Installed() bool   { return false }
