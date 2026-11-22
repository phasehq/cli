//go:build !windows

package proxy

import (
	"errors"
	"os"
	"syscall"
)

// openInventoryFile opens the inventory file without following a symlink,
// and refuses one that is not this user's or that others may read or write.
func openInventoryFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, errors.New("the leak protection inventory must not be a symlink")
		}
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || int(stat.Uid) != os.Getuid() {
		_ = file.Close()
		return nil, errors.New("the leak protection inventory must be a regular owner-only file of this user")
	}
	return file, nil
}
