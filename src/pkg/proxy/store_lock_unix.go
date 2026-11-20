//go:build !windows

package proxy

import (
	"errors"
	"os"
	"syscall"
)

// lockCAFile blocks until this process holds the exclusive lock on path.
func lockCAFile(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() { _ = file.Close() }, nil
}

// tryLockFile takes the exclusive lock on path when no one holds it, and
// reports busy when someone does. It never waits.
func tryLockFile(path string) (unlock func(), busy bool, err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { _ = file.Close() }, false, nil
}
