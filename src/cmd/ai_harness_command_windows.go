//go:build windows

package cmd

import "syscall"

// windowsShortPathName returns the 8.3 short form of an existing path. It has
// no spaces when the volume keeps short names, so harness wrapper commands can
// name the hook executable without quoting.
func windowsShortPathName(path string) (string, error) {
	long, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, syscall.MAX_PATH)
	for {
		length, err := syscall.GetShortPathName(long, &buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length]), nil
		}
		buffer = make([]uint16, length)
	}
}
