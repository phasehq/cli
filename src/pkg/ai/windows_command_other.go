//go:build !windows

package ai

import "errors"

// windowsShortPathName exists only on Windows.
func windowsShortPathName(string) (string, error) {
	return "", errors.New("short path names exist only on Windows")
}
