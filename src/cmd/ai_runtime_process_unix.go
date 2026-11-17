//go:build !windows

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func configureDetachedProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func stopRuntimeProcessGracefully(_ context.Context, process *os.Process, _ hookRuntimeState) error {
	return process.Signal(os.Interrupt)
}

func processIsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return (err == nil || errors.Is(err, syscall.EPERM)) && !processIsZombie(pid)
}

// processIsZombie reports an exited process that its parent has not reaped,
// which a non-reaping container init keeps forever; kill(pid, 0) still
// succeeds for it. Only Linux exposes the state here, so elsewhere the hook
// reaps the daemon it starts.
func processIsZombie(pid int) bool {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state follows the command name, which may itself contain ") ".
	end := bytes.LastIndexByte(stat, ')')
	return end >= 0 && end+2 < len(stat) && (stat[end+2] == 'Z' || stat[end+2] == 'X')
}

func openRuntimeEnvironmentFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("Phase AI environment file must be a regular non-symlink file")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("Phase AI environment file must be a regular non-symlink file")
	}
	return file, nil
}

func tryLockLeaseFile(path string) (*os.File, bool, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, false, errors.New("Phase AI session lease lock must be a regular non-symlink file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, nil
		}
		return nil, false, err
	}
	// removeHeldLockFile unlinks a lock file while holding it. A process that
	// opened the old file before the unlink now holds a lock nobody else can
	// reach, so it must see that the path no longer names its file and retry.
	if current, err := os.Lstat(path); err != nil || !os.SameFile(info, current) {
		_ = file.Close()
		return nil, false, nil
	}
	return file, true, nil
}

// removeHeldLockFile deletes a lock file, and the files it guards, only while
// holding its lock, so no process can hold a lock on a file that has left the
// directory. A lock held by someone else is left alone, with its files.
func removeHeldLockFile(path string, guarded ...string) error {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	file, acquired, err := tryLockLeaseFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && !acquired) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlockLeaseFile(file)
	var errs []error
	for _, name := range append(guarded, path) {
		if info, err := os.Lstat(name); err == nil && !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func unlockLeaseFile(file *os.File) error {
	if file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func openOwnerOnlyFile(path string) (*os.File, error) {
	return os.Open(path)
}
