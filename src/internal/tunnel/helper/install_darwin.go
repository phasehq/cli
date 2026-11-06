//go:build darwin

package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Where the helper lives once installed. Everything is owned by root, so the user
// can't swap the program that runs with root's privileges.
const (
	Label         = "dev.phase.tunnel"
	InstalledPath = "/Library/PrivilegedHelperTools/dev.phase.tunnel"
	PlistPath     = "/Library/LaunchDaemons/dev.phase.tunnel.plist"
	SocketPath    = "/var/run/dev.phase.tunnel.sock"
	LogPath       = "/Library/Logs/dev.phase.tunnel.log"
)

// Supported reports whether this system has a helper.
func Supported() bool { return true }

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>tunnel</string>
		<string>helper</string>
		<string>--uid</string>
		<string>%d</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

// Install copies the running program into place and starts it at boot. It runs as root.
func Install(uid int) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the helper needs root")
	}
	if uid <= 0 {
		return errors.New("the helper needs the user it serves")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+Label).Run()
	if err := copyExecutable(self, InstalledPath); err != nil {
		return fmt.Errorf("copy the helper into place: %w", err)
	}
	plist := fmt.Sprintf(plistTemplate, Label, InstalledPath, uid, LogPath, LogPath)
	if err := writeRootFile(PlistPath, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write the helper's launch settings: %w", err)
	}
	if output, err := exec.Command("/bin/launchctl", "bootstrap", "system", PlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("start the helper: %w: %s", err, strings.TrimSpace(string(output)))
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(SocketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the helper didn't start; see %s", LogPath)
}

// Uninstall stops the helper and removes it. It runs as root.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("removing the helper needs root")
	}
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+Label).Run()
	for _, path := range []string{PlistPath, InstalledPath, SocketPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Installed reports whether the helper's files are in place.
func Installed() bool {
	_, err := os.Stat(PlistPath)
	return err == nil
}

func copyExecutable(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	temporary := target + ".new." + strconv.Itoa(os.Getpid())
	out, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(temporary)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Chown(temporary, 0, 0); err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, target)
}

func writeRootFile(path string, content []byte, mode os.FileMode) error {
	temporary := path + ".new." + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chown(temporary, 0, 0); err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}
