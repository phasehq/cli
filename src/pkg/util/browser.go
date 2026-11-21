package util

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

func OpenBrowser(target string) error {
	name, args, err := browserCommand(runtime.GOOS, target)
	if err != nil {
		return err
	}
	return exec.Command(name, args...).Start()
}

// browserCommand returns the program that opens target on goos. Windows uses
// the URL protocol handler directly: cmd.exe would read & and | in the URL as
// command separators.
func browserCommand(goos, target string) (string, []string, error) {
	if err := validateBrowserURL(target); err != nil {
		return "", nil, err
	}
	switch goos {
	case "darwin":
		return "open", []string{target}, nil
	case "linux":
		return "xdg-open", []string{target}, nil
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", target}, nil
	default:
		return "", nil, fmt.Errorf("unsupported platform: %s", goos)
	}
}

// validateBrowserURL accepts only an absolute http or https URL with a host
// and no spaces, quotes or control characters, so the opener never reads it
// as a file, a flag or more than one argument.
func validateBrowserURL(target string) error {
	if strings.ContainsAny(target, " \t\r\n\"'`^<>|\\") {
		return fmt.Errorf("refusing to open an unsafe URL: %q", target)
	}
	for _, r := range target {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("refusing to open an unsafe URL: %q", target)
		}
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("refusing to open a URL that is not http or https: %q", target)
	}
	return nil
}
