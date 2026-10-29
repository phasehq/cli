package version

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Version is the CLI version. Override via -ldflags at build time.
var Version = "dev"

type developmentBuildIdentity struct {
	revision       string
	modified       bool
	executableTime time.Time
	executableSize int64
}

func init() {
	Version = resolveVersion(Version, currentDevelopmentBuildIdentity())
}

func currentDevelopmentBuildIdentity() developmentBuildIdentity {
	// Without an explicit clean VCS setting, conservatively treat the build as
	// modified so separately installed development binaries cannot all collapse
	// to the same "dev" runtime identity.
	identity := developmentBuildIdentity{modified: true}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				identity.revision = strings.TrimSpace(setting.Value)
			case "vcs.modified":
				identity.modified = !strings.EqualFold(strings.TrimSpace(setting.Value), "false")
			}
		}
	}
	if executable, err := os.Executable(); err == nil {
		if info, statErr := os.Stat(executable); statErr == nil && info.Mode().IsRegular() {
			identity.executableTime = info.ModTime().UTC()
			identity.executableSize = info.Size()
		}
	}
	return identity
}

func resolveVersion(configured string, identity developmentBuildIdentity) string {
	// GoReleaser supplies the release version with -ldflags. Never decorate or
	// otherwise alter that public version string.
	if configured != "dev" {
		return configured
	}

	revision := strings.TrimSpace(identity.revision)
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision == "" {
		revision = "unknown"
	} else {
		revision = "g" + revision
	}
	resolved := configured + "+" + revision
	if !identity.modified {
		return resolved
	}

	resolved += ".dirty"
	if identity.executableTime.IsZero() || identity.executableSize < 0 {
		return resolved
	}
	// A development hook binary is copied atomically into each harness plugin.
	// Its mtime and size are stable for that installed binary, but change when a
	// later dirty build is copied over it. This lets a new hook replace an older
	// daemon even when both builds come from the same Git revision.
	stamp := identity.executableTime.UTC().Format("20060102T150405.000000000Z")
	return resolved + "." + stamp + "." + strconv.FormatInt(identity.executableSize, 10)
}
