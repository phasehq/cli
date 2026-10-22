package version

import (
	"strings"
	"testing"
	"time"
)

func TestResolveVersionPreservesLinkerSuppliedRelease(t *testing.T) {
	identity := developmentBuildIdentity{
		revision:       "0123456789abcdef",
		modified:       true,
		executableTime: time.Date(2026, time.August, 10, 8, 0, 0, 0, time.UTC),
		executableSize: 42,
	}
	if got := resolveVersion("2.66.1", identity); got != "2.66.1" {
		t.Fatalf("release version = %q, want linker-supplied value", got)
	}
}

func TestResolveVersionUsesGitRevisionForCleanDevelopmentBuild(t *testing.T) {
	identity := developmentBuildIdentity{
		revision:       "0123456789abcdef",
		modified:       false,
		executableTime: time.Date(2026, time.August, 10, 8, 0, 0, 0, time.UTC),
		executableSize: 42,
	}
	if got := resolveVersion("dev", identity); got != "dev+g0123456789ab" {
		t.Fatalf("clean development version = %q", got)
	}
}

func TestResolveVersionDistinguishesSuccessiveDirtyExecutableCopies(t *testing.T) {
	first := developmentBuildIdentity{
		revision:       "0123456789abcdef",
		modified:       true,
		executableTime: time.Date(2026, time.August, 10, 8, 0, 0, 1, time.UTC),
		executableSize: 42,
	}
	second := first
	second.executableTime = second.executableTime.Add(time.Nanosecond)

	firstVersion := resolveVersion("dev", first)
	secondVersion := resolveVersion("dev", second)
	if firstVersion == secondVersion {
		t.Fatalf("successive dirty executable copies share version %q", firstVersion)
	}
	for _, got := range []string{firstVersion, secondVersion} {
		if !strings.HasPrefix(got, "dev+g0123456789ab.dirty.") || !strings.HasSuffix(got, ".42") {
			t.Fatalf("dirty development version = %q", got)
		}
	}
}

func TestResolveVersionUsesExecutableIdentityWithoutVCSMetadata(t *testing.T) {
	identity := developmentBuildIdentity{
		modified:       true,
		executableTime: time.Date(2026, time.August, 10, 8, 0, 0, 0, time.UTC),
		executableSize: 42,
	}
	got := resolveVersion("dev", identity)
	if !strings.HasPrefix(got, "dev+unknown.dirty.") || !strings.HasSuffix(got, ".42") {
		t.Fatalf("development version without VCS metadata = %q", got)
	}
}

func TestResolveVersionFailsStableWhenExecutableIdentityUnavailable(t *testing.T) {
	identity := developmentBuildIdentity{revision: "0123456789abcdef", modified: true}
	if got := resolveVersion("dev", identity); got != "dev+g0123456789ab.dirty" {
		t.Fatalf("development version without executable identity = %q", got)
	}
}
