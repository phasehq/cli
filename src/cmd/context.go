package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// contextNames returns the application and environment names to display for a
// fetch. They are read off the returned secrets when possible, and resolved
// from the account's app list when the fetch came back empty — otherwise a
// path that matches no secrets would report a blank app and environment and
// look like a broken .phase.json.
func contextNames(p *sdk.Phase, secrets []sdk.SecretResult, appName, envName, appID string) (string, string) {
	apps := map[string]bool{}
	envs := map[string]bool{}
	for _, s := range secrets {
		if s.Application != "" {
			apps[s.Application] = true
		}
		if s.Environment != "" {
			envs[s.Environment] = true
		}
	}
	if len(apps) > 0 && len(envs) > 0 {
		return strings.Join(mapKeys(apps), ", "), strings.Join(mapKeys(envs), ", ")
	}
	return phase.ResolveNames(p, appName, envName, appID)
}

// emptyResultHint explains why a fetch matched nothing. Secrets are filtered by
// exact path, so secrets kept in folders are invisible at the default '/'; a
// --tags filter can also empty the result, in which case suggesting a broader
// path alone would misdirect. Returns "" when neither filter was applied —
// the environment is then genuinely empty and there is nothing to suggest.
// Set forStdout when the hint is printed to stdout so ANSI styling is gated on
// the right stream.
func emptyResultHint(path, tags, verb string, forStdout bool) string {
	bold, yellow := util.BoldErr, util.BoldYellowErr
	if forStdout {
		bold, yellow = util.Bold, util.BoldYellow
	}
	switch {
	case tags != "" && path != "":
		return fmt.Sprintf("💡 No secrets matched tag filter %s at path %s. Adjust %s, or pass %s to %s secrets from all paths.\n",
			yellow(tags), yellow(path), bold("--tags"), bold(`--path ""`), verb)
	case tags != "":
		return fmt.Sprintf("💡 No secrets matched tag filter %s. Adjust or drop %s to %s all secrets.\n",
			yellow(tags), bold("--tags"), verb)
	case path != "":
		return fmt.Sprintf("💡 No secrets found at path %s. Secrets under other paths are not included — pass %s to %s secrets from all paths.\n",
			yellow(path), bold(`--path ""`), verb)
	default:
		return ""
	}
}
