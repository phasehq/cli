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

// emptyPathHint explains why a path filter matched nothing. Secrets are filtered
// by exact path, so secrets kept in folders are invisible at the default '/'.
// Returns "" when no path filter was applied, since every path was searched.
func emptyPathHint(path, verb string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("💡 No secrets found at path %s. Secrets under other paths are not included — pass %s to %s secrets from all paths.\n",
		util.BoldYellowErr(path), util.BoldErr(`--path ""`), verb)
}
