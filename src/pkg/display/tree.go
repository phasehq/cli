package display

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
)

var (
	// Simplified patterns for display icons only (Go doesn't support lookaheads)
	crossEnvPattern = regexp.MustCompile(`\$\{[^}]*\.[^}]+\}`)
	localRefPattern = regexp.MustCompile(`\$\{[^}.]+\}`)
)

func getTerminalWidth() int {
	// Simple approach - just return 80 for portability
	return 80
}

func censorSecret(secret string, maxLength int) string {
	if len(secret) <= 6 {
		return strings.Repeat("*", len(secret))
	}
	censored := secret[:3] + strings.Repeat("*", len(secret)-6) + secret[len(secret)-3:]
	if len(censored) > maxLength && maxLength > 6 {
		return censored[:maxLength-6]
	}
	return censored
}

// renderSecretRow renders a single secret row into the table.
func renderSecretRow(pathPrefix string, s phase.SecretResult, show bool, keyWidth, valueWidth int, bold, reset string) {
	keyDisplay := s.Key
	if len(s.Tags) > 0 {
		keyDisplay += " 🏷️"
	}
	if s.Comment != "" {
		keyDisplay += " 💬"
	}

	icon := ""
	if crossEnvPattern.MatchString(s.Value) {
		icon += "⛓️  "
	}
	if localRefPattern.MatchString(s.Value) {
		icon += "🔗 "
	}

	personalIndicator := ""
	if s.Overridden {
		personalIndicator = "🔏 "
	}

	var valueDisplay string
	if s.IsDynamic && !show {
		valueDisplay = "****************"
	} else if show {
		valueDisplay = s.Value
	} else {
		censorLen := valueWidth - len(icon) - len(personalIndicator) - 2
		if censorLen < 6 {
			censorLen = 6
		}
		valueDisplay = censorSecret(s.Value, censorLen)
	}
	valueDisplay = icon + personalIndicator + valueDisplay

	// Truncate if needed
	if len(keyDisplay) > keyWidth {
		keyDisplay = keyDisplay[:keyWidth-1] + "…"
	}
	if len(valueDisplay) > valueWidth {
		valueDisplay = valueDisplay[:valueWidth-1] + "…"
	}

	fmt.Fprintf(os.Stdout, "  %s   │ %-*s│ %-*s│\n",
		pathPrefix, keyWidth, keyDisplay, valueWidth, valueDisplay)
}

// RenderSecretsTree renders secrets in a tree view with path hierarchy
func RenderSecretsTree(secrets []phase.SecretResult, show bool) {
	if len(secrets) == 0 {
		fmt.Println("No secrets to display.")
		return
	}

	appName := secrets[0].Application
	envName := secrets[0].Environment

	bold, cyan, green, magenta, reset := util.AnsiCodes()

	fmt.Printf("  %s Secrets for Application: %s%s%s%s, Environment: %s%s%s%s\n",
		"🔮", bold, cyan, appName, reset, bold, green, envName, reset)

	// Organize by path
	paths := map[string][]phase.SecretResult{}
	for _, s := range secrets {
		path := s.Path
		if path == "" {
			path = "/"
		}
		paths[path] = append(paths[path], s)
	}

	// Sort paths
	var sortedPaths []string
	for p := range paths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	termWidth := getTerminalWidth()
	isLastPath := false

	for pi, path := range sortedPaths {
		pathSecrets := paths[path]
		isLastPath = pi == len(sortedPaths)-1
		pathConnector := "├"
		pathPrefix := "│"
		if isLastPath {
			pathConnector = "└"
			pathPrefix = " "
		}

		fmt.Printf("  %s── %s Path: %s - %s%s%d Secrets%s\n",
			pathConnector, "📁", path, bold, magenta, len(pathSecrets), reset)

		// Separate static and dynamic secrets
		var staticSecrets []phase.SecretResult
		dynamicGroups := map[string][]phase.SecretResult{}
		var dynamicGroupOrder []string
		for _, s := range pathSecrets {
			if s.IsDynamic {
				if _, seen := dynamicGroups[s.DynamicGroup]; !seen {
					dynamicGroupOrder = append(dynamicGroupOrder, s.DynamicGroup)
				}
				dynamicGroups[s.DynamicGroup] = append(dynamicGroups[s.DynamicGroup], s)
			} else {
				staticSecrets = append(staticSecrets, s)
			}
		}

		// Calculate column widths across all secrets in this path
		minKeyWidth := 15
		maxKeyLen := minKeyWidth
		for _, s := range pathSecrets {
			kl := len(s.Key) + 4 // room for tag/comment icons
			if kl > maxKeyLen {
				maxKeyLen = kl
			}
		}
		keyWidth := maxKeyLen + 2
		if keyWidth > 40 {
			keyWidth = 40
		}
		if keyWidth < minKeyWidth {
			keyWidth = minKeyWidth
		}
		valueWidth := termWidth - keyWidth - 10
		if valueWidth < 20 {
			valueWidth = 20
		}

		// Print table header
		fmt.Fprintf(os.Stdout, "  %s   ╭─%s┬─%s╮\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
		fmt.Fprintf(os.Stdout, "  %s   │ %s%-*s%s│ %s%-*s%s│\n",
			pathPrefix, bold, keyWidth, "KEY", reset, bold, valueWidth, "VALUE", reset)
		fmt.Fprintf(os.Stdout, "  %s   ├─%s┼─%s┤\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))

		// Print static secrets
		for _, s := range staticSecrets {
			renderSecretRow(pathPrefix, s, show, keyWidth, valueWidth, bold, reset)
		}

		// Print dynamic secret groups
		for _, groupLabel := range dynamicGroupOrder {
			groupSecrets := dynamicGroups[groupLabel]

			// Section separator if there were static secrets or a previous group
			if len(staticSecrets) > 0 || groupLabel != dynamicGroupOrder[0] {
				fmt.Fprintf(os.Stdout, "  %s   ├─%s┼─%s┤\n",
					pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
			}

			// Group header row
			header := fmt.Sprintf("⚡️ %s", groupLabel)
			if len(header) > keyWidth+valueWidth+1 {
				header = header[:keyWidth+valueWidth-2] + "…"
			}
			fmt.Fprintf(os.Stdout, "  %s   │ %s%-*s%s│\n",
				pathPrefix, bold, keyWidth+valueWidth+1, header, reset)

			for _, s := range groupSecrets {
				renderSecretRow(pathPrefix, s, show, keyWidth, valueWidth, bold, reset)
			}
		}

		fmt.Fprintf(os.Stdout, "  %s   ╰─%s┴─%s╯\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
	}
}
