package display

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"golang.org/x/term"
)

var (
	// Simplified patterns for display icons only (Go doesn't support lookaheads)
	crossEnvPattern = regexp.MustCompile(`\$\{[^}]*\.[^}]+\}`)
	localRefPattern = regexp.MustCompile(`\$\{[^}.]+\}`)
)

func getTerminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// runeWidth returns the terminal column width of a single rune.
// Take into account the col width a char would take
func runeWidth(r rune) int {
	switch {
	case r == '\uFE0F' || r == '\u200A' || r == '\u200B' || r == '\u200D':
		return 0 // variation selectors, hair space, zero-width space, ZWJ
	case r >= 0x1F000:
		return 2 // Supplementary emoji (nearly all EAW=W)
	case r == 0x26A1: // ⚡
		return 2
	default:
		return 1
	}
}

// displayWidth returns the visual terminal column width of s.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

// padRight pads s with spaces to fill exactly width display columns.
func padRight(s string, width int) string {
	sw := displayWidth(s)
	if sw >= width {
		return s
	}
	return s + strings.Repeat(" ", width-sw)
}

// truncateToWidth truncates s to fit within maxWidth display columns.
func truncateToWidth(s string, maxWidth int) string {
	if displayWidth(s) <= maxWidth {
		return s
	}
	var result []byte
	w := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		rw := runeWidth(r)
		if w+rw > maxWidth-1 {
			break
		}
		result = append(result, s[i:i+size]...)
		w += rw
		i += size
	}
	return string(result) + "…"
}

// wrapToWidth splits s into lines that each fit within maxWidth display columns.
func wrapToWidth(s string, maxWidth int) []string {
	var lines []string
	var line []byte
	w := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		// Handle multi line secret wrapping in the value column
		if r == '\n' {
			lines = append(lines, string(line))
			line = nil
			w = 0
			i += size
			continue
		}
		rw := runeWidth(r)
		if maxWidth > 0 && rw > 0 && w+rw > maxWidth {
			lines = append(lines, string(line))
			line = nil
			w = 0
		}
		line = append(line, s[i:i+size]...)
		w += rw
		i += size
	}
	lines = append(lines, string(line))
	return lines
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

// renderSecretRow renders a single secret row.
func renderSecretRow(pathPrefix string, s sdk.SecretResult, show bool, keyWidth, valueWidth int) {
	keyDisplay := s.Key

	// Secret type indicators
	if s.Type == sdk.SecretTypeSealed {
		keyDisplay += " 🔒"
	} else if s.Type == sdk.SecretTypeConfig {
		keyDisplay += " 🔧"
	}

	if len(s.Tags) > 0 {
		keyDisplay += " 🔖"
	}
	if s.Comment != "" {
		keyDisplay += " 💬"
	}

	icon := ""
	if crossEnvPattern.MatchString(s.Value) {
		icon += "🌐 "
	}
	if localRefPattern.MatchString(s.Value) {
		icon += "🔗 "
	}

	personalIndicator := ""
	if s.Overridden {
		personalIndicator = "🔏 "
	}

	var valueDisplay string
	if ai.ShouldRedact(s.Type) {
		valueDisplay = "[REDACTED]"
	} else if s.Type == sdk.SecretTypeSealed {
		valueDisplay = "[sealed secret]"
	} else if s.IsDynamic && !show {
		valueDisplay = "****************"
		// Show type configs
	} else if show || s.Type == sdk.SecretTypeConfig {
		valueDisplay = s.Value
	} else {
		censorLen := valueWidth - displayWidth(icon) - displayWidth(personalIndicator) - 2
		if censorLen < 6 {
			censorLen = 6
		}
		valueDisplay = censorSecret(s.Value, censorLen)
	}
	valueDisplay = icon + personalIndicator + valueDisplay

	// Truncate key (never wraps)
	keyDisplay = truncateToWidth(keyDisplay, keyWidth)

	if !show {
		valueDisplay = truncateToWidth(valueDisplay, valueWidth)
	}

	if show {
		// Wrap long values within the value column
		valueLines := wrapToWidth(valueDisplay, valueWidth)
		for i, vline := range valueLines {
			if i == 0 {
				fmt.Fprintf(os.Stdout, "  %s   │ %s│ %s│\n",
					pathPrefix, padRight(keyDisplay, keyWidth), padRight(vline, valueWidth))
			} else {
				fmt.Fprintf(os.Stdout, "  %s   │ %s│ %s│\n",
					pathPrefix, strings.Repeat(" ", keyWidth), padRight(vline, valueWidth))
			}
		}
	} else {
		valueDisplay = truncateToWidth(valueDisplay, valueWidth)
		fmt.Fprintf(os.Stdout, "  %s   │ %s│ %s│\n",
			pathPrefix, padRight(keyDisplay, keyWidth), padRight(valueDisplay, valueWidth))
	}
}

// RenderSecretsTree renders secrets in a tree view with path hierarchy
func RenderSecretsTree(secrets []sdk.SecretResult, show bool) {
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
	paths := map[string][]sdk.SecretResult{}
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

	for pi, path := range sortedPaths {
		pathSecrets := paths[path]
		isLastPath := pi == len(sortedPaths)-1
		pathConnector := "├"
		pathPrefix := "│"
		if isLastPath {
			pathConnector = "└"
			pathPrefix = " "
		}

		fmt.Printf("  %s── %s Path: %s - %s%s%d Secrets%s\n",
			pathConnector, "📁", path, bold, magenta, len(pathSecrets), reset)

		// Separate static and dynamic secrets
		var staticSecrets []sdk.SecretResult
		dynamicGroups := map[string][]sdk.SecretResult{}
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

		// Calculate column widths
		minKeyWidth := 15
		maxKeyLen := minKeyWidth
		for _, s := range pathSecrets {
			kl := displayWidth(s.Key) + 4
			if kl > maxKeyLen {
				maxKeyLen = kl
			}
		}
		keyWidth := maxKeyLen + 6
		if keyWidth > 40 {
			keyWidth = 40
		}
		if keyWidth < minKeyWidth {
			keyWidth = minKeyWidth
		}
		// Full row: "  X   │ " + key + "│ " + value + "│" = prefix(6) + 2 + key + 2 + value + 1
		// Total = keyWidth + valueWidth + 11, must be < termWidth
		valueWidth := termWidth - keyWidth - 12
		if valueWidth < 20 {
			valueWidth = 20
		}
		// Table top
		fmt.Fprintf(os.Stdout, "  %s   ┌─%s┬─%s┐\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
		fmt.Fprintf(os.Stdout, "  %s   │ %s%s│ %s%s│\n",
			pathPrefix, bold, padRight("KEY", keyWidth)+reset, bold, padRight("VALUE", valueWidth)+reset)
		fmt.Fprintf(os.Stdout, "  %s   ├─%s┼─%s┤\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))

		// Static secrets
		for _, s := range staticSecrets {
			renderSecretRow(pathPrefix, s, show, keyWidth, valueWidth)
		}

		// Dynamic secret groups
		for _, groupLabel := range dynamicGroupOrder {
			groupSecrets := dynamicGroups[groupLabel]

			if len(staticSecrets) > 0 || groupLabel != dynamicGroupOrder[0] {
				fmt.Fprintf(os.Stdout, "  %s   ├─%s┼─%s┤\n",
					pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
			}

			// Group header spans both columns
			header := fmt.Sprintf("⚡ %s", groupLabel)
			totalInner := keyWidth + 2 + valueWidth
			header = truncateToWidth(header, totalInner)
			fmt.Fprintf(os.Stdout, "  %s   │ %s%s%s│\n",
				pathPrefix, bold, padRight(header, totalInner), reset)
			fmt.Fprintf(os.Stdout, "  %s   ├─%s┼─%s┤\n",
				pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))

			for _, s := range groupSecrets {
				renderSecretRow(pathPrefix, s, show, keyWidth, valueWidth)
			}
		}

		// Table bottom
		fmt.Fprintf(os.Stdout, "  %s   └─%s┴─%s┘\n",
			pathPrefix, strings.Repeat("─", keyWidth), strings.Repeat("─", valueWidth))
	}
}
