package agentsdk

import "strings"

func semanticMapValue(values map[string]string, canonical string) (string, bool, bool) {
	alias := lowerCamelSemanticName(canonical)
	value, exact := values[canonical]
	if alias == canonical {
		return value, exact, false
	}
	aliasValue, aliased := values[alias]
	if exact && aliased {
		return "", false, true
	}
	if exact {
		return value, true, false
	}
	return aliasValue, aliased, false
}

func canonicalSemanticKey(value string, canonicalNames []string) (string, bool) {
	matched := ""
	for _, canonical := range canonicalNames {
		if value != canonical && value != lowerCamelSemanticName(canonical) {
			continue
		}
		if matched != "" {
			return "", false
		}
		matched = canonical
	}
	return matched, matched != ""
}

func lowerCamelSemanticName(value string) string {
	if !strings.Contains(value, "_") {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	upperNext := false
	for _, character := range value {
		if character == '_' {
			upperNext = true
			continue
		}
		if upperNext && character >= 'a' && character <= 'z' {
			builder.WriteRune(character - ('a' - 'A'))
		} else {
			builder.WriteRune(character)
		}
		upperNext = false
	}
	return builder.String()
}
