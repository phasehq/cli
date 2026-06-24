package proxy

import (
	"path"
	"strings"
)

// denied returns a non-empty reason if the HTTP action is blocked by this
// binding's deny rules. PoC model: allow-by-default within a bound host, minus
// explicit deny rules.
func (b *Binding) denied(method, reqPath string) string {
	for _, r := range b.Deny {
		if r.matches(method, reqPath) {
			return "deny rule"
		}
	}
	return ""
}

func (r Rule) matches(method, reqPath string) bool {
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			if strings.EqualFold(m, method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.Paths) > 0 {
		ok := false
		for _, p := range r.Paths {
			if pathMatch(p, reqPath) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// pathMatch supports trailing "*" as a prefix wildcard (e.g. "/v1/*") and
// otherwise falls back to path.Match glob semantics.
func pathMatch(pattern, reqPath string) bool {
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(reqPath, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	matched, err := path.Match(pattern, reqPath)
	return err == nil && matched
}
