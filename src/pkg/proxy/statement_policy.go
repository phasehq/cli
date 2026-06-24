package proxy

import (
	"log"
	"regexp"
	"strings"
)

// StmtPolicy is the shared, protocol-agnostic statement policy + audit seam used
// by every DBEngine, so DROP-blocking and SQL audit are identical across DBs.
//
// v1 uses KEYWORD matching (word-boundary, to avoid matching identifiers like
// "dropdown"). Documented bypasses it does NOT catch: SQL comments, stacked
// statements, CTE-wrapped DML, stored procedures. Swap Classify/Blocked for a
// pure-Go SQL AST parser (fail-closed) later without touching the engines.
type StmtPolicy struct {
	provider string
	who      string
	deny     []string
	denyRe   []*regexp.Regexp
}

func NewStmtPolicy(provider, who string, deny []string) *StmtPolicy {
	p := &StmtPolicy{provider: provider, who: who, deny: deny}
	for _, kw := range deny {
		p.denyRe = append(p.denyRe, regexp.MustCompile(`(?i)\b`+regexp.QuoteMeta(strings.TrimSpace(kw))+`\b`))
	}
	return p
}

// classify extracts the leading verb (best-effort) for audit.
func classify(sql string) Statement {
	verb := ""
	if f := strings.Fields(strings.TrimSpace(sql)); len(f) > 0 {
		verb = strings.ToUpper(f[0])
	}
	return Statement{Raw: oneline(sql), Verb: verb}
}

// Blocked reports whether the SQL hits a deny keyword.
func (p *StmtPolicy) Blocked(sql string) (bool, string) {
	for i, re := range p.denyRe {
		if re.MatchString(sql) {
			return true, "deny_statement:" + strings.ToUpper(strings.TrimSpace(p.deny[i]))
		}
	}
	return false, ""
}

func (p *StmtPolicy) Allow(s Statement) {
	log.Printf("[stmt] agent=%s provider=%s ALLOW %s", p.who, p.provider, truncate(s.Raw, 200))
}

func (p *StmtPolicy) Block(s Statement, reason string) {
	log.Printf("[block] agent=%s provider=%s BLOCK %s (%s)", p.who, p.provider, truncate(s.Raw, 200), reason)
}

func (p *StmtPolicy) Session(msg string) {
	log.Printf("[db] agent=%s provider=%s %s", p.who, p.provider, msg)
}

func oneline(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
