package censor

// MaxFindings is how many findings one Report lists. Counts go on past it.
const MaxFindings = 4096

// Report is what a scan found. It holds counts, placeholders, rule labels, form
// names and JSON pointers, never anything that was matched.
type Report struct {
	JSON    bool `json:"json"`
	Changed bool `json:"changed"`

	Inventory int `json:"inventory"` // places an indexed value was found and replaced
	Redacted  int `json:"redacted"`  // pattern rule matches replaced
	Alerts    int `json:"alerts"`    // pattern rule matches only recorded
	// Left counts what was found in text the provider signed or encrypted, such
	// as a thinking block, and left exactly as it was.
	Left int `json:"left,omitempty"`

	Findings  []Finding `json:"findings,omitempty"`
	Truncated bool      `json:"truncated,omitempty"` // more findings than MaxFindings

	Strings       int `json:"strings,omitempty"`        // JSON string values looked at
	SkippedBinary int `json:"skipped_binary,omitempty"` // strings skipped as images or files
	CacheLookups  int `json:"cache_lookups,omitempty"`
	CacheHits     int `json:"cache_hits,omitempty"`
}

// Finding is one thing a scan found.
type Finding struct {
	Kind        string `json:"kind"`                  // "inventory" or "rule"
	Placeholder string `json:"placeholder,omitempty"` // what replaced it (or, when left, would have); empty for an alert
	Action      string `json:"action"`                // "redact", "alert", or "left" (found in provider-signed text, not changed)
	Label       string `json:"label,omitempty"`       // a rule's label
	Rule        string `json:"rule,omitempty"`        // a rule's id
	Score       int    `json:"score,omitempty"`       // a rule match's score
	Form        string `json:"form"`                  // how it appeared: raw, base64, hex, base64>gzip>json, pattern, ...
	Part        string `json:"part,omitempty"`        // url-password, or leaf:<n> for the n-th string of a JSON value
	Decoded     bool   `json:"decoded,omitempty"`     // found inside a decoded base64 or hex run
	Partial     bool   `json:"partial,omitempty"`     // only part of an indexed value was there
	// Path is the JSON pointer of the string it was found in, for RewriteJSON. A
	// string holding JSON adds '#' and the pointer inside it.
	Path string `json:"path,omitempty"`
	// Withheld numbers a value whose id is withheld, from 1, the same while the
	// Index holds it: all that tells two such values of one type apart.
	Withheld int `json:"-"`
	// Loaded says the value was found only through entries added with
	// AddLoaded: a store handed them over, and no client has added them since.
	Loaded bool `json:"-"`
}

// Match is a Finding with where it sits in the scanned bytes.
type Match struct {
	Finding
	Start int `json:"start"`
	End   int `json:"end"`
}

func (h hit) finding() Finding {
	return Finding{
		Kind: h.kind, Placeholder: h.placeholder, Action: h.action, Label: h.label, Rule: h.rule,
		Score: h.score, Form: h.form, Part: h.part, Decoded: h.decoded, Partial: h.partial, Path: h.path,
		Withheld: int(h.withheld), Loaded: h.loaded,
	}
}

func (r *Report) add(h hit) {
	switch {
	case h.action == actionLeft:
		r.Left++
	case h.kind == kindInventory:
		r.Inventory++
	case h.action == actionRedact:
		r.Redacted++
	default:
		r.Alerts++
	}
	if len(r.Findings) >= MaxFindings {
		r.Truncated = true
		return
	}
	r.Findings = append(r.Findings, h.finding())
}

// Found reports whether the scan found anything that is replaced: an indexed
// value or a pattern rule match that redacts.
func (r *Report) Found() bool { return r != nil && (r.Inventory > 0 || r.Redacted > 0) }

// Redact scans plain bytes, such as a text body or a log line, and replaces what
// it finds. The returned bytes are data itself when nothing changed.
func (ix *Index) Redact(data []byte) ([]byte, *Report) {
	return ix.RedactWith(data, ScanOptions{})
}

// RedactWith is Redact with options; only Rules applies.
func (ix *Index) RedactWith(data []byte, opts ScanOptions) ([]byte, *Report) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out, hits, ruleHits, _, changed := ix.scanBlock(data, "", newScanState(), false, ix.rulesFor(opts))
	report := &Report{Changed: changed}
	for _, h := range hits {
		report.add(h)
	}
	for _, h := range ruleHits {
		report.add(h)
	}
	if !changed {
		out = data
	}
	return out, report
}

// Find scans bytes that cannot be rewritten, such as a URL or a header value,
// and says where each finding sits and what would replace it. Ranges are
// sorted by start; a rule match that spans an indexed value contains its range.
// A finding inside a decoded run covers the whole run. At most MaxFindings are
// returned, and when there are more the first indexed value and the first match
// of every rule label are among them: a caller that acts on a kind of finding
// is never kept from seeing one by a crowd of others before it.
func (ix *Index) Find(data []byte) []Match {
	return ix.FindWith(data, ScanOptions{})
}

// FindWith is Find with options; only Rules applies.
func (ix *Index) FindWith(data []byte, opts ScanOptions) []Match {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	_, _, _, reps, _ := ix.scanBlock(data, "", newScanState(), true, ix.rulesFor(opts))
	if len(reps) == 0 {
		return nil
	}
	// Past the cap the first of each kind is kept, and the rest of the room
	// goes to the others in order.
	var first map[int]bool
	if len(reps) > MaxFindings {
		first = map[int]bool{}
		seen := map[[2]string]bool{}
		for i, r := range reps {
			if kind := [2]string{r.hit.kind, r.hit.label}; !seen[kind] {
				seen[kind], first[i] = true, true
			}
		}
	}
	matches := make([]Match, 0, min(len(reps), MaxFindings))
	room := MaxFindings - len(first)
	for i, r := range reps {
		if !first[i] {
			if room <= 0 {
				continue
			}
			room--
		}
		matches = append(matches, Match{Finding: r.hit.finding(), Start: r.start, End: r.end})
	}
	return matches
}
