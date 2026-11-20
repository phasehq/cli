package censortest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/url"
	"strings"
)

// piece is a form whose fragments of length count as a leak on their own.
type piece struct {
	bytes  []byte
	length int
}

// encodedForms lists what a value looks like after the encodings it commonly
// picks up on its way out of a process, more of them than the matcher indexes,
// and the forms whose fragments are looked for too.
func encodedForms(value string) ([][]byte, []piece) {
	raw := []byte(value)
	var whole [][]byte
	pieces := []piece{{bytes: raw, length: rawFragment}}
	seen := map[string]bool{}
	add := func(encoded string) {
		if !seen[encoded] {
			seen[encoded] = true
			whole = append(whole, []byte(encoded))
		}
	}
	add(value)
	if strings.Contains(value, "\n") {
		add(strings.ReplaceAll(value, "\n", "\r\n"))
		add(strings.ReplaceAll(value, "\n", `\n`))
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		add(encoding.EncodeToString(raw))
		// A value inside a larger encoded blob sits at one of three alignments.
		// Only the characters built entirely from the value's own bits are
		// predictable.
		for shift := 0; shift < 3; shift++ {
			padded := append(make([]byte, shift), raw...)
			encoded := encoding.WithPadding(base64.NoPadding).EncodeToString(padded)
			head := []int{0, 2, 3}[shift]
			tail := len(padded) * 8 / 6
			if tail > head {
				pieces = append(pieces, piece{bytes: []byte(encoded[head:tail]), length: b64Fragment})
			}
		}
	}
	lowerHex := hex.EncodeToString(raw)
	pieces = append(pieces,
		piece{bytes: []byte(lowerHex), length: hexFragment},
		piece{bytes: []byte(strings.ToUpper(lowerHex)), length: hexFragment},
	)
	add(lowerHex)
	add(strings.ToUpper(lowerHex))
	add(url.QueryEscape(value))
	add(url.PathEscape(value))
	strict := strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
	add(strict)
	add(jsonEscape(value, true))
	add(jsonEscape(value, false))
	add(html.EscapeString(value))
	return whole, pieces
}

func jsonEscape(value string, escapeHTML bool) string {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(escapeHTML)
	if err := encoder.Encode(value); err != nil {
		return value
	}
	encoded := strings.TrimSuffix(out.String(), "\n")
	return strings.TrimSuffix(strings.TrimPrefix(encoded, `"`), `"`)
}
