package censor

import (
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
)

func ruleHit(t *testing.T, ix *Index, text string) (Finding, string, bool) {
	t.Helper()
	result := apply(ix, []byte(text))
	if len(result.Rules) == 0 {
		return Finding{}, string(result.Out), false
	}
	return result.Rules[0], string(result.Out), true
}

func TestKeywordProximityDecides(t *testing.T) {
	ix := build(t)
	value := randomString(t, alnum, 15) + "7" + randomString(t, alnum, 15)
	cases := []struct {
		name, text, action string
	}{
		{"env assignment", "WEBHOOK_SECRET=" + value, "redact"},
		{"yaml", "  client_secret: " + value, "redact"},
		{"ini with spaces", "api_key = \"" + value + "\"", "redact"},
		{"connection string", "Server=tcp:db,1433;User ID=app;Password=" + value + ";Encrypt=True", "redact"},
		{"cli flag", "npx vercel deploy --token=" + value, "redact"},
		{"no keyword", "the build id is " + value, ""},
		{"keyword on the line before", "token:\n" + value, ""},
		{"git hash after token", "token: " + randomHex(t, 20), ""},
		{"uuid after auth", "auth id: 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b", ""},
		{"a reference, not a value", "STRIPE_SECRET_KEY=process.env.STRIPE_SECRET_KEY_2", ""},
		{"documentation example", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", ""},
		{"placeholder value", "API_KEY=your-api-key-goes-here-1234", ""},
		{"identifier, no digit", "token = SensitiveStringValueHolder", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, out, ok := ruleHit(t, ix, tc.text)
			action := ""
			if ok {
				action = hit.Action
			}
			if action != tc.action {
				t.Fatalf("action %q (score %d), want %q: %s", action, hit.Score, tc.action, out)
			}
			if tc.action == "redact" && strings.Contains(out, value) {
				t.Fatalf("value survived: %s", out)
			}
		})
	}
}

func TestJSONKeyCountsAsKeyword(t *testing.T) {
	ix := build(t)
	value := randomString(t, alnum, 14) + "9" + randomString(t, alnum, 14)
	body, _ := json.Marshal(map[string]any{"input": map[string]string{"apiKey": value, "note": value}})
	result := apply(ix, body)
	if len(result.Rules) != 1 || result.Rules[0].Path != "/input/apiKey" || result.Rules[0].Score != 50 {
		t.Fatalf("%+v", result.Rules)
	}
	if strings.Count(string(result.Out), value) != 1 {
		t.Fatalf("only the apiKey value should go: %s", result.Out)
	}
}

func TestValidatorsAndScores(t *testing.T) {
	ix := build(t)
	body := randomString(t, alnum, 30)
	valid := "ghp_" + body + base62(crc32.ChecksumIEEE([]byte(body)), 6)
	hit, _, ok := ruleHit(t, ix, "clone with "+valid)
	if !ok || hit.Score != 80 || hit.Action != "redact" {
		t.Fatalf("checksummed token: %+v", hit)
	}
	hit, _, _ = ruleHit(t, ix, "clone with ghp_"+randomString(t, alnum, 36))
	if hit.Score != 60 {
		t.Fatalf("token without a valid checksum: %+v", hit)
	}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIn0." + randomString(t, alnum+"-_", 43)
	if hit, _, _ := ruleHit(t, ix, "the response held "+jwt); hit.Action != "alert" || hit.Score != 30 {
		t.Fatalf("bare JWT: %+v", hit)
	}
	if hit, out, _ := ruleHit(t, ix, "Authorization: Bearer "+jwt); hit.Action != "redact" || strings.Contains(out, jwt) {
		t.Fatalf("JWT after bearer: %+v %s", hit, out)
	}
}

func TestNoKeywordSecretsInImagesOrHashes(t *testing.T) {
	ix := build(t)
	var text strings.Builder
	for i := 0; i < 200; i++ {
		text.WriteString("commit " + randomHex(t, 20) + " id " + randomString(t, "0123456789abcdef", 8) + "-4b1c-4d2e-9f3a-" + randomHex(t, 6) + "\n")
	}
	text.WriteString("data:image/png;base64," + randomString(t, alnum+"+/", 4000))
	if result := apply(ix, []byte(text.String())); len(result.Rules) != 0 {
		t.Fatalf("%+v", result.Rules[0])
	}
}
