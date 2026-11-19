package censor

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestEveryFormIsReplaced(t *testing.T) {
	value := "sk_test_" + randomString(t, alnum, 40) + "/+?&=\"x"
	ix := build(t, secret{ID: "api_key", Type: "secret", Value: value})
	raw := []byte(value)
	b64 := func(e *base64.Encoding, prefix string) string {
		return e.EncodeToString(append([]byte(prefix), raw...))
	}
	cases := map[string]string{
		"raw":            value,
		"base64":         b64(base64.StdEncoding, ""),
		"base64 shift 1": b64(base64.StdEncoding, "u"),
		"base64 shift 2": b64(base64.StdEncoding, "us"),
		"basic auth":     b64(base64.StdEncoding, "deploy:"),
		"base64url":      b64(base64.URLEncoding, "ab"),
		"hex":            hex.EncodeToString(raw),
		"HEX":            strings.ToUpper(hex.EncodeToString(raw)),
		"url":            url.QueryEscape(value),
		"url path":       url.PathEscape(value),
		"json":           jsonEscape(value),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			text := "before " + encoded + " after"
			result := apply(ix, []byte(text))
			if len(result.Hits) == 0 {
				t.Fatalf("no hit for %s", name)
			}
			out := string(result.Out)
			if strings.Contains(out, encoded) || !strings.Contains(out, "ph:secret:api_key") {
				t.Fatalf("not replaced: %q", out)
			}
			if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") {
				t.Fatalf("neighbouring text damaged: %q", out)
			}
			t.Logf("%-15s form=%s partial=%v", name, result.Hits[0].Form, result.Hits[0].Partial)
		})
	}
}

func TestStandaloneBase64LeavesNoEdgeCharacters(t *testing.T) {
	value := randomString(t, alnum, 41)
	ix := build(t, secret{ID: "k", Value: value})
	for _, encoded := range []string{base64.StdEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value))} {
		out := string(apply(ix, []byte(`token: "`+encoded+`"`)).Out)
		if out != `token: "ph:secret:k"` {
			t.Fatalf("got %q", out)
		}
	}
}

func TestJSONStringsAreRewrittenInPlace(t *testing.T) {
	value := randomHex(t, 32)
	ix := build(t, secret{ID: "seed", Type: "sealed", Value: value})
	body := modelRequest("line one\nSEED=" + value + "\n\"quoted\" tag")
	result := apply(ix, body)
	if !result.JSON || !result.Changed {
		t.Fatalf("%+v", result.Report)
	}
	if bytes.Contains(result.Out, []byte(value)) || !json.Valid(result.Out) {
		t.Fatalf("bad output %s", result.Out)
	}
	if got := result.Hits[0].Path; got != "/messages/2/content/0/content" {
		t.Fatalf("path %q", got)
	}
	// Everything but the changed string keeps its bytes, including key order.
	want := strings.Replace(string(body), value, "ph:sealed:seed", 1)
	if string(result.Out) != want {
		t.Fatalf("output changed elsewhere:\n%s\n%s", result.Out, want)
	}
}

func TestJSONInsideAStringIsWalked(t *testing.T) {
	value := "ghs_" + randomString(t, alnum, 36)
	ix := build(t, secret{ID: "deploy", Value: value})
	arguments, _ := json.Marshal(map[string]any{"cmd": []string{"bash", "-lc", "curl -H 'Authorization: token " + value + "' https://api.example.com"}})
	body, _ := json.Marshal(map[string]any{"model": "gpt", "input": []any{map[string]any{"type": "function_call", "arguments": string(arguments)}}})
	result := apply(ix, body)
	if len(result.Hits) != 1 || result.Hits[0].Path != "/input/0/arguments#/cmd/2" {
		t.Fatalf("%+v", result.Hits)
	}
	var outer struct {
		Input []struct{ Arguments string } `json:"input"`
	}
	if err := json.Unmarshal(result.Out, &outer); err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(outer.Input[0].Arguments)) || strings.Contains(outer.Input[0].Arguments, value) {
		t.Fatalf("arguments %s", outer.Input[0].Arguments)
	}
}

func TestPointerEscapesKeys(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "k", Value: value})
	body, _ := json.Marshal(map[string]any{"messages": map[string]any{"a/b~c": value}})
	result := apply(ix, body)
	if len(result.Hits) != 1 || result.Hits[0].Path != "/messages/a~1b~0c" {
		t.Fatalf("%+v", result.Hits)
	}
}

// everyChunkCounts is a random value none of whose 12-byte chunks is too plain
// to count. About one random chunk in 700 repeats its characters until it is
// under 2.8 bits a byte, which the index marks as carrying no partial match
// alone: right for the index, and a failure once in 140 runs for a test of
// what a piece of a 64-character value does at every offset.
func everyChunkCounts(t testing.TB, alphabet string, n int) string {
	t.Helper()
	for {
		value := randomString(t, alphabet, n)
		plain := false
		for at := 0; at+chunkSize <= n; at += chunkSize {
			plain = plain || entropy(value[at:at+chunkSize]) < weakChunkEntropy
		}
		if !plain {
			return value
		}
	}
}

// TestPartialLeaks measures what a contiguous piece of a value does at every offset.
func TestPartialLeaks(t *testing.T) {
	value := everyChunkCounts(t, alnum+"-_", 64)
	ix := build(t, secret{ID: "token", Value: value})
	for _, length := range []int{12, 16, 23, 24, 32} {
		caught, total := 0, 0
		for offset := 0; offset+length <= len(value); offset++ {
			piece := value[offset : offset+length]
			result := apply(ix, []byte("the value starts with "+piece+" and that's all"))
			total++
			if len(result.Hits) > 0 {
				caught++
				if !result.Hits[0].Partial {
					t.Fatalf("a piece was reported as a full match")
				}
				if strings.Contains(string(result.Out), piece[:12]) && strings.Contains(string(result.Out), piece[length-12:]) {
					t.Fatalf("caught but the piece survived: %q", result.Out)
				}
				// Nothing past the placeholder should be left from the value.
				if !strings.Contains(string(result.Out), "ph:secret:token and that's all") || !strings.HasPrefix(string(result.Out), "the value starts with ph:") {
					t.Fatalf("leftover characters: %q", result.Out)
				}
			}
		}
		t.Logf("partial leak of %2d chars: caught at %d of %d offsets (%.0f%%)", length, caught, total, 100*float64(caught)/float64(total))
		if length >= 2*chunkSize-1 && caught != total {
			t.Fatalf("a %d-char piece must always be caught", length)
		}
	}
}

// A chunk too plain to count carries no partial match alone, so a piece of a
// value is caught for certain from 23 bytes only where the chunk it holds whole
// is not such a one. Random values have one about once in 140, and this is
// what it does.
func TestAPlainChunkCarriesNoPieceAlone(t *testing.T) {
	plain := "aabbccaabbcc"
	if entropy(plain) >= weakChunkEntropy {
		t.Fatalf("the test's chunk has %.2f bits a byte", entropy(plain))
	}
	head, tail := fixedText("plain chunk head", alnum, 24), fixedText("plain chunk tail", alnum, 24)
	for _, chunk := range []string{head[:12], head[12:], tail[:12], tail[12:]} {
		if entropy(chunk) < weakChunkEntropy {
			t.Fatalf("the test's chunk %s is plain too", chunk)
		}
	}
	value := head + plain + tail
	ix := build(t, secret{ID: "token", Value: value})
	for offset := 0; offset+23 <= len(value); offset++ {
		piece := value[offset : offset+23]
		result := apply(ix, []byte("the value starts with "+piece+" and that's all"))
		// The plain chunk is the third: a piece of 23 bytes holds it whole,
		// and no other, from offset 13 to 24.
		if alone := offset >= 13 && offset <= 24; alone != (len(result.Hits) == 0) {
			t.Errorf("the piece at offset %d: %d hits", offset, len(result.Hits))
		}
	}
	// With a chunk that counts beside it, and in the whole value, it is found.
	for _, piece := range []string{value[12:36], value[24:48], value} {
		if result := apply(ix, []byte("the value starts with "+piece+" and that's all")); len(result.Hits) != 1 || string(result.Out) != "the value starts with ph:secret:token and that's all" {
			t.Errorf("%d bytes of the value: %q", len(piece), result.Out)
		}
	}
}

// protectableDigits is a random number of n digits that is sure to be indexed.
// About one random 21-digit number in a hundred repeats its digits so much
// that it is under the 2.5 bits a byte a value needs, and IndexValue reports it
// as too plain to protect. A test that expects every part of its key file to be
// replaced failed that often for no other reason; what happens to such a
// number is pinned by TestAPlainLeafIsReportedAndLeft instead.
func protectableDigits(t testing.TB, n int) string {
	t.Helper()
	for {
		if value := randomString(t, decimal, n); entropy(value) >= minValueEntropy+0.25 {
			return value
		}
	}
}

func gcpKey(t testing.TB) (string, string) {
	t.Helper()
	return gcpKeyWith(t, protectableDigits(t, 21))
}

func gcpKeyWith(t testing.TB, clientID string) (string, string) {
	t.Helper()
	privateKey := fakePEM(t)
	key, _ := json.MarshalIndent(map[string]string{
		"type": "service_account", "project_id": "orders-prod-" + randomString(t, "0123456789", 6),
		"private_key_id": randomHex(t, 20), "private_key": privateKey,
		"client_email": "deployer@orders-prod.iam.gserviceaccount.com", "client_id": clientID,
		"auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
	}, "", "  ")
	return string(key), privateKey
}

// A leaf of a key file that is too plain to protect is reported as such and
// left in the request, while the rest of the file is replaced. A client id of
// 21 digits is such a leaf about once in a hundred, when its digits repeat.
// Nothing of it is in the entries or the index: what the scan cache then holds
// is the request's own text, as it went out.
func TestAPlainLeafIsReportedAndLeft(t *testing.T) {
	plain := "100200300100200300100"
	if entropy(plain) >= minValueEntropy {
		t.Fatalf("the test's number has %.2f bits a byte", entropy(plain))
	}
	key, privateKey := gcpKeyWith(t, plain)
	ix, entries := buildWithEntries(t, newKey(t), secret{ID: "gcp_sa", Type: "sealed", Value: key})
	reported := 0
	for _, u := range entries["gcp_sa"].Unprotected {
		if u.Reason == ReasonLowEntropy && strings.HasPrefix(u.Part, partLeafPrefix) {
			reported++
		}
	}
	if reported != 1 || !entries["gcp_sa"].Protected() {
		t.Fatalf("the plain leaf: %+v", entries["gcp_sa"].Unprotected)
	}
	wire, err := entries["gcp_sa"].Marshal()
	if err != nil {
		t.Fatal(err)
	}
	result := apply(ix, modelRequest(strings.Repeat("padding so the string is cached ", 10)+"\n"+key))
	if !bytes.Contains(result.Out, []byte(plain)) || bytes.Contains(result.Out, []byte("PRIVATE KEY")) || len(result.Hits) < 2 {
		t.Fatalf("the plain leaf should stay and the rest go: %+v", result.Hits)
	}
	for _, line := range strings.Split(strings.TrimSpace(privateKey), "\n")[1:3] {
		if bytes.Contains(result.Out, []byte(line)) {
			t.Fatal("a key line survived")
		}
	}
	if bytes.Contains(wire, []byte(plain[:8])) || bytes.Contains(reachableBytes(reflect.ValueOf(entries["gcp_sa"])), []byte(plain[:8])) {
		t.Fatal("the entries hold the leaf that was not indexed")
	}
	// The index holds it only as part of the text it scanned and left as it was.
	if held := reachableBytes(reflect.ValueOf(ix)); !bytes.Contains(held, []byte(`\"client_id\": \"`+plain)) {
		t.Fatal("the cached text of the request does not hold the leaf it left")
	}
}

func TestServiceAccountKeyFieldsAreProtectedOnTheirOwn(t *testing.T) {
	key, privateKey := gcpKey(t)
	ix, entries := buildWithEntries(t, newKey(t), secret{ID: "gcp_sa", Type: "sealed", Value: key})
	whole := apply(ix, modelRequest(key))
	if len(whole.Hits) < 2 || bytes.Contains(whole.Out, []byte("PRIVATE KEY")) || !bytes.Contains(whole.Out, []byte("deployer@orders-prod")) {
		t.Fatalf("whole key: %+v %s", whole.Hits, whole.Out)
	}
	for _, hit := range whole.Hits {
		if !strings.HasPrefix(hit.Part, "leaf:") || hit.Placeholder != "ph:sealed:gcp_sa" {
			t.Fatalf("whole key: %+v", whole.Hits)
		}
	}
	only := apply(ix, modelRequest("private_key:\n"+privateKey))
	if len(only.Hits) == 0 || !strings.HasPrefix(only.Hits[0].Part, "leaf:") || only.Hits[0].Placeholder != "ph:sealed:gcp_sa" {
		t.Fatalf("private key alone: %+v", only.Hits)
	}
	for _, line := range strings.Split(privateKey, "\n")[1:3] {
		if bytes.Contains(only.Out, []byte(line)) {
			t.Fatal("a key line survived")
		}
	}
	email := apply(ix, []byte("client_email is deployer@orders-prod.iam.gserviceaccount.com"))
	if len(email.Hits) != 0 {
		t.Fatalf("an email in the key file was treated as secret: %+v", email.Hits)
	}
	reasons := map[string]int{}
	for _, u := range entries["gcp_sa"].Unprotected {
		reasons[u.Reason]++
	}
	if reasons[ReasonPublicLeaf] != 3 || reasons[ReasonShortLeaf] == 0 {
		t.Fatalf("unprotected leaves: %+v", entries["gcp_sa"].Unprotected)
	}
}

func TestPEMLinesAndEnvFileForm(t *testing.T) {
	privateKey := fakePEM(t)
	ix := build(t, secret{ID: "tls_key", Value: privateKey})
	// Indented, as in a YAML block: the whole block no longer matches, each line does.
	indented := "tls.key: |\n"
	for _, line := range strings.Split(strings.TrimSpace(privateKey), "\n") {
		indented += "    " + line + "\n"
	}
	result := apply(ix, []byte(indented))
	lines := 0
	for _, hit := range result.Hits {
		if hit.Form == "line" {
			lines++
		}
	}
	if lines == 0 {
		t.Fatalf("no line hits: %+v", result.Hits)
	}
	body := strings.Split(strings.TrimSpace(privateKey), "\n")
	for _, line := range body[1 : len(body)-1] {
		if strings.Contains(string(result.Out), line) {
			t.Fatalf("line survived: %s", result.Out)
		}
	}
	env := `TLS_KEY="` + strings.ReplaceAll(strings.TrimSpace(privateKey), "\n", `\n`) + `"`
	envResult := apply(ix, modelRequest(env))
	if len(envResult.Hits) == 0 || envResult.Hits[0].Form != "newline-literal" || envResult.Hits[0].Partial {
		t.Fatalf("env form: %+v", envResult.Hits)
	}
	if !strings.Contains(string(envResult.Out), `TLS_KEY=\"ph:secret:tls_key\"`) {
		t.Fatalf("env output %s", envResult.Out)
	}
}

func TestDecodeAndRescan(t *testing.T) {
	password := "dckr_pat_" + randomString(t, alnum+"-_", 27)
	webhook := "whsec_" + randomString(t, alnum, 32)
	ix := build(t, secret{ID: "registry", Value: password}, secret{ID: "webhook", Value: webhook})
	auth := base64.StdEncoding.EncodeToString([]byte("deploy-bot:" + password))
	config, _ := json.Marshal(map[string]any{"auths": map[string]any{"https://index.docker.io/v1/": map[string]string{"username": "deploy-bot", "password": password, "auth": auth}}})
	dockerconfig := base64.StdEncoding.EncodeToString(config)
	text := "data:\n  .dockerconfigjson: " + dockerconfig + "\n"
	result := apply(ix, []byte(text))
	if len(result.Hits) == 0 || string(result.Out) != "data:\n  .dockerconfigjson: ph:secret:registry\n" {
		t.Fatalf("dockerconfigjson: %+v %q", result.Hits, result.Out)
	}
	t.Logf("dockerconfigjson with a password field: form %s", result.Hits[0].Form)

	// Only the auth field: the password is base64 inside base64, which needs a decode.
	authOnly, _ := json.Marshal(map[string]any{"auths": map[string]any{"ghcr.io": map[string]string{"auth": auth}}})
	doubled := apply(ix, []byte(".dockerconfigjson: "+base64.StdEncoding.EncodeToString(authOnly)))
	if len(doubled.Hits) == 0 || !doubled.Hits[0].Decoded || doubled.Hits[0].Form != "base64>base64" || string(doubled.Out) != ".dockerconfigjson: ph:secret:registry" {
		t.Fatalf("auth only: %+v %q", doubled.Hits, doubled.Out)
	}

	nested, _ := json.Marshal(map[string]string{"signing": base64.StdEncoding.EncodeToString([]byte(webhook))})
	hexResult := apply(ix, []byte("blob="+hex.EncodeToString(nested)))
	if len(hexResult.Hits) == 0 || hexResult.Hits[0].Form != "hex>base64" || string(hexResult.Out) != "blob=ph:secret:webhook" {
		t.Fatalf("hex: %+v %q", hexResult.Hits, hexResult.Out)
	}

	// Wrapped at 76 characters, as `base64` writes on Linux.
	padding := strings.Repeat("ordinary configuration text ", 10)
	inner := base64.StdEncoding.EncodeToString([]byte(webhook))
	wrappedSource := base64.StdEncoding.EncodeToString([]byte(padding + `{"secret":"` + inner + `"}` + padding))
	var wrapped strings.Builder
	for i := 0; i < len(wrappedSource); i += 76 {
		wrapped.WriteString(wrappedSource[i:min(i+76, len(wrappedSource))] + "\n")
	}
	wrappedResult := apply(ix, []byte(wrapped.String()))
	if len(wrappedResult.Hits) == 0 || strings.Count(string(wrappedResult.Out), "\n") != 1 {
		t.Fatalf("wrapped: %+v %q", wrappedResult.Hits, wrappedResult.Out)
	}
}

func TestShortAndPlainValuesAreReportedNotIndexed(t *testing.T) {
	ix, entries := buildWithEntries(t, newKey(t),
		secret{ID: "pg", Value: "postgres"},
		secret{ID: "plain", Value: "aaaaaaaaaaaaaaaaaaaa"},
		secret{ID: "ok", Value: randomString(t, alnum, 24)},
	)
	reason := func(id string) string {
		if len(entries[id].Unprotected) == 0 {
			return ""
		}
		return entries[id].Unprotected[0].Reason
	}
	if reason("pg") != ReasonTooShort || reason("plain") != ReasonLowEntropy || reason("ok") != "" {
		t.Fatalf("%+v %+v %+v", entries["pg"], entries["plain"], entries["ok"])
	}
	if entries["pg"].Protected() || !entries["ok"].Protected() {
		t.Fatal("Protected is wrong")
	}
	if len(apply(ix, []byte("user postgres password postgres")).Hits) != 0 {
		t.Fatal("a short value was matched")
	}
	if stats := ix.Stats(); stats.Secrets != 1 {
		t.Fatalf("values with nothing indexed should not count: %+v", stats)
	}
}

func TestPatternRules(t *testing.T) {
	ix := build(t, secret{ID: "known_phase", Value: "pss_service:v2:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)})
	parts := func() string {
		return randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	}
	user := "pss_user:v1:" + parts()
	service := "pss_service:v2:" + parts()
	agent := "pss_agent:v1:" + parts()
	aws := "AKIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	ghp := "ghp_" + randomString(t, alnum, 36)
	fine := "github_pat_11" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 20) + "_" + randomString(t, alnum, 59)
	text := strings.Join([]string{user, service, agent, aws, ghp, fine, fakePEM(t), user}, "\n")
	result := apply(ix, []byte(text))
	labels := map[string]int{}
	for _, hit := range result.Rules {
		labels[hit.Label]++
	}
	for _, label := range []string{"phase_pat", "phase_service_token", "phase_agent_token", "aws_access_key_id", "github_token", "private_key"} {
		if labels[label] == 0 {
			t.Errorf("no %s hit: %v", label, labels)
		}
	}
	out := string(result.Out)
	for _, survivor := range []string{user, service, agent, aws, ghp, fine, "PRIVATE KEY"} {
		if strings.Contains(out, survivor) {
			t.Errorf("survived: %.20s", survivor)
		}
	}
	if strings.Count(out, "ph:phase_pat:1") != 2 {
		t.Errorf("the same token should get the same placeholder: %s", out)
	}
}

func TestInventoryWinsOverRules(t *testing.T) {
	token := "pss_service:v2:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	ix := build(t, secret{ID: "phase_token", Value: token})
	result := apply(ix, []byte("PHASE_SERVICE_TOKEN="+token))
	if string(result.Out) != "PHASE_SERVICE_TOKEN=ph:secret:phase_token" || len(result.Rules) != 0 {
		t.Fatalf("%q %+v", result.Out, result.Rules)
	}
}

func TestUnchangedHistoryComesFromTheCache(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "k", Value: value})
	history := []string{strings.Repeat("a long tool result ", 40), strings.Repeat("another file ", 40) + value}
	first := apply(ix, modelRequest(history...))
	second := apply(ix, modelRequest(append(history, strings.Repeat("new output ", 40))...))
	if first.Report.CacheHits != 0 || second.Report.CacheHits != 2 || second.Report.CacheLookups != 3 {
		t.Fatalf("first %d/%d, second %d/%d", first.Report.CacheHits, first.Report.CacheLookups, second.Report.CacheHits, second.Report.CacheLookups)
	}
	if len(second.Hits) != 1 || bytes.Contains(second.Out, []byte(value)) {
		t.Fatalf("cached hit lost: %+v", second.Hits)
	}
}

// TestAddingAValueClearsTheCache: a string cached as clean must be scanned again
// once a value it holds is indexed.
func TestAddingAValueClearsTheCache(t *testing.T) {
	key := newKey(t)
	ix, _ := buildWithEntries(t, key)
	value := randomString(t, alnum, 32)
	body := modelRequest(strings.Repeat("a long tool result ", 40) + value)
	if first := apply(ix, body); first.Changed {
		t.Fatal("nothing is indexed yet")
	}
	e, err := IndexValue(key, "secret", "late", value)
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(e); err != nil {
		t.Fatal(err)
	}
	second := apply(ix, body)
	if !second.Changed || bytes.Contains(second.Out, []byte(value)) || second.Report.CacheHits != 0 {
		t.Fatalf("stale cache: %+v", second.Report)
	}
}

func TestBinaryBlocksAreSkipped(t *testing.T) {
	ix := build(t, secret{ID: "k", Value: randomString(t, alnum, 32)})
	image := make([]byte, 64<<10)
	_, _ = rand.Read(image)
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"type": "image", "source": map[string]string{"type": "base64", "data": base64.StdEncoding.EncodeToString(image)}}}})
	if result := apply(ix, body); result.Report.SkippedBinary != 1 {
		t.Fatalf("%+v", result.Report)
	}
	_, report, err := ix.RewriteJSON(body, ScanOptions{BinaryMinLength: -1})
	if err != nil || report.SkippedBinary != 0 {
		t.Fatalf("a negative threshold should never skip: %+v %v", report, err)
	}
}

func TestConversationFieldsOption(t *testing.T) {
	ix := build(t)
	value := randomString(t, alnum, 14) + "9" + randomString(t, alnum, 14)
	body, _ := json.Marshal(map[string]any{"metadata": map[string]string{"apiKey": value}})
	if _, report, _ := ix.RewriteJSON(body, ScanOptions{}); report.Redacted != 0 {
		t.Fatalf("a harness field should not count as a keyword: %+v", report)
	}
	out, report, _ := ix.RewriteJSON(body, ScanOptions{ConversationFields: []string{"metadata"}})
	if report.Redacted != 1 || bytes.Contains(out, []byte(value)) {
		t.Fatalf("%+v", report)
	}
}

func TestRewriteJSONRefusesOtherBodies(t *testing.T) {
	ix := build(t)
	for _, body := range []string{"", "   ", "plain text", `{"a":`, `{"a":1}}`} {
		out, _, err := ix.RewriteJSON([]byte(body), ScanOptions{})
		if err != ErrNotJSON || string(out) != body {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

func TestFindGivesRangesInTheInput(t *testing.T) {
	value := "whsec_" + randomString(t, alnum, 32)
	ix := build(t, secret{ID: "webhook", Value: value})
	aws := "AKIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	// Hex around JSON around base64: found only by decoding the hex run.
	encoded := hex.EncodeToString([]byte(`{"signing":"` + base64.StdEncoding.EncodeToString([]byte(value)) + `"}`))
	data := "/v1/hooks?secret=" + url.QueryEscape(value) + "&blob:" + encoded + "&id=" + aws + "&tail=1"
	matches := ix.Find([]byte(data))
	if len(matches) != 3 {
		t.Fatalf("%+v", matches)
	}
	want := []struct{ text, placeholder string }{
		{url.QueryEscape(value), "ph:secret:webhook"},
		{encoded, "ph:secret:webhook"},
		{aws, "ph:aws_access_key_id:1"},
	}
	for i, m := range matches {
		if data[m.Start:m.End] != want[i].text || m.Placeholder != want[i].placeholder {
			t.Fatalf("match %d: %q %+v", i, data[m.Start:m.End], m)
		}
	}
	if !matches[1].Decoded || matches[1].Form != "hex>base64" {
		t.Fatalf("%+v", matches[1])
	}
	if ix.Find([]byte("/v1/models?limit=20")) != nil {
		t.Fatal("found something in a clean URL")
	}
}

func TestFindMapsRuleRangesAroundPlaceholders(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "k", Value: value})
	// A rule match after an indexed value: its range has to be shifted back by
	// the difference between the value and its placeholder.
	ghp := "ghp_" + randomString(t, alnum, 36)
	data := "first " + value + " then " + ghp + " end"
	matches := ix.Find([]byte(data))
	if len(matches) != 2 || data[matches[0].Start:matches[0].End] != value || data[matches[1].Start:matches[1].End] != ghp {
		t.Fatalf("%+v", matches)
	}
}

func TestRedactPlainText(t *testing.T) {
	value := randomString(t, alnum, 40)
	ix := build(t, secret{ID: "k", Value: value})
	out, report := ix.Redact([]byte("export TOKEN=" + value))
	if string(out) != "export TOKEN=ph:secret:k" || !report.Changed || report.Inventory != 1 || !report.Found() {
		t.Fatalf("%q %+v", out, report)
	}
	clean := []byte("nothing to see")
	out, report = ix.Redact(clean)
	if &out[0] != &clean[0] || report.Changed || report.Found() {
		t.Fatal("clean input should come back as it was")
	}
}

func TestFalsePositivesOnOrdinaryText(t *testing.T) {
	ix := build(t, manySecrets(t, 300)...)
	text := corpus(t, 4<<20)
	result := apply(ix, text)
	if len(result.Hits) != 0 {
		t.Fatalf("%d inventory false positives: %+v", len(result.Hits), result.Hits[:min(len(result.Hits), 5)])
	}
	byRule := map[string]int{}
	for _, hit := range result.Rules {
		byRule[hit.Rule+"/"+hit.Action]++
	}
	if len(result.Rules) != 0 {
		t.Fatalf("%d rule false positives: %v", len(result.Rules), byRule)
	}
	stats := ix.Stats()
	t.Logf("corpus %d bytes, %d forms, %d chunks: 0 inventory hits; rule hits %v", len(text), stats.Forms, stats.Chunks, byRule)

	// The same for what is most easily taken for a credential: each file as
	// plain text, then all of them as the tool results of one request.
	negatives := ordinaryNegatives(t)
	names := make([]string, 0, len(negatives))
	for name := range negatives {
		names = append(names, name)
	}
	sort.Strings(names)
	var contents []string
	size := 0
	for _, name := range names {
		content := negatives[name]
		contents = append(contents, content)
		size += len(content)
		out, report := ix.Redact([]byte(content))
		if string(out) != content || len(report.Findings) != 0 {
			t.Errorf("%s: %d false positives, the first %+v", name, len(report.Findings), report.Findings[:min(len(report.Findings), 3)])
		}
	}
	request := apply(ix, modelRequest(contents...))
	if request.Changed || len(request.Hits)+len(request.Rules) != 0 {
		t.Errorf("as tool results: %d inventory and %d rule false positives, the first %+v", len(request.Hits), len(request.Rules), request.Report.Findings[:min(len(request.Report.Findings), 3)])
	}
	t.Logf("%d files of lock files, minified code, digests, names, URLs and images, %d bytes: 0 inventory and 0 rule hits", len(names), size)

	// And for the kinds of text a review found the rules replacing. Nothing in
	// them is replaced; a rule that exists to report, and is named for the
	// file, may report.
	reviewed, mayAlert := reviewedNegatives(t)
	names = names[:0]
	for name := range reviewed {
		names = append(names, name)
	}
	sort.Strings(names)
	contents, size = contents[:0], 0
	alerts := 0
	allowed := func(name string, findings []Finding) {
		t.Helper()
		for _, f := range findings {
			if f.Kind != kindRule || f.Action != actionAlert || f.Rule != mayAlert[name] {
				t.Errorf("%s: %s %s %s (score %d)", name, f.Kind, f.Rule, f.Action, f.Score)
			}
			alerts++
		}
	}
	for _, name := range names {
		content := reviewed[name]
		contents = append(contents, content)
		size += len(content)
		out, report := ix.Redact([]byte(content))
		if string(out) != content || report.Inventory != 0 || report.Redacted != 0 {
			t.Errorf("%s: %d inventory hits and %d replacements", name, report.Inventory, report.Redacted)
		}
		allowed(name, report.Findings)
		// As the tool result of a request, where a JSON file is walked key by key.
		result := apply(ix, modelRequest(content))
		if result.Changed || len(result.Hits) != 0 || result.Report.Redacted != 0 {
			t.Errorf("%s as a tool result: %d inventory hits and %d replacements", name, len(result.Hits), result.Report.Redacted)
		}
		allowed(name, result.Rules)
	}
	if request = apply(ix, modelRequest(contents...)); request.Changed || len(request.Hits) != 0 || request.Report.Redacted != 0 {
		t.Errorf("as tool results: %d inventory hits and %d replacements", len(request.Hits), request.Report.Redacted)
	}
	t.Logf("%d files of manifests, Firebase and Auth0 configs, class maps, model names and image references, %d bytes: 0 inventory hits, 0 replacements, %d alerts", len(names), size, alerts)
}

func TestEveryInventorySecretIsFoundInARequest(t *testing.T) {
	secrets := manySecrets(t, 300)
	ix := build(t, secrets...)
	var texts []string
	for _, s := range secrets {
		texts = append(texts, "config value: "+s.Value)
	}
	result := apply(ix, modelRequest(texts...))
	found := map[string]bool{}
	for _, hit := range result.Hits {
		found[hit.Placeholder] = true
	}
	if len(found) != len(secrets) {
		t.Fatalf("found %d of %d", len(found), len(secrets))
	}
	for _, s := range secrets {
		if bytes.Contains(result.Out, []byte(strings.TrimSpace(s.Value))) {
			t.Fatalf("%s survived", s.ID)
		}
	}
}

func benchmarkApply(b *testing.B, size int, warm bool) {
	secrets := manySecrets(b, 300)
	benchmarkApplyWith(b, build(b, secrets...), secrets, size, warm)
}

// benchmarkApplyWith scans a request of size bytes with an index of secrets.
func benchmarkApplyWith(b *testing.B, ix *Index, secrets []secret, size int, warm bool) {
	text := corpus(b, size)
	// A request: the corpus as tool results of about 32 KB each, with a few secrets.
	var results []string
	for i := 0; i < len(text); i += 32 << 10 {
		results = append(results, string(text[i:min(i+(32<<10), len(text))]))
	}
	for i := 0; i < 5 && i < len(results); i++ {
		results[i*len(results)/5] += "\nleaked " + secrets[i*7].Value
	}
	body := modelRequest(results...)
	if warm {
		apply(ix, body)
	}
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	var last result
	for i := 0; i < b.N; i++ {
		if !warm {
			b.StopTimer()
			ix.cache.reset()
			b.StartTimer()
		}
		last = apply(ix, body)
	}
	b.StopTimer()
	if len(last.Hits) < 5 {
		b.Fatalf("expected at least 5 hits, got %d", len(last.Hits))
	}
	b.ReportMetric(float64(len(last.Hits)), "hits")
}

func BenchmarkApply1MB(b *testing.B)        { benchmarkApply(b, 1<<20, false) }
func BenchmarkApply10MB(b *testing.B)       { benchmarkApply(b, 10<<20, false) }
func BenchmarkApply10MBCached(b *testing.B) { benchmarkApply(b, 10<<20, true) }
