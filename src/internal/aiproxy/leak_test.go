package aiproxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

// Values used across the leak protection tests. They are fake, random-looking
// and long enough to be indexed.
const (
	leakSecretOne = "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"
	leakSecretTwo = "postgres://app:Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3@db.internal:5432/app"
)

func newTestLeakGuard(t *testing.T, mode string) *leakGuard {
	t.Helper()
	guard, err := newLeakGuard(mode)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

// registerLeakValues indexes values as the CLI would and adds them.
func registerLeakValues(t *testing.T, guard *leakGuard, values map[string]string) {
	t.Helper()
	var entries []*censor.Entries
	for id, value := range values {
		entry, err := censor.IndexValue(guard.key, "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if _, _, err := guard.add(entries); err != nil {
		t.Fatal(err)
	}
}

func TestLeakModeComesFromTheEnvironmentAndDefaultsToCensor(t *testing.T) {
	for value, want := range map[string]string{
		"": leakModeCensor, "censor": leakModeCensor, "CENSOR": leakModeCensor, " observe ": leakModeObserve,
		"off": leakModeOff, "Off": leakModeOff, "disabled": leakModeCensor, "0": leakModeCensor,
	} {
		if got := leakModeFrom(value); got != want {
			t.Errorf("mode %q = %q, want %q", value, got, want)
		}
	}
	t.Setenv(LeakProtectionEnvironmentKey, "observe")
	guard, err := newLeakGuardFromEnvironment()
	if err != nil || guard.mode != leakModeObserve {
		t.Fatalf("the proxy process's environment was not read: %v %v", guard, err)
	}
}

func TestLeakHostTable(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	cases := []struct {
		host, path string
		port       int
		inspected  bool
		harness    string
	}{
		{"api.anthropic.com", "/v1/messages", 443, true, "claude"},
		{"API.Anthropic.com.", "/v1/messages", 443, true, "claude"},
		{"api.anthropic.com", "/v1/messages", 8443, false, ""},
		{"evil-api.anthropic.com", "/v1/messages", 443, false, ""},
		{"anthropic.com", "/", 443, false, ""},
		{"chatgpt.com", "/backend-api/codex/responses", 443, true, "codex"},
		{"chatgpt.com", "/backend-api/", 443, true, "codex"},
		{"chatgpt.com", "/backend-apix", 443, false, "codex"},
		{"chatgpt.com", "/", 443, false, "codex"},
		{"api.openai.com", "/v1/responses", 443, true, "codex"},
		{"openrouter.ai", "/api/v1/chat/completions", 443, true, "opencode"},
		{"opencode.ai", "/inference/openai/v1/chat/completions", 443, true, "opencode"},
		{"opencode.ai", "/zen/v1/chat/completions", 443, true, "opencode"},
		{"opencode.ai", "/", 443, true, "opencode"},
		{"opencode.ai", "/zen/v1/chat/completions", 8443, false, ""},
		{"api.opencode.ai", "/zen/v1/chat/completions", 443, false, ""},
		{"api2.cursor.sh", "/aiserver.v1.InferenceService/RunInference", 443, false, ""},
		{"example.com", "/", 443, false, ""},
	}
	for _, c := range cases {
		match := guard.inspects(c.host, c.port)
		if got := match.inspectsPath(c.path); got != c.inspected {
			t.Errorf("%s:%d%s inspected = %v, want %v", c.host, c.port, c.path, got, c.inspected)
		}
		if c.harness != "" && (match == nil || match.harness != c.harness) {
			t.Errorf("%s belongs to %v, want %s", c.host, match, c.harness)
		}
	}
	// The unread entries are in the table, so status can name them.
	if match := defaultLeakHosts.lookup("agentn.global.api5.cursor.sh"); match == nil || match.harness != "cursor" || match.inspected() {
		t.Fatalf("a Cursor subdomain is not listed as unread: %+v", match)
	}
	if match := defaultLeakHosts.lookup("cursor.sh"); match == nil || match.harness != "cursor" {
		t.Fatal("cursor.sh itself is not listed")
	}
	// Requests are re-sent with a copy of the client's hello for the hosts
	// flagged in the table and for no other.
	var mirrored []string
	for _, harness := range defaultLeakHosts {
		for _, rule := range harness.Hosts {
			if rule.MirrorHello {
				mirrored = append(mirrored, harness.Harness+" "+rule.Host)
				if rule.Treatment != leakTreatmentInspect {
					t.Errorf("%s is flagged and is not inspected: %+v", rule.Host, rule)
				}
			}
		}
	}
	if len(mirrored) != 1 || mirrored[0] != "opencode opencode.ai" {
		t.Fatalf("the hosts whose hello is copied: %v", mirrored)
	}
	encoded, _ := json.Marshal(defaultLeakHosts)
	if strings.Count(string(encoded), `"mirrorHello":true`) != 1 {
		t.Fatalf("the flag is not written as mirrorHello: %s", encoded)
	}
	if off := newTestLeakGuard(t, leakModeOff); off.inspects("api.anthropic.com", 443) != nil {
		t.Fatal("off mode still reads model hosts")
	}
	var none *leakGuard
	if none.inspects("api.anthropic.com", 443) != nil {
		t.Fatal("a proxy without leak protection reads model hosts")
	}
}

func TestLeakBodyRoundTripsPerEncoding(t *testing.T) {
	plain := []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)
	gzipped := func() []byte {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		_, _ = writer.Write(plain)
		_ = writer.Close()
		return buffer.Bytes()
	}()
	rawDeflate := func() []byte {
		var buffer bytes.Buffer
		writer, _ := flate.NewWriter(&buffer, flate.DefaultCompression)
		_, _ = writer.Write(plain)
		_ = writer.Close()
		return buffer.Bytes()
	}()
	encoder, _ := zstd.NewWriter(nil)
	zstded := encoder.EncodeAll(plain, nil)
	_ = encoder.Close()
	zlibbed, err := encodeLeakBody(plain, "deflate")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		header string
		body   []byte
	}{{"", plain}, {"identity", plain}, {"gzip", gzipped}, {"x-gzip", gzipped}, {"GZIP", gzipped}, {"deflate", zlibbed}, {"deflate", rawDeflate}, {"zstd", zstded}} {
		encoding, ok := leakEncoding(c.header)
		if !ok {
			t.Fatalf("%q is not known", c.header)
		}
		decoded, variant, err := decodeLeakBody(c.body, encoding)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatalf("%q did not decode: %v", c.header, err)
		}
		encoded, err := encodeLeakBody(decoded, variant)
		if err != nil {
			t.Fatal(err)
		}
		// The body goes back in the variant it came in: zlib stays zlib and
		// raw deflate stays raw, since the server reads what the client sent.
		if c.header == "deflate" {
			_, zlibErr := zlib.NewReader(bytes.NewReader(encoded))
			if wasZlib := bytes.Equal(c.body, zlibbed); wasZlib != (zlibErr == nil) {
				t.Fatalf("deflate came in as zlib=%v and went out as zlib=%v", wasZlib, zlibErr == nil)
			}
			if !bytes.Equal(c.body, zlibbed) {
				inflated, rawErr := io.ReadAll(flate.NewReader(bytes.NewReader(encoded)))
				if rawErr != nil || !bytes.Equal(inflated, plain) {
					t.Fatalf("raw deflate did not go out as raw deflate: %v", rawErr)
				}
			}
		}
		again, _, err := decodeLeakBody(encoded, encoding)
		if err != nil || !bytes.Equal(again, plain) {
			t.Fatalf("%q did not survive re-encoding: %v", c.header, err)
		}
	}
	for _, header := range []string{"br", "gzip, br", "compress"} {
		if _, ok := leakEncoding(header); ok {
			t.Errorf("%q should not be undone", header)
		}
	}
	if _, _, err := decodeLeakBody([]byte("not gzip"), "gzip"); err == nil {
		t.Fatal("a broken gzip body decoded")
	}
	// A small body that inflates past the limit is not decoded.
	var bomb bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&bomb, gzip.BestCompression)
	zeros := make([]byte, 1<<20)
	for written := 0; written <= maxLeakDecoded; written += len(zeros) {
		_, _ = writer.Write(zeros)
	}
	_ = writer.Close()
	if _, _, err := decodeLeakBody(bomb.Bytes(), "gzip"); err == nil {
		t.Fatal("a body over the decoded limit was decoded")
	}
}

func TestLeakMetaSkipsLoginHeadersAndReadsTheRest(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	header := http.Header{}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Cookie", "x-api-key"} {
		header.Add(name, "Bearer "+leakSecretOne)
	}
	scan := &leakScan{}
	guard.scanHeaders(scan, header)
	if scan.found() || scan.block {
		t.Fatalf("a login header was judged: %+v", scan)
	}
	// Any other header is reported and never blocks.
	header.Set("X-Custom", "value "+leakSecretOne)
	guard.scanHeaders(scan, header)
	if scan.block || scan.inventory != 1 || !containsString(scan.where, "header") || scan.placeholders[0] != "ph:secret:one" {
		t.Fatalf("a value in another header was not reported, or blocked: %+v", scan)
	}
	urlScan := func(target string) *leakScan {
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		scan := &leakScan{}
		scan.addFixed(guard.findInURL(parsed, censor.ScanOptions{}), "url", true)
		return scan
	}
	if scan := urlScan("/v1/messages?key=" + leakSecretOne); !scan.block || !containsString(scan.where, "url") {
		t.Fatalf("a value in the URL was not found: %+v", scan)
	}
	// Phase's own tokens block in the URL even when nobody registered them.
	token := "pss_service:v2:" + strings.Repeat("a1b2c3d4", 8) + ":" + strings.Repeat("e5f6a7b8", 8) + ":" + strings.Repeat("c9d0e1f2", 8) + ":" + strings.Repeat("a3b4c5d6", 8)
	if scan := urlScan("/v1/messages?t=" + token); !scan.block || !containsString(scan.labels, "phase_service_token") {
		t.Fatalf("a Phase token in the URL does not block: %+v", scan)
	}
}

// A pass-through window is a period in which nothing is read, so it must need
// two failures in a row, stay with one host, and close on a success.
func TestHandshakeBypassIsPerHostAndNeedsTwoFailures(t *testing.T) {
	tracker := newHandshakeTracker()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	tracker.now = func() time.Time { return now }
	host := "api.anthropic.com"

	if window := tracker.note(host, false); window != 0 || tracker.bypassed(host) {
		t.Fatal("one failed handshake must not open a pass-through: a dropped connection looks the same")
	}
	if window := tracker.note(host, false); window != 20*time.Second || !tracker.bypassed(host) {
		t.Fatalf("two failures in a row should open a 20 second window, got %v", window)
	}
	if tracker.bypassed("chatgpt.com") {
		t.Fatal("the pass-through is for one host")
	}
	now = now.Add(21 * time.Second)
	if tracker.bypassed(host) {
		t.Fatal("the window did not end")
	}
	if window := tracker.note(host, false); window != 40*time.Second {
		t.Fatalf("each further failure doubles the window, got %v", window)
	}
	for i := 0; i < 10; i++ {
		tracker.note(host, false)
	}
	if window := tracker.note(host, false); window != 10*time.Minute {
		t.Fatalf("the window is capped at ten minutes, got %v", window)
	}
	tracker.note(host, true)
	if tracker.bypassed(host) {
		t.Fatal("a handshake that succeeds clears the pass-through")
	}
	if window := tracker.note(host, false); window != 0 || tracker.bypassed(host) {
		t.Fatal("the count starts again after a success")
	}
}

func TestLeakStatusIsCountsAndHostsOnly(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne, "two": leakSecretTwo, "short": "abc"})
	status := guard.status()
	if status.Mode != leakModeCensor || status.SecretsKnown != 2 || status.Unprotected != 1 {
		t.Fatalf("status counts are wrong: %+v", status)
	}
	if !containsString(status.InspectedHosts, "api.anthropic.com") || !containsString(status.InspectedHosts, "opencode.ai") ||
		!containsString(status.UnreadHosts, "*.cursor.sh") || containsString(status.UnreadHosts, "opencode.ai") ||
		containsString(status.InspectedHosts, "cursor.sh") {
		t.Fatalf("status hosts are wrong: %+v", status)
	}
	guard.handshakes.note("api.anthropic.com", false)
	guard.handshakes.note("api.anthropic.com", false)
	status = guard.status()
	if containsString(status.InspectedHosts, "api.anthropic.com") || !containsString(status.UnreadHosts, "api.anthropic.com") {
		t.Fatalf("a host in a pass-through window is still listed as inspected: %+v", status)
	}
	payload, _ := json.Marshal(status)
	for _, forbidden := range []string{leakSecretOne, leakSecretTwo, `"one"`, `"two"`, "ph:secret"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("status names a value or an id: %s", payload)
		}
	}
	off := newTestLeakGuard(t, leakModeOff).status()
	if len(off.InspectedHosts) != 0 || !containsString(off.UnreadHosts, "api.anthropic.com") {
		t.Fatalf("off mode lists hosts as inspected: %+v", off)
	}
}

func inventoryProxy(t *testing.T, guard *leakGuard) *httpProxy {
	t.Helper()
	state := selectionState(t)
	state.hints = &hintLog{}
	return &httpProxy{state: state, control: &controlHandler{state: state, leak: guard}, leak: guard}
}

func controlCall(proxy *httpProxy, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://phase.invalid"+path, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	setProxyCapability(request, "runtime-test")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	return recorder
}

func errorCode(recorder *httptest.ResponseRecorder) string {
	var failure struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &failure)
	return failure.Error.Code
}

func TestInventoryControlRoutes(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	proxy := inventoryProxy(t, guard)

	recorder := controlCall(proxy, http.MethodGet, "/v1/inventory/key", "", nil)
	var keyAnswer remoteapi.InventoryKeyResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &keyAnswer) != nil || keyAnswer.SchemaVersion != 1 || keyAnswer.Format != censor.EntriesVersion {
		t.Fatalf("key route: %d %s", recorder.Code, recorder.Body.String())
	}
	raw, _ := base64.StdEncoding.DecodeString(keyAnswer.Key)
	key, err := censor.KeyFromBytes(raw)
	if err != nil || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the key does not rebuild or is cacheable: %v", err)
	}

	entry := func(id, value string) json.RawMessage {
		e, err := censor.IndexValue(key, "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := e.Marshal()
		return data
	}
	body, _ := json.Marshal(remoteapi.InventoryRequest{SchemaVersion: 1, Entries: []json.RawMessage{entry("one", leakSecretOne), entry("short", "abc")}})
	recorder = controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body)
	var added remoteapi.InventoryResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &added) != nil || added.Added != 1 || added.Unprotected != 1 {
		t.Fatalf("registration: %d %s", recorder.Code, recorder.Body.String())
	}
	if guard.index.Stats().Secrets != 1 {
		t.Fatal("the registered value is not in the index")
	}

	for name, c := range map[string]struct {
		contentType string
		body        []byte
		status      int
		code        string
	}{
		"not json content":   {"text/plain", body, http.StatusUnsupportedMediaType, "invalid_control_content_type"},
		"not json":           {"application/json", []byte("{"), http.StatusBadRequest, "invalid_inventory"},
		"unknown field":      {"application/json", []byte(`{"schemaVersion":1,"entries":[],"values":["x"]}`), http.StatusBadRequest, "invalid_inventory"},
		"wrong schema":       {"application/json", []byte(`{"schemaVersion":2,"entries":[]}`), http.StatusBadRequest, "invalid_inventory"},
		"trailing data":      {"application/json", []byte(`{"schemaVersion":1,"entries":[]} {}`), http.StatusBadRequest, "invalid_inventory"},
		"entry not object":   {"application/json", []byte(`{"schemaVersion":1,"entries":["x"]}`), http.StatusBadRequest, "invalid_inventory"},
		"bad entry version":  {"application/json", []byte(`{"schemaVersion":1,"entries":[{"v":2,"type":"secret","id":"x","forms":[]}]}`), http.StatusBadRequest, "invalid_inventory"},
		"bad entry id":       {"application/json", []byte(`{"schemaVersion":1,"entries":[{"v":1,"type":"secret","id":"a b","forms":[]}]}`), http.StatusBadRequest, "invalid_inventory"},
		"entry extra field":  {"application/json", []byte(`{"schemaVersion":1,"entries":[{"v":1,"type":"secret","id":"x","forms":[],"value":"plain"}]}`), http.StatusBadRequest, "invalid_inventory"},
		"oversized":          {"application/json", append([]byte(`{"schemaVersion":1,"entries":["`), bytes.Repeat([]byte("a"), maxInventoryBodyBytes)...), http.StatusRequestEntityTooLarge, "inventory_too_large"},
		"too many entries":   {"application/json", []byte(`{"schemaVersion":1,"entries":[` + strings.TrimSuffix(strings.Repeat("{},", maxInventoryEntries+1), ",") + `]}`), http.StatusBadRequest, "invalid_inventory"},
		"malformed mac size": {"application/json", []byte(`{"schemaVersion":1,"entries":[{"v":1,"type":"secret","id":"x","forms":[{"form":"raw","len":24,"rolls":"AAAAAAAAAAAAAAAAAAAAAA==","macs":"AA==","weak":"AA=="}]}]}`), http.StatusBadRequest, "invalid_inventory"},
	} {
		recorder := controlCall(proxy, http.MethodPost, "/v1/inventory", c.contentType, c.body)
		if recorder.Code != c.status || errorCode(recorder) != c.code {
			t.Errorf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "plain") {
			t.Errorf("%s: the answer echoes the input", name)
		}
	}
	if guard.index.Stats().Secrets != 1 {
		t.Fatal("a refused registration changed the index")
	}

	// A browser page cannot register values.
	request := httptest.NewRequest(http.MethodPost, "http://phase.invalid/v1/inventory", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example")
	setProxyCapability(request, "runtime-test")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a browser registration was accepted: %d", recorder.Code)
	}
	// Without the capability nothing is reachable.
	request = httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/inventory/key", nil)
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusProxyAuthRequired || strings.Contains(recorder.Body.String(), keyAnswer.Key) {
		t.Fatalf("the key was served without the capability: %d", recorder.Code)
	}
	// No route lists what is indexed.
	for _, path := range []string{"/v1/inventory", "/v1/inventory/entries", "/v1/inventory/ids"} {
		if recorder := controlCall(proxy, http.MethodGet, path, "", nil); recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d", path, recorder.Code)
		}
	}

	// A full index is a 507 with a clear message.
	small, err := censor.NewIndex(guard.key, censor.IndexOptions{MaxSecrets: 1})
	if err != nil {
		t.Fatal(err)
	}
	guard.index = small
	body, _ = json.Marshal(remoteapi.InventoryRequest{SchemaVersion: 1, Entries: []json.RawMessage{entry("one", leakSecretOne), entry("two", leakSecretTwo)}})
	recorder = controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body)
	if recorder.Code != http.StatusInsufficientStorage || errorCode(recorder) != "leak_inventory_full" || !strings.Contains(recorder.Body.String(), "full") {
		t.Fatalf("a full index: %d %s", recorder.Code, recorder.Body.String())
	}

	// Without leak protection the routes say so.
	bare := inventoryProxy(t, nil)
	if recorder := controlCall(bare, http.MethodGet, "/v1/inventory/key", "", nil); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("key without leak protection: %d", recorder.Code)
	}
}

func TestStatusReportsLeakProtection(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeObserve)
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	proxy := inventoryProxy(t, guard)
	recorder := controlCall(proxy, http.MethodGet, "/v1/status", "", nil)
	var status remoteapi.StatusResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil ||
		status.LeakProtection.Mode != leakModeObserve || status.LeakProtection.SecretsKnown != 1 {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), leakSecretOne) || strings.Contains(recorder.Body.String(), "ph:secret:one") {
		t.Fatal("status names a value or a placeholder")
	}
}

// Inspection runs before the Connection's credential is injected, so the live
// value the proxy adds is never scanned, and the rewritten body is what is
// forwarded with it.
func TestLeakInspectionRunsBeforeInjectionOnABoundHost(t *testing.T) {
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-custom", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-custom")
	defer state.destroy()
	guard := newTestLeakGuard(t, leakModeCensor)
	guard.hosts = leakHostTable{{Harness: "test", Hosts: []leakHostRule{{Host: "api.example.test", Treatment: leakTreatmentInspect}}}}
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne, "live": customLiveToken})
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream, leak: guard}

	body := `{"messages":[{"role":"user","content":"the key is ` + leakSecretOne + `"}]}`
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", strings.NewReader(body))
	result := processThrough(proxy, request)
	if result.failure != nil {
		t.Fatalf("the request was refused: %+v", result.failure)
	}
	sent := upstream.last.Load()
	if sent.Header.Get("Authorization") != "Bearer "+customLiveToken {
		t.Fatal("the credential was not injected")
	}
	forwarded, _ := io.ReadAll(sent.Body)
	want := strings.Replace(body, leakSecretOne, "ph:secret:one", 1)
	if string(forwarded) != want || sent.ContentLength != int64(len(want)) {
		t.Fatalf("the forwarded body is %q (length %d)", forwarded, sent.ContentLength)
	}
}

func TestLeakEventDetailFitsTheConsole(t *testing.T) {
	scan := &leakScan{match: &leakHostMatch{harness: "claude"}, mode: leakModeCensor, protocol: "http"}
	for i := 0; i < 30; i++ {
		scan.addFinding(censor.Finding{Kind: "inventory", Placeholder: fmt.Sprintf("ph:secret:%064d", i), Action: "redact"}, "body")
	}
	scan.addFinding(censor.Finding{Kind: "rule", Label: "jwt", Placeholder: "ph:jwt:1", Action: "redact"}, "body")
	scan.addFinding(censor.Finding{Kind: "rule", Label: "private_key_header", Action: "alert"}, "header")
	scan.addFinding(censor.Finding{Kind: "inventory", Placeholder: "ph:secret:signed", Action: "left"}, "body")
	// Nothing listed yet: an event names only what is new for the host.
	if detail := scan.detail(); detail["placeholders"] != nil || detail["signedFindings"] != 1 {
		t.Fatalf("detail: %+v", detail)
	}
	scan.listed = scan.placeholders
	if listed := strings.Split(scan.detail()["placeholders"].(string), ","); len(listed) == 0 || len(listed) > maxLeakPlaceholders {
		t.Fatalf("%d placeholders listed", len(listed))
	}
	scan.listed = nil
	detail := scan.detail()
	if len(detail) > 16 {
		t.Fatalf("detail has %d keys", len(detail))
	}
	for key, value := range detail {
		if text, ok := value.(string); ok && len(text) > maxLeakDetailText {
			t.Fatalf("detail.%s is %d characters", key, len(text))
		}
	}
	if detail["placeholders"] != nil || detail["placeholderCount"] != 31 || detail["inventoryHits"] != 30 ||
		detail["ruleRedactions"] != 1 || detail["ruleAlerts"] != 1 || detail["where"] != "body,header" || detail["labels"] != "jwt,private_key_header" {
		t.Fatalf("detail: %+v", detail)
	}
	// What the proxy keeps is what it sends.
	kept := safeEventDetail(detail, nil)
	for key := range detail {
		if _, ok := kept[key]; !ok {
			t.Errorf("detail.%s is dropped before it reaches the Console", key)
		}
	}
	event := agentapi.Event{EventID: "event-x", Detail: kept}
	if _, err := json.Marshal(event); err != nil {
		t.Fatal(err)
	}
}

func censorIndex(guard *leakGuard, typ, id, value string) ([]*censor.Entries, error) {
	entry, err := censor.IndexValue(guard.key, typ, id, value)
	if err != nil {
		return nil, err
	}
	return []*censor.Entries{entry}, nil
}
