package censor

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/phasehq/cli/internal/censortest"
)

func TestKeyBytesRoundTrip(t *testing.T) {
	key := newKey(t)
	again, err := KeyFromBytes(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if *again != *key {
		t.Fatal("a key rebuilt from its bytes differs")
	}
	exported := key.Bytes()
	exported[0] ^= 1
	if bytes.Equal(exported, key.Bytes()) {
		t.Fatal("Bytes should return a copy")
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 64), make([]byte, KeySize)} {
		if _, err := KeyFromBytes(bad); err == nil {
			t.Fatalf("a %d-byte key was accepted", len(bad))
		}
	}
	other := newKey(t)
	if bytes.Equal(other.Bytes(), key.Bytes()) {
		t.Fatal("two random keys are equal")
	}
}

func TestIndexValueChecksIdentifiers(t *testing.T) {
	key := newKey(t)
	value := randomString(t, alnum, 32)
	for _, bad := range [][2]string{{"", "id"}, {"secret", ""}, {"se cret", "id"}, {"secret", "a:b"}, {"secret", strings.Repeat("a", 65)}, {"ph:x", "id"}, {"secret", "id\n"}} {
		if _, err := IndexValue(key, bad[0], bad[1], value); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	e, err := IndexValue(key, "secret", "Abc_1.2-3", value)
	if err != nil || e.Placeholder() != "ph:secret:Abc_1.2-3" {
		t.Fatalf("%v %v", e, err)
	}
	if _, err := IndexValue(nil, "secret", "id", value); err == nil {
		t.Fatal("no key accepted")
	}
	long, err := IndexValue(key, "secret", "long", randomString(t, alnum, MaxValueLength+1))
	if err != nil || long.Protected() || long.Unprotected[0].Reason != ReasonTooLong {
		t.Fatalf("%+v %v", long, err)
	}
}

// splitCorpus is the lab's test material: the fake-secret repository, 300
// values of mixed shapes, and the requests the lab's tests sent.
func splitCorpus(t *testing.T) ([]secret, [][]byte) {
	fixture := censortest.NewFixture()
	secrets := manySecrets(t, 300)
	for _, entry := range fixture.Entries {
		if entry.Expect != "rule" {
			secrets = append(secrets, secret{ID: entry.ID, Type: entry.Type, Value: entry.Value})
		}
	}
	key, privateKey := gcpKey(t)
	secrets = append(secrets, secret{ID: "gcp_sa", Type: "sealed", Value: key})
	var payloads [][]byte
	for name, content := range fixture.Files {
		payloads = append(payloads, modelRequest("read "+name, content), []byte(content))
	}
	for i, s := range secrets {
		raw := []byte(s.Value)
		forms := []string{
			s.Value, base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(append([]byte("deploy:"), raw...)),
			base64.URLEncoding.EncodeToString(append([]byte("ab"), raw...)), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)),
			url.QueryEscape(s.Value), url.PathEscape(s.Value), jsonEscape(s.Value),
		}
		if len(s.Value) > 40 && i%3 == 0 {
			forms = append(forms, s.Value[5:33], s.Value[len(s.Value)-17:])
		}
		payloads = append(payloads, []byte("before "+strings.Join(forms, " | ")+" after"), modelRequest(forms...))
	}
	payloads = append(payloads, modelRequest("private_key:\n"+privateKey))
	text := corpus(t, 1<<20)
	payloads = append(payloads, text, modelRequest(string(text[:200<<10]), "leaked "+secrets[3].Value))
	return secrets, payloads
}

// TestClientEntriesMatchDirectIndexing proves the split: entries a client builds
// with the daemon's exported key, sent as bytes and parsed back, find exactly
// what the daemon finds when the same values are indexed with its own key.
func TestClientEntriesMatchDirectIndexing(t *testing.T) {
	secrets, payloads := splitCorpus(t)
	daemonKey := newKey(t)
	direct, _ := buildWithEntries(t, daemonKey, secrets...)

	clientKey, err := KeyFromBytes(daemonKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	split, err := NewIndex(daemonKey, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wireBytes := 0
	for _, s := range secrets {
		e, err := IndexValue(clientKey, s.Type, s.ID, s.Value)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		wireBytes += len(wire)
		parsed, err := ParseEntries(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := split.Add(parsed); err != nil {
			t.Fatal(err)
		}
	}
	if direct.Stats() != split.Stats() {
		t.Fatalf("stats differ: %+v %+v", direct.Stats(), split.Stats())
	}
	found := 0
	for i, payload := range payloads {
		directOut, directReport := scanBoth(direct, payload)
		splitOut, splitReport := scanBoth(split, payload)
		if !bytes.Equal(directOut, splitOut) || !reflect.DeepEqual(directReport, splitReport) {
			t.Fatalf("payload %d differs:\n%+v\n%+v", i, directReport, splitReport)
		}
		if !reflect.DeepEqual(direct.Find(payload), split.Find(payload)) {
			t.Fatalf("payload %d: Find differs", i)
		}
		found += directReport.Inventory
	}
	if found < len(secrets) {
		t.Fatalf("only %d inventory hits over %d payloads", found, len(payloads))
	}
	t.Logf("%d values, %d bytes of entries on the wire, %d chunks; %d payloads, %d inventory hits, identical", len(secrets), wireBytes, split.Stats().Chunks, len(payloads), found)

	// Entries made under any other key find nothing.
	stranger, _ := buildWithEntries(t, newKey(t))
	for _, s := range secrets[:20] {
		e, _ := IndexValue(newKey(t), s.Type, s.ID, s.Value)
		if err := stranger.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, payload := range payloads[:40] {
		if _, report := scanBoth(stranger, payload); report.Inventory != 0 {
			t.Fatal("entries under another key matched")
		}
	}
}

func scanBoth(ix *Index, payload []byte) ([]byte, *Report) {
	out, report, err := ix.RewriteJSON(payload, ScanOptions{})
	if err != nil {
		out, report = ix.Redact(payload)
	}
	return out, report
}

// representativeValues are the shapes the lab met.
func representativeValues(t *testing.T) []secret {
	gcp, _ := gcpKey(t)
	return []secret{
		{ID: "token", Value: "sk_live_51" + randomString(t, alnum, 60)},
		{ID: "hex", Value: randomHex(t, 32)},
		{ID: "pem", Value: fakePEM(t)},
		{ID: "gcp", Value: gcp},
		{ID: "dburl", Value: "postgres://orders_app:" + randomString(t, alnum, 24) + "@orders-db.internal.example.com:5432/orders"},
		{ID: "jwt", Value: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXJzIiwiYXVkIjoib3JkZXJzIn0." + randomString(t, alnum+"-_", 86)},
		{ID: "phase", Value: "pss_service:v2:" + randomHex(t, 32) + ":" + randomHex(t, 32)},
		{ID: "symbols", Value: randomString(t, alnum+"!@#$%^&*", 28)},
	}
}

// secretParts are the bytes of a value that are secret, for checking places
// that legitimately keep a request's other text: a JSON value's leaves, a
// URL's password, a PEM block's body, a JWT's signature.
func secretParts(value string) []string {
	if leaves := jsonLeaves(value); len(leaves) > 0 {
		var parts []string
		for _, l := range leaves {
			if len(l.value) >= leafMinLength && !looksPublic(l.value) {
				parts = append(parts, secretParts(l.value)...)
			}
		}
		return parts
	}
	if password := urlPassword(value); password != "" {
		return []string{password}
	}
	if strings.Contains(value, "-----BEGIN") {
		var parts []string
		for _, line := range strings.Split(value, "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "-----") {
				parts = append(parts, line)
			}
		}
		return parts
	}
	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
		return []string{value[strings.LastIndex(value, ".")+1:]}
	}
	return []string{value}
}

func assertNoSubstring(t *testing.T, where string, haystack []byte, value string) {
	t.Helper()
	for i := 0; i+8 <= len(value); i++ {
		if bytes.Contains(haystack, []byte(value[i:i+8])) {
			t.Fatalf("%s holds an 8-byte piece of a value, at offset %d of it", where, i)
		}
	}
}

// TestNothingHoldsPlaintext checks the serialized entries, every field of the
// entries, and every byte the index holds, for any 8-byte piece of a value.
func TestNothingHoldsPlaintext(t *testing.T) {
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	values := representativeValues(t)
	for _, s := range values {
		e, err := IndexValue(key, "secret", s.ID, s.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !e.Protected() {
			t.Fatalf("%s was not indexed", s.ID)
		}
		wire, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		assertNoSubstring(t, s.ID+" on the wire", wire, s.Value)
		assertNoSubstring(t, s.ID+" entries", reachableBytes(reflect.ValueOf(e)), s.Value)
		if err := ix.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	held := reachableBytes(reflect.ValueOf(ix))
	for _, s := range values {
		assertNoSubstring(t, "the index", held, s.Value)
	}

	// After scanning requests that carry every value, the cache keeps rewritten
	// text, which must not hold any secret part either.
	var texts []string
	for _, s := range values {
		texts = append(texts, strings.Repeat("padding so the string is cached ", 10)+"\n"+s.Value)
	}
	if _, report, err := ix.RewriteJSON(modelRequest(texts...), ScanOptions{}); err != nil || report.CacheLookups == 0 {
		t.Fatalf("%+v %v", report, err)
	}
	held = reachableBytes(reflect.ValueOf(ix))
	for _, s := range values {
		for _, part := range secretParts(s.Value) {
			assertNoSubstring(t, "the index after a scan", held, part)
		}
	}
}

// reachableBytes gathers every string, byte and integer reachable from v,
// unexported fields included. The compiled rules are left out: they are the
// shipped rule file, not anything indexed.
func reachableBytes(v reflect.Value) []byte {
	var out []byte
	seen := map[uintptr]bool{}
	rulesType := reflect.TypeOf(&Rules{})
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			out = append(out, v.String()...)
			out = append(out, 0)
		case reflect.Uint8:
			out = append(out, byte(v.Uint()))
		case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			out = binary.LittleEndian.AppendUint64(out, v.Uint())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			out = binary.LittleEndian.AppendUint64(out, uint64(v.Int()))
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
			out = append(out, 0)
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				walk(iter.Key())
				walk(iter.Value())
			}
		case reflect.Pointer:
			if v.IsNil() || v.Type() == rulesType || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			walk(v.Elem())
		case reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i))
			}
		}
	}
	walk(v)
	return out
}

func validEntries(t *testing.T) (*Key, *Entries) {
	key := newKey(t)
	e, err := IndexValue(key, "secret", "ok", "postgres://app:"+randomString(t, alnum, 30)+"@db.internal:5432/app")
	if err != nil {
		t.Fatal(err)
	}
	return key, e
}

func TestMalformedEntriesAreRefused(t *testing.T) {
	_, good := validEntries(t)
	wire, err := good.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEntries(wire); err != nil {
		t.Fatal(err)
	}
	clone := func() *Entries {
		e, err := ParseEntries(wire)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// A form whose length is not a multiple of the chunk, so it has a tail.
	tailed := -1
	chunkOf := func(f Form) int {
		c, err := schemes[good.Version].chunkOf(&f)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for i, f := range good.Forms {
		if f.Length%chunkOf(f) != 0 {
			tailed = i
			break
		}
	}
	whole := -1
	for i, f := range good.Forms {
		if f.Length%chunkOf(f) == 0 {
			whole = i
			break
		}
	}
	if tailed < 0 || whole < 0 {
		t.Fatal("the test value needs forms with and without a tail")
	}
	mutations := map[string]func(e *Entries){
		"version 0":            func(e *Entries) { e.Version = 0 },
		"version 3":            func(e *Entries) { e.Version = EntriesVersion + 1 },
		"wide in scheme 1":     func(e *Entries) { e.Version = 1 },
		"narrow hex form":      func(e *Entries) { narrowHexForm(t, e) },
		"empty type":           func(e *Entries) { e.Type = "" },
		"type with a colon":    func(e *Entries) { e.Type = "a:b" },
		"long id":              func(e *Entries) { e.ID = strings.Repeat("x", 65) },
		"unknown form":         func(e *Entries) { e.Forms[0].Form = "rot13" },
		"short form":           func(e *Entries) { e.Forms[0].Length = 11 },
		"huge form":            func(e *Entries) { e.Forms[0].Length = 1 << 40 },
		"negative length":      func(e *Entries) { e.Forms[0].Length = -12 },
		"length and chunks":    func(e *Entries) { e.Forms[0].Length += chunkSize },
		"missing lookup":       func(e *Entries) { e.Forms[0].Lookups = e.Forms[0].Lookups[:len(e.Forms[0].Lookups)-3] },
		"a whole rolling hash": func(e *Entries) { e.Forms[0].Rolls = make([]byte, 8*(e.Forms[0].Length/chunkSize)) },
		"extra mac":            func(e *Entries) { e.Forms[0].MACs = append(e.Forms[0].MACs, make([]byte, macSize)...) },
		"short mac":            func(e *Entries) { e.Forms[0].MACs = e.Forms[0].MACs[:len(e.Forms[0].MACs)-1] },
		"weak too long":        func(e *Entries) { e.Forms[0].Weak = append(e.Forms[0].Weak, 0) },
		"weak too short":       func(e *Entries) { e.Forms[0].Weak = nil },
		"weak past the end":    func(e *Entries) { e.Forms[0].Weak[len(e.Forms[0].Weak)-1] |= 0x80 },
		"tail missing":         func(e *Entries) { e.Forms[tailed].Tail = nil },
		"tail short":           func(e *Entries) { e.Forms[tailed].Tail = e.Forms[tailed].Tail[:4] },
		"tail not needed":      func(e *Entries) { e.Forms[whole].Tail = make([]byte, macSize) },
		"unknown part":         func(e *Entries) { e.Forms[0].Part = "password" },
		"leaf without number":  func(e *Entries) { e.Forms[0].Part = "leaf:" },
		"leaf with zero lead":  func(e *Entries) { e.Forms[0].Part = "leaf:01" },
		"leaf with letters":    func(e *Entries) { e.Forms[0].Part = "leaf:1a" },
		"leaf too long":        func(e *Entries) { e.Forms[0].Part = "leaf:12345678901234" },
		"unknown reason":       func(e *Entries) { e.Unprotected = []Unprotected{{Reason: "because"}} },
		"bad unprotected part": func(e *Entries) { e.Unprotected = []Unprotected{{Part: "x", Reason: ReasonTooShort}} },
		"too many forms": func(e *Entries) {
			for len(e.Forms) <= maxFormsPerValue {
				e.Forms = append(e.Forms, e.Forms[0])
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := clone()
			mutate(e)
			ix, _ := NewIndex(newKey(t), IndexOptions{})
			if err := ix.Add(e); err == nil {
				t.Fatal("Add accepted it")
			}
			if ix.Stats() != (IndexStats{}) {
				t.Fatal("a refused Add changed the index")
			}
			encoded, err := json.Marshal(e)
			if err != nil {
				return
			}
			if _, err := ParseEntries(encoded); err == nil {
				t.Fatal("ParseEntries accepted it")
			}
			if _, err := e.Marshal(); err == nil {
				t.Fatal("Marshal accepted it")
			}
		})
	}
	for name, raw := range map[string]string{
		"not JSON":       "nope",
		"empty":          "",
		"null":           "null",
		"array":          "[]",
		"unknown field":  strings.Replace(string(wire), `"v":2`, `"v":2,"extra":true`, 1),
		"trailing data":  string(wire) + `{}`,
		"trailing text":  string(wire) + `x`,
		"bad base64":     strings.Replace(string(wire), `"lookups":"`, `"lookups":"!`, 1),
		"string version": strings.Replace(string(wire), `"v":2`, `"v":"2"`, 1),
	} {
		if _, err := ParseEntries([]byte(raw)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	ix, _ := NewIndex(newKey(t), IndexOptions{})
	if err := ix.Add(nil); err == nil {
		t.Fatal("nil entries accepted")
	}
}

func TestAddingTheSameValueTwiceIsHarmless(t *testing.T) {
	key := newKey(t)
	value := randomString(t, alnum, 40)
	ix, _ := buildWithEntries(t, key, secret{ID: "k", Value: value})
	before := ix.Stats()
	again, _ := IndexValue(key, "secret", "k", value)
	if err := ix.Add(again); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(again); err != nil {
		t.Fatal(err)
	}
	if ix.Stats() != before {
		t.Fatalf("%+v then %+v", before, ix.Stats())
	}
	// A new value under the same id protects both, as after a rotation.
	rotated := randomString(t, alnum, 40)
	next, _ := IndexValue(key, "secret", "k", rotated)
	if err := ix.Add(next); err != nil {
		t.Fatal(err)
	}
	if stats := ix.Stats(); stats.Secrets != 1 || stats.Forms <= before.Forms {
		t.Fatalf("%+v", stats)
	}
	out, _ := ix.Redact([]byte(value + " " + rotated))
	if string(out) != "ph:secret:k ph:secret:k" {
		t.Fatalf("%q", out)
	}
}

func TestIndexCaps(t *testing.T) {
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{MaxSecrets: 2})
	if err != nil {
		t.Fatal(err)
	}
	add := func(id string) error {
		e, err := IndexValue(key, "secret", id, randomString(t, alnum, 40))
		if err != nil {
			t.Fatal(err)
		}
		return ix.Add(e)
	}
	if add("a") != nil || add("b") != nil {
		t.Fatal("under the cap")
	}
	before := ix.Stats()
	if err := add("c"); !errors.Is(err, ErrIndexFull) {
		t.Fatalf("%v", err)
	}
	if ix.Stats() != before {
		t.Fatal("a refused Add changed the index")
	}
	if err := add("a"); err != nil {
		t.Fatalf("another value for a known id is not a new secret: %v", err)
	}

	small, _ := NewIndex(key, IndexOptions{MaxChunks: 100})
	e, _ := IndexValue(key, "secret", "big", randomString(t, alnum, 200))
	if err := small.Add(e); !errors.Is(err, ErrIndexFull) || small.Stats() != (IndexStats{}) {
		t.Fatalf("%v %+v", err, small.Stats())
	}
	if _, err := NewIndex(nil, IndexOptions{}); err == nil {
		t.Fatal("an index without a key")
	}
}

func TestConcurrentAddAndScan(t *testing.T) {
	key := newKey(t)
	ix, _ := NewIndex(key, IndexOptions{})
	secrets := manySecrets(t, 60)
	var bodies [][]byte
	for _, s := range secrets {
		bodies = append(bodies, modelRequest(strings.Repeat("filler text for the cache ", 12)+s.Value))
	}
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(secrets); i += 4 {
				e, err := IndexValue(key, "secret", secrets[i].ID, secrets[i].Value)
				if err == nil {
					err = ix.Add(e)
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				body := bodies[(i*7+r)%len(bodies)]
				if _, _, err := ix.RewriteJSON(body, ScanOptions{}); err != nil {
					t.Error(err)
					return
				}
				ix.Find(body[:min(len(body), 4096)])
				ix.Redact(body)
			}
		}(r)
	}
	wg.Wait()
	for i, body := range bodies {
		out, report, _ := ix.RewriteJSON(body, ScanOptions{})
		if report.Inventory == 0 || bytes.Contains(out, []byte(strings.TrimSpace(secrets[i].Value))) {
			t.Fatalf("value %d not caught after concurrent adds: %+v", i, report)
		}
	}
	if stats := ix.Stats(); stats.Secrets != len(secrets) {
		t.Fatalf("%+v", stats)
	}
}

func FuzzParseEntries(f *testing.F) {
	key, _ := NewKey()
	for _, value := range []string{"short", "Zq8vLm2Rt5Xw9Kp3Hd7Nf4Bc", "postgres://a:Zq8vLm2Rt5Xw9Kp3Hd7Nf4Bc@h/db", `{"k":"Zq8vLm2Rt5Xw9Kp3Hd7Nf4Bc0123"}`} {
		e, _ := IndexValue(key, "secret", "seed", value)
		wire, _ := e.Marshal()
		f.Add(wire)
	}
	f.Add([]byte(`{"v":1,"type":"secret","id":"x","forms":[{"form":"raw","len":12,"rolls":"AAAAAAAAAAA=","macs":"AAAAAAAAAAAAAAAAAAAAAA==","weak":"AA=="}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := ParseEntries(data)
		if err != nil {
			return
		}
		ix, _ := NewIndex(key, IndexOptions{})
		if err := ix.Add(e); err != nil {
			t.Fatalf("parsed entries were refused by Add: %v", err)
		}
		ix.Find([]byte(fmt.Sprintf("probe %x", data)))
	})
}

// narrowHexForm rewrites the entries' hex form as plain 12-byte chunks, which
// scheme 2 exists to keep out of an index.
func narrowHexForm(t *testing.T, e *Entries) {
	t.Helper()
	for i := range e.Forms {
		f := &e.Forms[i]
		if f.Form != formHex || !f.Wide {
			continue
		}
		n := f.Length / chunkSize
		f.Wide, f.Lookups, f.MACs, f.Weak, f.Tail = false, make([]byte, 3*n), make([]byte, macSize*n), make([]byte, (n+7)/8), nil
		if f.Length%chunkSize != 0 {
			f.Tail = make([]byte, macSize)
		}
		return
	}
	t.Fatal("the test value has no wide hex form")
}
