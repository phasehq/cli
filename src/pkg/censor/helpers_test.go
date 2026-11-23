package censor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// secret is a plaintext value a test indexes. Only tests hold values.
type secret struct {
	ID, Type, Value string
}

func randomString(t testing.TB, alphabet string, n int) string {
	t.Helper()
	out := make([]byte, n)
	for i := range out {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = alphabet[k.Int64()]
	}
	return string(out)
}

func randomHex(t testing.TB, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func fakePEM(t testing.TB) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newKey(t testing.TB) *Key {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// build indexes plaintext values the way a client and the daemon would together,
// in one process.
func build(t testing.TB, secrets ...secret) *Index {
	t.Helper()
	ix, _ := buildWithEntries(t, newKey(t), secrets...)
	return ix
}

// buildScheme is build with entries of one matching scheme.
func buildScheme(t testing.TB, version int, secrets ...secret) *Index {
	t.Helper()
	ix, _ := buildSchemeWithEntries(t, newKey(t), version, secrets...)
	return ix
}

func buildWithEntries(t testing.TB, key *Key, secrets ...secret) (*Index, map[string]*Entries) {
	t.Helper()
	return buildSchemeWithEntries(t, key, EntriesVersion, secrets...)
}

func buildSchemeWithEntries(t testing.TB, key *Key, version int, secrets ...secret) (*Index, map[string]*Entries) {
	t.Helper()
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]*Entries{}
	for _, s := range secrets {
		typ := s.Type
		if typ == "" {
			typ = "secret"
		}
		e, err := IndexValueScheme(key, version, typ, s.ID, s.Value)
		if err != nil {
			t.Fatal(err)
		}
		if err := ix.Add(e); err != nil {
			t.Fatal(err)
		}
		entries[s.ID] = e
	}
	return ix, entries
}

// result is what scanning a payload found, split the way the lab's tests read it.
type result struct {
	Out     []byte
	JSON    bool
	Changed bool
	Hits    []Finding // inventory
	Rules   []Finding // pattern rules
	Report  *Report
}

// apply scans a payload as the proxy would: a JSON body is rewritten in place,
// anything else as plain bytes.
func apply(ix *Index, payload []byte) result {
	out, report, err := ix.RewriteJSON(payload, ScanOptions{})
	if errors.Is(err, ErrNotJSON) {
		out, report = ix.Redact(payload)
	}
	r := result{Out: out, JSON: report.JSON, Changed: report.Changed, Report: report}
	for _, f := range report.Findings {
		if f.Kind == kindInventory {
			r.Hits = append(r.Hits, f)
		} else {
			r.Rules = append(r.Rules, f)
		}
	}
	return r
}

func modelRequest(texts ...string) []byte {
	messages := []any{map[string]any{"role": "user", "content": "check the config"}}
	for i, text := range texts {
		messages = append(messages,
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": fmt.Sprintf("t%d", i), "name": "Read", "input": map[string]any{"file_path": "/repo/.env"}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": fmt.Sprintf("t%d", i), "content": text}}},
		)
	}
	body, _ := json.Marshal(map[string]any{"model": "test-model", "max_tokens": 1024, "stream": true, "messages": messages})
	return body
}

// corpus is ordinary text and code: this module's Go sources, plus git hashes,
// UUIDs and the kind of base64 a request carries. The base64 is of random
// bytes. It used to be of hex text, which made the test that reads this fail
// about once in 330 runs: twelve characters of base64 over hex hold only 36
// bits, the test indexes about a thousand such chunks of its hex secrets, and
// megabytes of the same kind of text sooner or later repeat one. What that
// showed about the matcher is pinned by TestOneThinChunkIsNoMatch.
//
// Random base64 can spell the one key prefix that needs no punctuation: a blob
// holding "AIza" is drawn again, because 35 letters and digits after it make a
// Google API key to the letter, about once in forty thousand corpora.
func corpus(t testing.TB, size int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	root := filepath.Join("..", "..")
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || buffer.Len() >= size {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err == nil {
			buffer.Write(content)
		}
		return nil
	})
	for buffer.Len() < size {
		blob := base64.StdEncoding.EncodeToString(randomBytes(t, 48))
		if strings.Contains(blob, "AI"+"za") {
			continue
		}
		fmt.Fprintf(&buffer, "commit %s\nMerge: %s\nid=%s-%s-4%s-a%s-%s\nblob %s\n",
			randomHex(t, 20), randomHex(t, 4), randomHex(t, 4), randomHex(t, 2), randomHex(t, 2)[1:], randomHex(t, 2)[1:], randomHex(t, 6), blob)
	}
	return buffer.Bytes()[:size]
}

func manySecrets(t testing.TB, n int) []secret {
	t.Helper()
	secrets := make([]secret, 0, n)
	for i := 0; i < n; i++ {
		var value string
		switch i % 6 {
		case 0:
			value = randomHex(t, 32)
		case 1:
			value = "sk_live_" + randomString(t, alnum, 48)
		case 2:
			value = base64.StdEncoding.EncodeToString([]byte(randomString(t, alnum, 30)))
		case 3:
			value = randomString(t, alnum+"!@#$%^&*", 24)
		case 4:
			value = "postgres://app:" + randomString(t, alnum, 24) + "@db.internal:5432/app"
		case 5:
			value = fakePEM(t)
		}
		secrets = append(secrets, secret{ID: fmt.Sprintf("s%03d", i), Type: "secret", Value: value})
	}
	return secrets
}
