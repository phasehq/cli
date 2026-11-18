package censor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// skeleton is the JSON with every string literal emptied: the bytes the walk
// must never change.
func skeleton(data []byte) ([]byte, int) {
	var out []byte
	count := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			out = append(out, data[i])
			continue
		}
		count++
		out = append(out, '"', '"')
		for i++; i < len(data) && data[i] != '"'; i++ {
			if data[i] == '\\' {
				i++
			}
		}
	}
	return out, count
}

// FuzzRewriteJSON checks that the JSON walk never panics, always returns valid
// JSON, and never changes a byte outside a string value.
func FuzzRewriteJSON(f *testing.F) {
	key, _ := NewKey()
	ix, _ := NewIndex(key, IndexOptions{})
	values := []string{"Zq8vLm2Rt5Xw9Kp3Hd7Nf4BcQ1", "sk_" + "live_51AbCdEfGh1234IjKlMnOp5678QrStUv", "postgres://app:Qw3Er5Ty7Ui9Op1As3Df5Gh@db/app"}
	for i, value := range values {
		e, _ := IndexValue(key, "secret", string(rune('a'+i)), value)
		_ = ix.Add(e)
	}
	arguments, _ := json.Marshal(map[string]any{"cmd": []string{"bash", "-lc", "echo " + values[0]}})
	seeds := [][]byte{
		modelRequest("token " + values[0]),
		modelRequest("config:\n" + values[1] + "\n\"quoted\" \\ é \t tab"),
		[]byte(`{"input":[{"type":"function_call","arguments":` + string(mustJSON(string(arguments))) + `}]}`),
		[]byte(`  [ 1, -2.5e3, true, false, null, "` + values[2] + `", {"k" : "v"} ]  `),
		[]byte(`"` + base64.StdEncoding.EncodeToString(gzippedSeed(values[0])) + `"`),
		[]byte(`{"messages":{"api_key":"Ab3dEf6hIj9lMn2pQr5tUv8x"},"x":"A😀` + values[0] + `"}`),
		[]byte(`{}`), []byte(`[]`), []byte(`""`), []byte(`0`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, report, err := ix.RewriteJSON(data, ScanOptions{})
		if !json.Valid(data) {
			if err == nil {
				t.Fatal("invalid JSON was accepted")
			}
			return
		}
		if err != nil {
			t.Fatalf("valid JSON refused: %v", err)
		}
		if !json.Valid(out) {
			t.Fatalf("the output is not JSON: %q", out)
		}
		before, n := skeleton(data)
		after, m := skeleton(out)
		if n != m || !bytes.Equal(before, after) {
			t.Fatalf("bytes outside strings changed:\n%q\n%q", data, out)
		}
		if !report.Changed && !bytes.Equal(out, data) {
			t.Fatal("unchanged output differs")
		}
	})
}

func mustJSON(s string) []byte {
	out, _ := json.Marshal(s)
	return out
}

func gzippedSeed(value string) []byte {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	_, _ = gz.Write(helmRelease(value))
	_ = gz.Close()
	return buffer.Bytes()
}
