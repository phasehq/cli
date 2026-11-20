package censor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func gzipped(t testing.TB, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func helmRelease(value string) []byte {
	padding := strings.Repeat(`{"replicas":3,"image":"registry.example.com/orders:1.4.2","resources":{"limits":{"cpu":"500m"}}},`, 40)
	return []byte(`{"manifest":[` + padding + `{"config":{"apiKey":"` + value + `"}}]}`)
}

// TestGzippedBlobIsCaught is the Helm case: a release kept as gzip and then base64.
func TestGzippedBlobIsCaught(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "helm", Value: value})
	blob := base64.StdEncoding.EncodeToString(gzipped(t, helmRelease(value)))
	result := apply(ix, []byte("release: "+blob+"\n"))
	if len(result.Hits) != 1 || string(result.Out) != "release: ph:secret:helm\n" {
		t.Fatalf("%+v %q", result.Hits, result.Out)
	}
	if hit := result.Hits[0]; !hit.Decoded || hit.Form != "base64>gzip>raw" {
		t.Fatalf("%+v", hit)
	}

	// The same inside a model request, and once more wrapped in base64, as kubectl
	// shows a Helm release Secret's data field.
	twice := base64.StdEncoding.EncodeToString([]byte(blob))
	body := modelRequest("apiVersion: v1\nkind: Secret\ndata:\n  release: " + twice + "\n")
	request := apply(ix, body)
	if len(request.Hits) != 1 || bytes.Contains(request.Out, []byte(twice)) || request.Hits[0].Form != "base64>base64>gzip>raw" {
		t.Fatalf("%+v", request.Hits)
	}
}

func TestZlibBlobIsCaught(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "z", Value: value})
	var buffer bytes.Buffer
	zw := zlib.NewWriter(&buffer)
	_, _ = zw.Write(helmRelease(value))
	_ = zw.Close()
	result := apply(ix, []byte("state="+base64.RawURLEncoding.EncodeToString(buffer.Bytes())))
	if len(result.Hits) != 1 || string(result.Out) != "state=ph:secret:z" || result.Hits[0].Form != "base64>zlib>raw" {
		t.Fatalf("%+v %q", result.Hits, result.Out)
	}
}

// TestDecompressionBombIsNotScanned: a run that inflates past the caps is left as
// it decoded, without an error, a panic or the memory to hold it.
func TestDecompressionBombIsNotScanned(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "bomb", Value: value})
	// 64 MiB of zeros with the value at the very end: past every cap.
	var buffer bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 64; i++ {
		_, _ = gz.Write(zeros)
	}
	_, _ = gz.Write([]byte(value))
	_ = gz.Close()
	bomb := buffer.Bytes()
	if len(bomb) > 256<<10 {
		t.Fatalf("the bomb is %d bytes compressed", len(bomb))
	}
	text := []byte("blob: " + base64.StdEncoding.EncodeToString(bomb))
	result := apply(ix, text)
	if len(result.Hits) != 0 || !bytes.Equal(result.Out, text) {
		t.Fatalf("a bomb should not be scanned: %+v", result.Hits)
	}

	// Under the hard cap but far past the ratio cap: also not scanned.
	small := gzipped(t, append(make([]byte, 900<<10), value...))
	if ratio := (900 << 10) / len(small); ratio < inflateRatio {
		t.Fatalf("the test needs a ratio above %d, got %d", inflateRatio, ratio)
	}
	if result := apply(ix, []byte("blob: "+base64.StdEncoding.EncodeToString(small))); len(result.Hits) != 0 {
		t.Fatalf("past the ratio cap: %+v", result.Hits)
	}

	// Many bombs in one body stop at the per-call budget instead of costing
	// their full size each.
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, base64.StdEncoding.EncodeToString(small))
	}
	st := newScanState()
	ix.mu.RLock()
	ix.scanBlock([]byte(strings.Join(many, "\n")), "", st, false, ix.rules)
	ix.mu.RUnlock()
	if st.inflateLeft > 0 {
		t.Fatalf("budget left %d", st.inflateLeft)
	}
}

func TestBrokenCompressedDataIsScannedAsItDecoded(t *testing.T) {
	value := randomString(t, alnum, 32)
	ix := build(t, secret{ID: "k", Value: value})
	broken := gzipped(t, helmRelease(value))
	broken = broken[:len(broken)/2]
	if result := apply(ix, []byte("x "+base64.StdEncoding.EncodeToString(broken))); len(result.Hits) != 0 {
		t.Fatalf("%+v", result.Hits)
	}
	// A gzip header followed by the value in the clear: the run is not inflated,
	// and the value is still found in it.
	fake := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}, []byte(" "+value+" ")...)
	result := apply(ix, []byte("x "+base64.StdEncoding.EncodeToString(fake)))
	if len(result.Hits) != 1 || result.Hits[0].Placeholder != "ph:secret:k" || strings.Contains(result.Hits[0].Form, "gzip") {
		t.Fatalf("%+v", result.Hits)
	}
	body, _ := json.Marshal(map[string]string{"input": base64.StdEncoding.EncodeToString(fake)})
	if out, _, err := ix.RewriteJSON(body, ScanOptions{}); err != nil || bytes.Contains(out, []byte(base64.StdEncoding.EncodeToString(fake))) {
		t.Fatalf("%s %v", out, err)
	}
}
