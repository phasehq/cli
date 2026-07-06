package proxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// applyCredential resolves the live credential from the proxy's secret snapshot
// and applies it. If the binding configures a dummy, it SWAPS the agent's dummy
// placeholder for the live value wherever it appears (the agent only ever holds
// the dummy). Otherwise it INJECTS the live value into the configured slot.
// Returns an audit label + whether a credential was applied.
func applyCredential(req *http.Request, b *Binding, secrets map[string]string) (string, bool) {
	// AWS SigV4 is not a header swap — the request is signed with the secret key,
	// so the proxy must re-sign it with the live credential (see sigv4.go).
	if isAWSSigV4(b.Inject.Scheme) {
		return resignAWS(req, b, secrets)
	}

	live := secrets[b.Inject.SecretKey]
	if live == "" {
		return "live " + b.Inject.SecretKey + " missing", false
	}
	if b.Inject.Dummy != "" {
		dummy := secrets[b.Inject.Dummy]
		if dummy == "" {
			return "dummy " + b.Inject.Dummy + " missing", false
		}
		n := swapCredential(req, dummy, live)
		return fmt.Sprintf("swap×%d", n), n > 0
	}
	injectScheme(req, b, live)
	return "inject:" + strings.ToLower(b.Inject.Scheme), true
}

// swapCredential replaces every occurrence of the dummy placeholder with the
// live credential across the request's headers, URL, and body.
func swapCredential(req *http.Request, dummy, live string) int {
	n := 0
	for k, vals := range req.Header {
		for i, v := range vals {
			if strings.Contains(v, dummy) {
				n += strings.Count(v, dummy)
				req.Header[k][i] = strings.ReplaceAll(v, dummy, live)
			}
		}
	}
	if strings.Contains(req.URL.RawQuery, dummy) {
		n += strings.Count(req.URL.RawQuery, dummy)
		req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, dummy, url.QueryEscape(live))
	}
	if strings.Contains(req.URL.Path, dummy) {
		n += strings.Count(req.URL.Path, dummy)
		req.URL.Path = strings.ReplaceAll(req.URL.Path, dummy, live)
	}
	if req.Body != nil {
		data, _ := io.ReadAll(req.Body)
		req.Body.Close()
		if len(data) > 0 {
			if bytes.Contains(data, []byte(dummy)) {
				n += bytes.Count(data, []byte(dummy))
				data = bytes.ReplaceAll(data, []byte(dummy), []byte(live))
			}
			req.Body = io.NopCloser(bytes.NewReader(data))
			req.ContentLength = int64(len(data))
			req.Header.Set("Content-Length", strconv.Itoa(len(data)))
		} else {
			req.Body = http.NoBody
			req.ContentLength = 0
		}
	}
	return n
}

// injectScheme writes the live credential into the configured slot (used when no
// dummy is configured for the binding).
func injectScheme(req *http.Request, b *Binding, live string) {
	switch strings.ToLower(b.Inject.Scheme) {
	case "bearer", "":
		req.Header.Set("Authorization", "Bearer "+live)
	case "basic":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(live)))
	case "x-api-key", "header":
		h := b.Inject.Header
		if h == "" {
			h = "X-Api-Key"
		}
		req.Header.Set(h, live)
	default:
		req.Header.Set("Authorization", "Bearer "+live)
	}
}
