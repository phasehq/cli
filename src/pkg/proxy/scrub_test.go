package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const (
	scrubTestAccessKeyID = "ASIAMINTEDEXAMPLE000"
	scrubTestSecretKey   = "mintedSecretKeyExample0000000000000000000"
	scrubTestToken       = "FwoGZXIvYXdzEMintedSessionTokenExample//////////wEaDExample"
)

const scrubSTSXML = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROAEXAMPLE:session</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>` + scrubTestAccessKeyID + `</AccessKeyId>
      <SecretAccessKey>` + scrubTestSecretKey + `</SecretAccessKey>
      <SessionToken>` + scrubTestToken + `</SessionToken>
      <Expiration>2026-11-14T11:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId></ResponseMetadata>
</AssumeRoleResponse>`

const scrubSTSJSON = `{"AssumeRoleResponse":{"AssumeRoleResult":{"AssumedRoleUser":{"Arn":"arn:aws:sts::123456789012:assumed-role/demo/session"},` +
	`"Credentials":{"AccessKeyId":"` + scrubTestAccessKeyID + `","SecretAccessKey":"` + scrubTestSecretKey + `","SessionToken":"` + scrubTestToken + `","Expiration":1.7631E9}}}}`

func scrubResponse(contentType string, body io.Reader, length int64) *http.Response {
	response := &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(body), ContentLength: length,
	}
	if contentType != "" {
		response.Header.Set("Content-Type", contentType)
	}
	if length >= 0 {
		response.Header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
	return response
}

// scrubbed runs a body through the scrubber and returns what the Agent would
// read and how many values were reported replaced.
func scrubbed(t *testing.T, response *http.Response) (string, int) {
	t.Helper()
	reported, calls := 0, 0
	if err := ScrubAWSCredentialResponse(response, func(values int) { reported, calls = values, calls+1 }); err != nil {
		t.Fatalf("scrub: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if calls > 1 {
		t.Fatalf("the scrubber reported %d times", calls)
	}
	return string(body), reported
}

func assertNoMintedMaterial(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{scrubTestAccessKeyID, scrubTestSecretKey, scrubTestToken} {
		if strings.Contains(body, secret) {
			t.Fatalf("credential material reached the Agent: %s", body)
		}
	}
}

func TestScrubReplacesSTSCredentialsInXMLAndJSON(t *testing.T) {
	tests := map[string]struct {
		contentType string
		body        string
		keep        []string
	}{
		"STS XML":             {"text/xml", scrubSTSXML, []string{"<Expiration>2026-11-14T11:00:00Z</Expiration>", "arn:aws:sts::123456789012:assumed-role/demo/session", "c6104cbe-af31-11e0-8154-cbc7ccf896c7"}},
		"STS JSON":            {"application/json", scrubSTSJSON, []string{`"Expiration":1.7631E9`, "arn:aws:sts::123456789012:assumed-role/demo/session"}},
		"amz json":            {"application/x-amz-json-1.1", `{"Credentials": {"AccessKeyId" : "` + scrubTestAccessKeyID + `", "SecretKey":"` + scrubTestSecretKey + `", "SessionToken":"` + scrubTestToken + `"}, "IdentityId":"eu-central-1:example"}`, []string{`"IdentityId":"eu-central-1:example"`}},
		"lower camel JSON":    {"application/json", `{"roleCredentials":{"accessKeyId":"` + scrubTestAccessKeyID + `","secretAccessKey":"` + scrubTestSecretKey + `","sessionToken":"` + scrubTestToken + `","expiration":1763114400000}}`, []string{`"expiration":1763114400000`}},
		"token first XML":     {"application/xml", `<CreateSessionResult><Credentials><SessionToken>` + scrubTestToken + `</SessionToken><SecretAccessKey>` + scrubTestSecretKey + `</SecretAccessKey><AccessKeyId>` + scrubTestAccessKeyID + `</AccessKeyId></Credentials></CreateSessionResult>`, nil},
		"namespaced XML":      {"text/xml; charset=utf-8", `<a:Credentials xmlns:a="urn:example"><a:AccessKeyId>` + scrubTestAccessKeyID + `</a:AccessKeyId><a:SecretAccessKey type="string">` + scrubTestSecretKey + `</a:SecretAccessKey></a:Credentials>`, nil},
		"CDATA":               {"text/xml", `<Credentials><AccessKeyId><![CDATA[` + scrubTestAccessKeyID + `]]></AccessKeyId><SecretAccessKey><![CDATA[` + scrubTestSecretKey + `]]></SecretAccessKey></Credentials>`, nil},
		"access key no token": {"text/xml", `<CreateAccessKeyResult><AccessKey><UserName>bob</UserName><AccessKeyId>` + scrubTestAccessKeyID + `</AccessKeyId><Status>Active</Status><SecretAccessKey>` + scrubTestSecretKey + `</SecretAccessKey></AccessKey></CreateAccessKeyResult>`, []string{"<UserName>bob</UserName>", "<Status>Active</Status>"}},
		"no content type":     {"", scrubSTSXML, nil},
		"escaped JSON quotes": {"application/json", `{"Credentials":{"AccessKeyId":"` + scrubTestAccessKeyID + `","SecretAccessKey":"abc\"` + scrubTestSecretKey + `","Note":"kept"}}`, []string{`"Note":"kept"`}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response := scrubResponse(test.contentType, strings.NewReader(test.body), int64(len(test.body)))
			body, reported := scrubbed(t, response)
			assertNoMintedMaterial(t, body)
			wantValues := strings.Count(test.body, scrubTestAccessKeyID) + strings.Count(test.body, scrubTestSecretKey) + strings.Count(test.body, scrubTestToken)
			if reported != wantValues || strings.Count(body, scrubMarker) != wantValues {
				t.Fatalf("replaced %d values (reported %d), want %d: %s", strings.Count(body, scrubMarker), reported, wantValues, body)
			}
			for _, kept := range test.keep {
				if !strings.Contains(body, kept) {
					t.Fatalf("%q was not kept: %s", kept, body)
				}
			}
			// The length is no longer the upstream's, so the proxy frames the body.
			if response.ContentLength != -1 || response.Header.Get("Content-Length") != "" {
				t.Fatalf("Content-Length was left as %d / %q", response.ContentLength, response.Header.Get("Content-Length"))
			}
		})
	}
}

// Identities in provider output stay real: only a secret key with an access
// key ID beside it is credential material.
func TestScrubLeavesOrdinaryResponsesByteForByte(t *testing.T) {
	bodies := map[string]struct{ contentType, body string }{
		"list of access keys":     {"text/xml", `<ListAccessKeysResult><AccessKeyMetadata><member><UserName>bob</UserName><AccessKeyId>AKIAREALLISTED000000</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult>`},
		"caller identity":         {"text/xml", `<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/bob</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult>`},
		"cloudtrail access key":   {"application/x-amz-json-1.1", `{"Events":[{"AccessKeyId":"AKIAREALLISTED000000","EventName":"ListBuckets"}]}`},
		"session token alone":     {"application/json", `{"SessionToken":"an-application-token","SessionId":"s-1"}`},
		"secret key alone":        {"application/json", `{"SecretAccessKey":"a-field-that-happens-to-have-this-name"}`},
		"empty credential values": {"text/xml", `<Credentials><AccessKeyId></AccessKeyId><SecretAccessKey></SecretAccessKey></Credentials>`},
		"names inside a string":   {"application/json", `{"SecretString":"{\"AccessKeyId\":\"AKIASTOREDSECRET0000\",\"SecretAccessKey\":\"storedInSecretsManager\"}"}`},
		"far apart":               {"application/json", `{"AccessKeyId":"AKIAREALLISTED000000","pad":"` + strings.Repeat("x", scrubProximity+64) + `","SecretAccessKey":"unrelatedFieldFarAway"}`},
		"value too long":          {"application/json", `{"AccessKeyId":"AKIAREALLISTED000000","SecretAccessKey":"` + strings.Repeat("k", scrubMaxValue+1) + `"}`},
	}
	for name, test := range bodies {
		response := scrubResponse(test.contentType, strings.NewReader(test.body), int64(len(test.body)))
		body, reported := scrubbed(t, response)
		if body != test.body || reported != 0 {
			t.Errorf("%s was changed (reported %d): %s", name, reported, body)
		}
	}
}

// Anything that is not XML or JSON, and anything without a body, is not
// touched at all: not read, not re-framed.
func TestScrubSkipsOtherContent(t *testing.T) {
	for name, response := range map[string]*http.Response{
		"binary download": scrubResponse("application/octet-stream", strings.NewReader(scrubSTSJSON), int64(len(scrubSTSJSON))),
		"event stream":    scrubResponse("application/vnd.amazon.eventstream", strings.NewReader(scrubSTSJSON), -1),
		"text":            scrubResponse("text/plain", strings.NewReader(scrubSTSXML), int64(len(scrubSTSXML))),
	} {
		before, length := response.Body, response.ContentLength
		if err := ScrubAWSCredentialResponse(response, func(int) { t.Errorf("%s reported a scrub", name) }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if response.Body != before || response.ContentLength != length {
			t.Errorf("%s was wrapped or re-framed", name)
		}
	}
	upgrade := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	noContent := &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: http.NoBody}
	for _, response := range []*http.Response{upgrade, noContent, nil} {
		var before io.ReadCloser
		if response != nil {
			before = response.Body
		}
		if err := ScrubAWSCredentialResponse(response, nil); err != nil || (response != nil && response.Body != before) {
			t.Fatalf("a response without a readable body was touched: %v", err)
		}
	}
}

// trickleReader hands the body over a few bytes at a time, as a chunked
// response does, so every match straddles a read.
type trickleReader struct {
	data []byte
	step int
}

func (r *trickleReader) Read(destination []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	count := r.step
	if count > len(r.data) {
		count = len(r.data)
	}
	if count > len(destination) {
		count = len(destination)
	}
	copy(destination, r.data[:count])
	r.data = r.data[count:]
	return count, nil
}

func TestScrubHandlesChunkedBodiesOfUnknownLength(t *testing.T) {
	for _, step := range []int{1, 7, 64, 4096} {
		for name, document := range map[string]string{"xml": scrubSTSXML, "json": scrubSTSJSON} {
			contentType := "text/xml"
			if name == "json" {
				contentType = "application/json"
			}
			response := scrubResponse(contentType, &trickleReader{data: []byte(document), step: step}, -1)
			body, reported := scrubbed(t, response)
			assertNoMintedMaterial(t, body)
			if reported != 3 || strings.Count(body, scrubMarker) != 3 {
				t.Fatalf("%s in %d-byte reads: replaced %d, reported %d", name, step, strings.Count(body, scrubMarker), reported)
			}
		}
	}
}

// There is no size limit: a body far larger than the scanner's window is
// streamed, never held whole, and credential material anywhere in it is
// replaced while the rest arrives byte for byte.
func TestScrubHandlesOversizedBodies(t *testing.T) {
	filler := func(index int) string {
		return `{"index":` + strconv.Itoa(index) + `,"payload":"` + strings.Repeat("d", 900) + `","AccessKeyId":"AKIAREALLISTED000000"},` + "\n"
	}
	var document strings.Builder
	document.WriteString("[")
	const records = 12000 // about 11 MiB, larger than any in-memory buffer the proxy uses
	positions := map[int]bool{0: true, records / 2: true, records - 1: true}
	for index := 0; index < records; index++ {
		document.WriteString(filler(index))
		if positions[index] {
			document.WriteString(scrubSTSJSON + ",\n")
		}
	}
	document.WriteString("null]")
	source := document.String()
	if len(source) < 10<<20 {
		t.Fatalf("test body is only %d bytes", len(source))
	}
	for _, step := range []int{32 << 10, 1500} {
		response := scrubResponse("application/json", &trickleReader{data: []byte(source), step: step}, int64(len(source)))
		scrubber := response
		if err := ScrubAWSCredentialResponse(scrubber, nil); err != nil {
			t.Fatal(err)
		}
		reader, ok := response.Body.(*scrubbingReadCloser)
		if !ok {
			t.Fatal("the body was not wrapped")
		}
		var output bytes.Buffer
		buffer := make([]byte, 8<<10)
		largestWindow := 0
		for {
			read, err := reader.Read(buffer)
			output.Write(buffer[:read])
			if held := len(reader.pending) + len(reader.output); held > largestWindow {
				largestWindow = held
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
				break
			}
		}
		body := output.String()
		assertNoMintedMaterial(t, body)
		if reader.values != 9 || strings.Count(body, scrubMarker) != 9 {
			t.Fatalf("replaced %d values in a %d-byte body (step %d)", reader.values, len(source), step)
		}
		// Everything that is not credential material is unchanged, lone
		// access key IDs included.
		want := strings.NewReplacer(scrubTestAccessKeyID, scrubMarker, scrubTestSecretKey, scrubMarker, scrubTestToken, scrubMarker).Replace(source)
		if body != want {
			t.Fatalf("the oversized body was altered beyond the credential values (step %d)", step)
		}
		if limit := scrubHoldback + 3*(32<<10); largestWindow > limit {
			t.Fatalf("the scrubber held %d bytes at once, more than its window of %d", largestWindow, limit)
		}
	}
}

func gzipBytes(t *testing.T, plain string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func gunzip(t *testing.T, compressed []byte) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

func TestScrubHandlesCompressedBodies(t *testing.T) {
	// Credential material inside a gzip body: decoded, replaced, re-encoded,
	// with a Content-Length that matches what is sent.
	compressed := gzipBytes(t, scrubSTSXML)
	response := scrubResponse("text/xml", bytes.NewReader(compressed), int64(len(compressed)))
	response.Header.Set("Content-Encoding", "gzip")
	response.Header.Set("Content-MD5", "stale")
	reported := 0
	if err := ScrubAWSCredentialResponse(response, func(values int) { reported += values }); err != nil {
		t.Fatal(err)
	}
	sent, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sent, []byte(scrubTestSecretKey)) || bytes.Equal(sent, compressed) {
		t.Fatal("the gzip body was passed on unchanged")
	}
	plain := gunzip(t, sent)
	assertNoMintedMaterial(t, plain)
	if reported != 3 || strings.Count(plain, scrubMarker) != 3 || !strings.Contains(plain, "<Expiration>2026-11-14T11:00:00Z</Expiration>") {
		t.Fatalf("reported %d, body %s", reported, plain)
	}
	if response.ContentLength != int64(len(sent)) || response.Header.Get("Content-Length") != strconv.Itoa(len(sent)) ||
		response.Header.Get("Content-Encoding") != "gzip" || response.Header.Get("Content-MD5") != "" {
		t.Fatalf("framing after re-encoding: length=%d headers=%v, sent %d bytes", response.ContentLength, response.Header, len(sent))
	}

	// A gzip body without credential material is passed on byte for byte.
	clean := gzipBytes(t, `<ListAccessKeysResult><AccessKeyId>AKIAREALLISTED000000</AccessKeyId></ListAccessKeysResult>`)
	untouched := scrubResponse("text/xml", bytes.NewReader(clean), int64(len(clean)))
	untouched.Header.Set("Content-Encoding", "gzip")
	if err := ScrubAWSCredentialResponse(untouched, func(int) { t.Error("a clean gzip body reported a scrub") }); err != nil {
		t.Fatal(err)
	}
	if passed, _ := io.ReadAll(untouched.Body); !bytes.Equal(passed, clean) || untouched.ContentLength != int64(len(clean)) ||
		untouched.Header.Get("Content-Length") != strconv.Itoa(len(clean)) {
		t.Fatal("a clean gzip body was changed")
	}

	// What cannot be inspected is refused, never passed on.
	for name, refused := range map[string]*http.Response{
		"brotli":         withEncoding(scrubResponse("application/json", strings.NewReader(scrubSTSJSON), -1), "br"),
		"stacked":        withEncoding(scrubResponse("application/json", bytes.NewReader(compressed), -1), "gzip, gzip"),
		"not gzip":       withEncoding(scrubResponse("application/json", strings.NewReader(scrubSTSJSON), -1), "gzip"),
		"truncated gzip": withEncoding(scrubResponse("text/xml", bytes.NewReader(compressed[:len(compressed)-6]), -1), "gzip"),
		"oversized gzip": withEncoding(scrubResponse("text/xml", io.LimitReader(zeroReader{}, defaultAWSBodyBufferBytes+2), -1), "gzip"),
	} {
		if err := ScrubAWSCredentialResponse(refused, nil); !errors.Is(err, ErrScrubUninspectable) {
			t.Errorf("%s: err = %v, want the response refused", name, err)
		}
	}
	// An explicit identity encoding is an ordinary body.
	identity := withEncoding(scrubResponse("application/json", strings.NewReader(scrubSTSJSON), int64(len(scrubSTSJSON))), "identity")
	if body, reported := scrubbed(t, identity); reported != 3 || strings.Contains(body, scrubTestSecretKey) {
		t.Fatalf("identity-encoded body: reported %d", reported)
	}
}

func withEncoding(response *http.Response, encoding string) *http.Response {
	response.Header.Set("Content-Encoding", encoding)
	return response
}

type zeroReader struct{}

func (zeroReader) Read(destination []byte) (int, error) {
	clear(destination)
	return len(destination), nil
}

// The count is reported even when the Agent stops reading: closing the body
// reports what was replaced so far.
func TestScrubReportsOnCloseAndNeverReportsAValue(t *testing.T) {
	response := scrubResponse("text/xml", strings.NewReader(scrubSTSXML+strings.Repeat(" ", 4*scrubHoldback)), -1)
	reported := -1
	if err := ScrubAWSCredentialResponse(response, func(values int) { reported = values }); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(scrubSTSXML)+scrubHoldback)
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		t.Fatal(err)
	}
	if reported != -1 {
		t.Fatal("the scrub was reported before the body ended")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if reported != 3 {
		t.Fatalf("reported %d on close", reported)
	}
	assertNoMintedMaterial(t, string(buffer))
}
