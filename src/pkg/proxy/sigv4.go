package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	awsAuthorizationPrefix = "AWS4-HMAC-SHA256 "
	awsDateFormat          = "20060102T150405Z"
	emptyPayloadSHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// awsUnsignedChunkedTrailerPayloadHash is what S3 clients send by default
	// for uploads: an aws-chunked body with no per-chunk signatures and a
	// trailing checksum. Like UNSIGNED-PAYLOAD, only the headers are signed.
	awsUnsignedChunkedTrailerPayloadHash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	defaultAWSBodyBufferBytes = int64(8 << 20)
	maximumAWSBodyBufferBytes = int64(64 << 20)
)

// AWSCredentials is the live credential used only by the proxy when rebuilding
// a request signature.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// AWSSigV4Options describes the identity and scope the proxy expects from an
// agent-signed request. ExpectedAccessKeyID is the exact identifier placed in
// the agent environment. It may be a stable fake identifier and does not need
// to equal the live IAM access-key ID used for the upstream signature.
// ExpectedService and ExpectedRegion are
// optional extra constraints for bindings whose endpoint is not an AWS-owned
// hostname.
type AWSSigV4Options struct {
	ExpectedAccessKeyID string
	ExpectedService     string
	ExpectedRegion      string
	MaxBodyBytes        int64
}

// AWSSigV4Result contains non-secret values useful for proxy audit events.
type AWSSigV4Result struct {
	Service            string
	Region             string
	HostScopeValidated bool
}

// AWSSigV4Failure is a stable machine-readable failure category. Callers must
// fail closed for every category.
type AWSSigV4Failure string

const (
	AWSSigV4InvalidOptions         AWSSigV4Failure = "invalid_options"
	AWSSigV4InvalidRequest         AWSSigV4Failure = "invalid_request"
	AWSSigV4MissingAuthorization   AWSSigV4Failure = "missing_authorization"
	AWSSigV4UnsupportedAlgorithm   AWSSigV4Failure = "unsupported_algorithm"
	AWSSigV4UnsupportedPresigned   AWSSigV4Failure = "unsupported_presigned"
	AWSSigV4UnsupportedStreaming   AWSSigV4Failure = "unsupported_streaming"
	AWSSigV4MalformedAuthorization AWSSigV4Failure = "malformed_authorization"
	AWSSigV4AccessKeyMismatch      AWSSigV4Failure = "access_key_mismatch"
	AWSSigV4InvalidSigningTime     AWSSigV4Failure = "invalid_signing_time"
	AWSSigV4ScopeMismatch          AWSSigV4Failure = "scope_mismatch"
	AWSSigV4MissingCredential      AWSSigV4Failure = "missing_live_credential"
	AWSSigV4InvalidPayloadHash     AWSSigV4Failure = "invalid_payload_hash"
	AWSSigV4BodyTooLarge           AWSSigV4Failure = "body_too_large"
	AWSSigV4BodyReadFailed         AWSSigV4Failure = "body_read_failed"
	AWSSigV4SigningFailed          AWSSigV4Failure = "signing_failed"
)

// AWSSigV4Error is deliberately redacted: it never includes an Authorization
// header, access-key ID, session token, secret, request body, or URL query.
type AWSSigV4Error struct {
	Failure AWSSigV4Failure
}

func (e *AWSSigV4Error) Error() string {
	switch e.Failure {
	case AWSSigV4InvalidOptions:
		return "AWS SigV4 re-signing options are invalid"
	case AWSSigV4InvalidRequest:
		return "AWS SigV4 request is invalid"
	case AWSSigV4MissingAuthorization:
		return "AWS SigV4 Authorization header is required"
	case AWSSigV4UnsupportedAlgorithm:
		return "AWS signing algorithm is not supported"
	case AWSSigV4UnsupportedPresigned:
		return "AWS SigV4 presigned requests are not supported"
	case AWSSigV4UnsupportedStreaming:
		return "AWS SigV4 streaming payloads are not supported"
	case AWSSigV4MalformedAuthorization:
		return "AWS SigV4 Authorization header is malformed"
	case AWSSigV4AccessKeyMismatch:
		return "AWS SigV4 request was not signed with the expected identity"
	case AWSSigV4InvalidSigningTime:
		return "AWS SigV4 signing time is invalid"
	case AWSSigV4ScopeMismatch:
		return "AWS SigV4 credential scope does not match the request endpoint"
	case AWSSigV4MissingCredential:
		return "AWS live signing credential is unavailable"
	case AWSSigV4InvalidPayloadHash:
		return "AWS SigV4 payload hash is invalid"
	case AWSSigV4BodyTooLarge:
		return "AWS request body is too large to hash safely"
	case AWSSigV4BodyReadFailed:
		return "AWS request body could not be hashed"
	case AWSSigV4SigningFailed:
		return "AWS SigV4 re-signing failed"
	default:
		return "AWS SigV4 request was rejected"
	}
}

type sigV4Scope struct {
	accessKeyID  string
	date         string
	region       string
	service      string
	signedHeader map[string]struct{}
}

type sigV4HTTPSigner interface {
	SignHTTP(
		context.Context,
		aws.Credentials,
		*http.Request,
		string,
		string,
		string,
		time.Time,
		...func(*v4.SignerOptions),
	) error
}

var awsSigner sigV4HTTPSigner = v4.NewSigner()

// resignAWSSigV4 atomically replaces an agent-produced SigV4 Authorization
// header with a signature produced from live material. It either commits a
// complete new header set or returns a typed error; callers must never forward
// on error.
func resignAWSSigV4(
	ctx context.Context,
	req *http.Request,
	live AWSCredentials,
	options AWSSigV4Options,
) (AWSSigV4Result, error) {
	if ctx == nil || req == nil || req.URL == nil {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4InvalidRequest, nil)
	}
	if options.ExpectedAccessKeyID == "" || strings.TrimSpace(options.ExpectedAccessKeyID) != options.ExpectedAccessKeyID {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4InvalidOptions, nil)
	}
	if !validAccessKeyID(options.ExpectedAccessKeyID) ||
		(options.ExpectedService != "" && !isScopeToken(options.ExpectedService)) ||
		(options.ExpectedRegion != "" && !isScopeToken(options.ExpectedRegion)) {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4InvalidOptions, nil)
	}
	bodyLimit, err := normalizedAWSBodyLimit(options.MaxBodyBytes)
	if err != nil {
		return AWSSigV4Result{}, err
	}
	if !validAccessKeyID(live.AccessKeyID) || live.SecretAccessKey == "" ||
		strings.ContainsAny(live.SessionToken, "\r\n") {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4MissingCredential, nil)
	}

	presigned, err := hasSigV4QueryAuthentication(req.URL)
	if err != nil {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4InvalidRequest, err)
	}
	if presigned {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4UnsupportedPresigned, nil)
	}

	authorization, present, err := singleHeader(req.Header, "Authorization")
	if err != nil {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4MalformedAuthorization, err)
	}
	if !present {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4MissingAuthorization, nil)
	}
	if !strings.HasPrefix(authorization, awsAuthorizationPrefix) {
		failure := AWSSigV4MalformedAuthorization
		if strings.HasPrefix(authorization, "AWS4-") {
			failure = AWSSigV4UnsupportedAlgorithm
		}
		return AWSSigV4Result{}, sigV4Error(failure, nil)
	}

	scope, err := parseSigV4Authorization(authorization)
	if err != nil {
		return AWSSigV4Result{}, err
	}
	if scope.accessKeyID != options.ExpectedAccessKeyID {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4AccessKeyMismatch, nil)
	}
	if err := validateSigV4SignedHeaders(req, scope); err != nil {
		return AWSSigV4Result{}, err
	}

	signingTime, err := sigV4SigningTime(req.Header, scope)
	if err != nil {
		return AWSSigV4Result{}, err
	}
	host, err := effectiveRequestHostname(req)
	if err != nil {
		return AWSSigV4Result{}, err
	}
	hostService, hostRegion, hostScopeKnown := deriveAWSHostScope(host)
	if !scopeMatches(scope, hostService, hostRegion) ||
		!scopeMatches(scope, options.ExpectedService, options.ExpectedRegion) {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4ScopeMismatch, nil)
	}

	payloadHash, err := sigV4PayloadHash(req, scope.service, bodyLimit)
	if err != nil {
		return AWSSigV4Result{}, err
	}

	// Sign a cloned header map. The original authorization and session-token
	// headers remain untouched unless signing completes and validates below.
	candidate := req.Clone(ctx)
	candidate.Header = req.Header.Clone()
	deleteHeader(candidate.Header, "Authorization")
	deleteHeader(candidate.Header, "X-Amz-Security-Token")
	credentials := aws.Credentials{
		AccessKeyID:     live.AccessKeyID,
		SecretAccessKey: live.SecretAccessKey,
		SessionToken:    live.SessionToken,
	}
	if err := awsSigner.SignHTTP(ctx, credentials, candidate, payloadHash, scope.service, scope.region, signingTime, sigV4SignerOptions(scope.service)); err != nil {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4SigningFailed, err)
	}
	newAuthorization, present, err := singleHeader(candidate.Header, "Authorization")
	if err != nil || !present || !strings.Contains(newAuthorization, "Credential="+live.AccessKeyID+"/") {
		return AWSSigV4Result{}, sigV4Error(AWSSigV4SigningFailed, err)
	}
	if live.SessionToken == "" {
		if _, present, err := singleHeader(candidate.Header, "X-Amz-Security-Token"); err != nil || present {
			return AWSSigV4Result{}, sigV4Error(AWSSigV4SigningFailed, err)
		}
	}

	req.Header = candidate.Header
	return AWSSigV4Result{
		Service:            scope.service,
		Region:             scope.region,
		HostScopeValidated: hostScopeKnown,
	}, nil
}

// sigV4SignerOptions mirrors the per-service signing conventions of the AWS
// SDKs. SigV4 canonicalizes most services' paths by URI-encoding them a second
// time, but the S3 family signs the request path exactly as sent, encoded once.
// Re-signing an S3 key such as "a b" or "a+b" with the default convention
// double-encodes it and S3 answers SignatureDoesNotMatch.
func sigV4SignerOptions(service string) func(*v4.SignerOptions) {
	return func(options *v4.SignerOptions) {
		switch service {
		case "s3", "s3-outposts", "s3-object-lambda", "s3express":
			options.DisableURIPathEscaping = true
		}
	}
}

// ResignAWSSigV4 replaces an agent-produced signature with one generated from
// proxy-only live material. It is exported for the executable Agent proxy;
// all failures remain typed and redacted.
func ResignAWSSigV4(
	ctx context.Context,
	req *http.Request,
	live AWSCredentials,
	options AWSSigV4Options,
) (AWSSigV4Result, error) {
	return resignAWSSigV4(ctx, req, live, options)
}

// CredentialRedaction maps one proxy-only live credential value to its safe
// Agent-visible identifier, decoy, or a fixed redaction marker.
type CredentialRedaction struct {
	Live         string
	AgentVisible string
}

// RedactAWSSigV4Response replaces every exact occurrence of proxy-only live
// AWS material in an upstream response. Headers are rewritten eagerly and the
// body is rewritten as it streams, including matches split across reads.
// A gzip body is checked whole and returned unchanged; other encoded bodies
// are rejected because plaintext redaction is unverifiable.
func RedactAWSSigV4Response(response *http.Response, redactions []CredentialRedaction) error {
	if response == nil {
		return errors.New("AWS response redaction configuration is invalid")
	}
	redactions = append([]CredentialRedaction(nil), redactions...)
	for _, redaction := range redactions {
		if redaction.Live == "" || redaction.AgentVisible == "" || strings.ContainsAny(redaction.AgentVisible, "\r\n\x00") {
			return errors.New("AWS response redaction configuration is invalid")
		}
		for _, forbidden := range redactions {
			if strings.Contains(redaction.AgentVisible, forbidden.Live) {
				return errors.New("AWS response redaction replacement contains live material")
			}
		}
	}
	if len(redactions) == 0 {
		return nil
	}
	sort.SliceStable(redactions, func(left, right int) bool {
		return len(redactions[left].Live) > len(redactions[right].Live)
	})
	response.Status = replaceAWSResponseText(response.Status, redactions)
	response.Header = replaceAWSResponseHeader(response.Header, redactions)
	response.Trailer = replaceAWSResponseHeader(response.Trailer, redactions)
	if response.StatusCode == http.StatusSwitchingProtocols || response.Body == nil || response.Body == http.NoBody {
		return nil
	}
	encoding := strings.TrimSpace(strings.Join(response.Header.Values("Content-Encoding"), ","))
	if strings.EqualFold(encoding, "gzip") {
		return checkGzipAWSResponse(response, redactions)
	}
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return errEncodedAWSResponse
	}
	response.Header.Del("Content-Length")
	response.Header.Del("Content-MD5")
	response.Header.Del("Digest")
	// ETag stays: it names the object version for conditional requests.
	response.ContentLength = -1
	body := response.Body
	var outermost *exactReplacingReadCloser
	for _, redaction := range redactions {
		outermost = &exactReplacingReadCloser{
			source: body, match: []byte(redaction.Live), replacement: []byte(redaction.AgentVisible),
		}
		body = outermost
	}
	outermost.onDone = func() { response.Trailer = replaceAWSResponseHeader(response.Trailer, redactions) }
	response.Body = body
	return nil
}

var errEncodedAWSResponse = errors.New("encoded AWS response cannot be safely redacted")

// checkGzipAWSResponse handles S3 objects stored with Content-Encoding: gzip,
// which S3 returns whatever the request accepts. The bounded body is decoded
// in full and passed on byte for byte only when no live value appears in it.
func checkGzipAWSResponse(response *http.Response, redactions []CredentialRedaction) error {
	if response.ContentLength > defaultAWSBodyBufferBytes {
		return errEncodedAWSResponse
	}
	compressed, err := readBounded(response.Body, defaultAWSBodyBufferBytes)
	_ = response.Body.Close()
	if err != nil {
		return errEncodedAWSResponse
	}
	response.Trailer = replaceAWSResponseHeader(response.Trailer, redactions)
	decoded, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return errEncodedAWSResponse
	}
	var body io.ReadCloser = decoded
	stages := make([]*exactReplacingReadCloser, 0, len(redactions))
	for _, redaction := range redactions {
		if bytes.Contains(compressed, []byte(redaction.Live)) {
			return errEncodedAWSResponse
		}
		stage := &exactReplacingReadCloser{source: body, match: []byte(redaction.Live), replacement: []byte(redaction.AgentVisible)}
		stages = append(stages, stage)
		body = stage
	}
	_, err = io.Copy(io.Discard, body)
	_ = body.Close()
	if err != nil {
		return errEncodedAWSResponse
	}
	for _, stage := range stages {
		if stage.replaced {
			return errEncodedAWSResponse
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(compressed))
	return nil
}

func replaceAWSResponseText(value string, redactions []CredentialRedaction) string {
	for _, redaction := range redactions {
		value = strings.ReplaceAll(value, redaction.Live, redaction.AgentVisible)
	}
	return value
}

func replaceAWSResponseHeader(header http.Header, redactions []CredentialRedaction) http.Header {
	if header == nil {
		return nil
	}
	replaced := make(http.Header, len(header))
	for name, values := range header {
		name = replaceAWSResponseText(name, redactions)
		for _, value := range values {
			replaced[name] = append(replaced[name], replaceAWSResponseText(value, redactions))
		}
	}
	return replaced
}

type exactReplacingReadCloser struct {
	source      io.ReadCloser
	match       []byte
	replacement []byte
	input       []byte
	output      []byte
	readErr     error
	onDone      func()
	done        bool
	replaced    bool
	scratch     [32 << 10]byte
}

func (r *exactReplacingReadCloser) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for len(r.output) == 0 {
		if index := bytes.Index(r.input, r.match); index >= 0 {
			r.output = append(r.output, r.input[:index]...)
			r.output = append(r.output, r.replacement...)
			r.input = r.input[index+len(r.match):]
			r.replaced = true
			continue
		}
		if r.readErr != nil {
			r.output = append(r.output, r.input...)
			r.input = nil
			if len(r.output) == 0 {
				err := r.readErr
				r.finish()
				return 0, err
			}
			break
		}
		if safeBytes := len(r.input) - len(r.match) + 1; safeBytes > 0 {
			r.output = append(r.output, r.input[:safeBytes]...)
			remaining := append([]byte(nil), r.input[safeBytes:]...)
			r.input = remaining
			break
		}
		read, err := r.source.Read(r.scratch[:])
		if read > 0 {
			r.input = append(r.input, r.scratch[:read]...)
		}
		if err != nil {
			r.readErr = err
		}
		if read == 0 && err == nil {
			return 0, nil
		}
	}
	read := copy(destination, r.output)
	r.output = r.output[read:]
	return read, nil
}

func (r *exactReplacingReadCloser) Close() error {
	r.finish()
	return r.source.Close()
}

func (r *exactReplacingReadCloser) finish() {
	if r.done {
		return
	}
	r.done = true
	if r.onDone != nil {
		r.onDone()
	}
	clear(r.match)
	clear(r.replacement)
	clear(r.input)
	r.match = nil
	r.replacement = nil
	r.input = nil
}

func sigV4Error(failure AWSSigV4Failure, _ error) *AWSSigV4Error {
	// Keep the causal error out of the returned value. Body readers and request
	// parsers are attacker-controlled and may include sensitive input in their
	// error strings; the stable Failure code is sufficient for diagnostics.
	return &AWSSigV4Error{Failure: failure}
}

func normalizedAWSBodyLimit(limit int64) (int64, error) {
	if limit == 0 {
		return defaultAWSBodyBufferBytes, nil
	}
	if limit < 0 || limit > maximumAWSBodyBufferBytes {
		return 0, sigV4Error(AWSSigV4InvalidOptions, nil)
	}
	return limit, nil
}

func parseSigV4Authorization(authorization string) (sigV4Scope, error) {
	if !strings.HasPrefix(authorization, awsAuthorizationPrefix) {
		return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}
	rest := strings.TrimPrefix(authorization, awsAuthorizationPrefix)
	fields := make(map[string]string, 3)
	for _, field := range strings.Split(rest, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || value == "" {
			return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
		if key != "Credential" && key != "SignedHeaders" && key != "Signature" {
			return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
		if _, duplicate := fields[key]; duplicate {
			return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
		fields[key] = value
	}
	if len(fields) != 3 || fields["Signature"] != strings.ToLower(fields["Signature"]) ||
		!isHex(fields["Signature"], 64) {
		return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}

	credential := strings.Split(fields["Credential"], "/")
	if len(credential) != 5 || credential[0] == "" || credential[4] != "aws4_request" ||
		!isDate(credential[1]) || !isScopeToken(credential[2]) || !isScopeToken(credential[3]) {
		return sigV4Scope{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}

	signedHeaders, err := parseSignedHeaders(fields["SignedHeaders"])
	if err != nil {
		return sigV4Scope{}, err
	}
	return sigV4Scope{
		accessKeyID:  credential[0],
		date:         credential[1],
		region:       credential[2],
		service:      credential[3],
		signedHeader: signedHeaders,
	}, nil
}

func parseSignedHeaders(value string) (map[string]struct{}, error) {
	parts := strings.Split(value, ";")
	if len(parts) == 0 || !sort.StringsAreSorted(parts) {
		return nil, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}
	result := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" || part != strings.ToLower(part) || !isHeaderToken(part) {
			return nil, sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
		if _, duplicate := result[part]; duplicate {
			return nil, sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
		result[part] = struct{}{}
	}
	if _, ok := result["host"]; !ok {
		return nil, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}
	return result, nil
}

func sigV4SigningTime(headers http.Header, scope sigV4Scope) (time.Time, error) {
	value, present, err := singleHeader(headers, "X-Amz-Date")
	if err != nil || !present {
		return time.Time{}, sigV4Error(AWSSigV4InvalidSigningTime, err)
	}
	if _, signed := scope.signedHeader["x-amz-date"]; !signed {
		return time.Time{}, sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}
	t, err := time.Parse(awsDateFormat, value)
	if err != nil || t.Format("20060102") != scope.date {
		return time.Time{}, sigV4Error(AWSSigV4InvalidSigningTime, err)
	}
	return t, nil
}

func validateSigV4SignedHeaders(req *http.Request, scope sigV4Scope) error {
	for header := range scope.signedHeader {
		switch header {
		case "host":
			continue
		case "content-length":
			if req.ContentLength < 0 {
				return sigV4Error(AWSSigV4MalformedAuthorization, nil)
			}
			continue
		}
		// SigV4 signs repeated values joined by commas, as the signer does when
		// re-signing; headers that must be single are checked where they are read.
		if !headerPresent(req.Header, header) {
			return sigV4Error(AWSSigV4MalformedAuthorization, nil)
		}
	}
	if _, present, err := singleHeader(req.Header, "X-Amz-Security-Token"); err != nil {
		return sigV4Error(AWSSigV4MalformedAuthorization, err)
	} else if _, signed := scope.signedHeader["x-amz-security-token"]; present != signed {
		return sigV4Error(AWSSigV4MalformedAuthorization, nil)
	}
	return nil
}

func sigV4PayloadHash(req *http.Request, service string, limit int64) (string, error) {
	value, present, err := singleHeader(req.Header, "X-Amz-Content-Sha256")
	if err != nil {
		return "", sigV4Error(AWSSigV4InvalidPayloadHash, err)
	}
	if present && value == awsUnsignedChunkedTrailerPayloadHash {
		// The body carries no signature in this mode, so it passes through
		// untouched while the headers are re-signed. Signed-chunk streaming
		// (STREAMING-AWS4-*) derives every chunk signature from the signing key
		// and stays unsupported.
		if service != "s3" || !isUnsignedAWSChunkedTrailerRequest(req) {
			return "", sigV4Error(AWSSigV4UnsupportedStreaming, nil)
		}
		return value, nil
	}
	if isAWSStreamingRequest(req) {
		return "", sigV4Error(AWSSigV4UnsupportedStreaming, nil)
	}
	if present {
		if strings.HasPrefix(value, "STREAMING-") {
			return "", sigV4Error(AWSSigV4UnsupportedStreaming, nil)
		}
		if value == "UNSIGNED-PAYLOAD" {
			if service != "s3" {
				return "", sigV4Error(AWSSigV4InvalidPayloadHash, nil)
			}
			return value, nil
		}
		if value != strings.ToLower(value) || !isHex(value, sha256.Size*2) {
			return "", sigV4Error(AWSSigV4InvalidPayloadHash, nil)
		}
		return value, nil
	}
	return hashRequestBodyPreserving(req, limit)
}

func isAWSStreamingRequest(req *http.Request) bool {
	return hasAWSChunkedEncoding(req) || req.Header.Get("X-Amz-Decoded-Content-Length") != ""
}

func hasAWSChunkedEncoding(req *http.Request) bool {
	for _, value := range req.Header.Values("Content-Encoding") {
		for _, encoding := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(encoding), "aws-chunked") {
				return true
			}
		}
	}
	return false
}

// isUnsignedAWSChunkedTrailerRequest accepts only the exact shape S3 clients
// produce for unsigned chunked uploads: aws-chunked content encoding, a
// decoded length, and one trailing checksum header declared in X-Amz-Trailer.
func isUnsignedAWSChunkedTrailerRequest(req *http.Request) bool {
	if !hasAWSChunkedEncoding(req) {
		return false
	}
	decoded, present, err := singleHeader(req.Header, "X-Amz-Decoded-Content-Length")
	if err != nil || !present {
		return false
	}
	if length, parseErr := strconv.ParseInt(decoded, 10, 64); parseErr != nil || length < 0 {
		return false
	}
	trailer, present, err := singleHeader(req.Header, "X-Amz-Trailer")
	if err != nil || !present {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(trailer)) {
	case "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-crc64nvme", "x-amz-checksum-sha1", "x-amz-checksum-sha256":
		return true
	}
	return false
}

func hashRequestBodyPreserving(req *http.Request, limit int64) (string, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return emptyPayloadSHA256, nil
	}
	if req.ContentLength < -1 {
		return "", sigV4Error(AWSSigV4InvalidRequest, nil)
	}
	if req.ContentLength > limit {
		return "", sigV4Error(AWSSigV4BodyTooLarge, nil)
	}

	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return "", sigV4Error(AWSSigV4BodyReadFailed, err)
		}
		data, readErr := readBounded(body, limit)
		closeErr := body.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", sigV4Error(AWSSigV4BodyReadFailed, closeErr)
		}
		return hashPayload(data), nil
	}

	original := req.Body
	data, readErr := readBounded(original, limit)
	if readErr != nil {
		// readBounded consumes at most limit+1 bytes. Replay that bounded prefix
		// before the unread remainder so even a rejected request remains intact.
		req.Body = &prefixReadCloser{
			Reader: io.MultiReader(bytes.NewReader(data), original),
			Closer: original,
		}
		return "", readErr
	}
	_ = original.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	return hashPayload(data), nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return data, sigV4Error(AWSSigV4BodyReadFailed, err)
	}
	if int64(len(data)) > limit {
		return data, sigV4Error(AWSSigV4BodyTooLarge, nil)
	}
	return data, nil
}

type prefixReadCloser struct {
	io.Reader
	io.Closer
}

func hashPayload(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hasSigV4QueryAuthentication(u *url.URL) (bool, error) {
	if u == nil {
		return false, errors.New("nil URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false, err
	}
	for key := range query {
		switch {
		case strings.EqualFold(key, "X-Amz-Algorithm"),
			strings.EqualFold(key, "X-Amz-Credential"),
			strings.EqualFold(key, "X-Amz-Signature"):
			return true, nil
		}
	}
	return false, nil
}

func singleHeader(headers http.Header, name string) (string, bool, error) {
	var values []string
	for key, candidates := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || strings.ContainsAny(values[0], "\r\n") {
		return "", true, errors.New("duplicate or invalid header")
	}
	return values[0], true, nil
}

// headerPresent reports whether name has a value, and no value breaks a line.
func headerPresent(headers http.Header, name string) bool {
	present := false
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return false
			}
			present = true
		}
	}
	return present
}

func deleteHeader(headers http.Header, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func effectiveRequestHostname(req *http.Request) (string, error) {
	requestHost, requestPort, err := normalizedAuthority(req.Host, req.URL.Scheme)
	if err != nil && req.Host != "" {
		return "", sigV4Error(AWSSigV4InvalidRequest, err)
	}
	urlHost, urlPort, err := normalizedAuthority(req.URL.Host, req.URL.Scheme)
	if err != nil && req.URL.Host != "" {
		return "", sigV4Error(AWSSigV4InvalidRequest, err)
	}
	if requestHost == "" {
		requestHost = urlHost
		requestPort = urlPort
	}
	if requestHost == "" || (urlHost != "" && (requestHost != urlHost || requestPort != urlPort)) {
		return "", sigV4Error(AWSSigV4InvalidRequest, nil)
	}
	return requestHost, nil
}

func normalizedAuthority(hostport, scheme string) (host, port string, err error) {
	if hostport == "" {
		return "", "", nil
	}
	if strings.ContainsAny(hostport, "/\\@") {
		return "", "", errors.New("invalid host")
	}
	parsed, err := url.Parse("//" + hostport)
	if err != nil || parsed.User != nil || parsed.Host != hostport {
		return "", "", errors.New("invalid host")
	}
	host = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return "", "", errors.New("empty host")
	}
	port = parsed.Port()
	if port != "" {
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return "", "", errors.New("invalid port")
		}
	} else if strings.EqualFold(scheme, "https") {
		port = "443"
	} else if strings.EqualFold(scheme, "http") {
		port = "80"
	}
	return host, port, nil
}

func scopeMatches(scope sigV4Scope, service, region string) bool {
	if service != "" && scope.service != service {
		return false
	}
	return region == "" || scope.region == region
}

func deriveAWSHostScope(host string) (service, region string, known bool) {
	if ip := net.ParseIP(host); ip != nil {
		return "", "", false
	}
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	var endpointLabels []string
	switch {
	case hasLabelSuffix(labels, []string{"amazonaws", "com", "cn"}):
		endpointLabels = labels[:len(labels)-3]
	case hasLabelSuffix(labels, []string{"amazonaws", "com"}):
		endpointLabels = labels[:len(labels)-2]
	case hasLabelSuffix(labels, []string{"api", "aws"}):
		endpointLabels = labels[:len(labels)-2]
	case hasLabelSuffix(labels, []string{"on", "aws"}):
		if len(labels) >= 5 && labels[len(labels)-4] == "lambda-url" && isAWSRegion(labels[len(labels)-3]) {
			return "lambda", labels[len(labels)-3], true
		}
		return "", "", false
	default:
		return "", "", false
	}
	if len(endpointLabels) == 0 {
		return "", "", false
	}

	for i, label := range endpointLabels {
		if isAWSRegion(label) {
			candidateRegion := label
			// Most regional endpoints put the signing-name immediately before
			// the region. A small set (notably managed OpenSearch domains) puts
			// it immediately after the region.
			if i+1 < len(endpointLabels) {
				if service = knownAWSPostRegionService(endpointLabels[i+1]); service != "" {
					return service, candidateRegion, true
				}
			}
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if endpointLabels[j] == "dualstack" || endpointLabels[j] == "fips" {
					continue
				}
				if service = knownAWSService(endpointLabels[j]); service != "" {
					return service, candidateRegion, true
				}
			}
		}
		if strings.HasPrefix(label, "s3-") && isAWSRegion(strings.TrimPrefix(label, "s3-")) {
			return "s3", strings.TrimPrefix(label, "s3-"), true
		}
	}

	// Global and virtual-hosted endpoints provide a reliable service but not
	// always a reliable signing region, so only constrain the service.
	for i := len(endpointLabels) - 1; i >= 0; i-- {
		if service = knownAWSService(endpointLabels[i]); service != "" {
			return service, "", true
		}
	}
	return "", "", false
}

func knownAWSPostRegionService(label string) string {
	switch label {
	case "es", "aoss":
		return label
	default:
		return ""
	}
}

func knownAWSService(label string) string {
	label = strings.TrimSuffix(label, "-fips")
	switch label {
	case "s3", "s3-accesspoint", "s3-accelerate", "s3-control", "s3-external-1",
		"s3-object-lambda", "s3-outposts":
		return "s3"
	case "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime":
		return "bedrock"
	case "email":
		return "ses"
	case "sts", "iam", "sqs", "dynamodb", "ec2", "lambda", "execute-api", "kms",
		"secretsmanager", "ssm", "ssmmessages", "ecr", "ecr-public", "codeartifact", "elasticloadbalancing", "rds", "rds-data", "sns",
		"logs", "events", "states", "kinesis", "firehose", "glue", "athena", "cloudformation",
		"cloudtrail", "autoscaling", "application-autoscaling", "elasticache", "redshift",
		"redshift-data", "es", "aoss", "bedrock", "sagemaker", "monitoring", "ses",
		"route53", "cloudfront":
		return label
	default:
		return ""
	}
}

func isAWSRegion(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 3 {
		return false
	}
	switch parts[0] {
	case "af", "ap", "ca", "cn", "eu", "eusc", "il", "me", "mx", "sa", "us":
	default:
		return false
	}
	if _, err := strconv.ParseUint(parts[len(parts)-1], 10, 8); err != nil {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}

func hasLabelSuffix(labels, suffix []string) bool {
	if len(labels) < len(suffix) {
		return false
	}
	for i := range suffix {
		if labels[len(labels)-len(suffix)+i] != suffix[i] {
			return false
		}
	}
	return true
}

func isDate(value string) bool {
	if len(value) != 8 {
		return false
	}
	_, err := time.Parse("20060102", value)
	return err == nil
}

func isScopeToken(value string) bool {
	if value == "" || len(value) > 128 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func isHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func isHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validAccessKeyID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r > '~' || r == '/' || r == ',' {
			return false
		}
	}
	return true
}
