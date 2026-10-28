package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	testExpectedAccessKeyID = "AKIAPHASETEST0000000"
	testDecoySecret         = "phaseTestDecoySecretKey000000000000000"
	testLiveAccessKeyID     = "AKIALIVEEXAMPLE00000"
	testLiveSecret          = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var testSigningTime = time.Date(2026, 7, 12, 8, 30, 0, 0, time.UTC)

func TestResignAWSSigV4MatchesDirectSigning(t *testing.T) {
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	payloadHash := sha256Hex(body)
	agentRequest := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", body)
	agentRequest.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signRequest(t, agentRequest, aws.Credentials{
		// Both values are Agent-visible decoys. The proxy installs the live ID,
		// secret, and optional session token only on the upstream request.
		AccessKeyID:     testExpectedAccessKeyID,
		SecretAccessKey: testDecoySecret,
	}, "sts", "us-east-1", payloadHash)
	agentAuthorization := agentRequest.Header.Get("Authorization")

	result, err := resignAWSSigV4(context.Background(), agentRequest, AWSCredentials{
		AccessKeyID:     testLiveAccessKeyID,
		SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Service != "sts" || result.Region != "us-east-1" || !result.HostScopeValidated {
		t.Fatalf("unexpected result: %+v", result)
	}

	reference := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", body)
	reference.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signRequest(t, reference, aws.Credentials{
		AccessKeyID:     testLiveAccessKeyID,
		SecretAccessKey: testLiveSecret,
	}, "sts", "us-east-1", payloadHash)
	if got, want := agentRequest.Header.Get("Authorization"), reference.Header.Get("Authorization"); got != want {
		t.Fatalf("re-signed authorization differs from direct signing\n got: %s\nwant: %s", got, want)
	}
	if agentRequest.Header.Get("Authorization") == agentAuthorization {
		t.Fatal("Authorization signature was not replaced")
	}
	if strings.Contains(agentRequest.Header.Get("Authorization"), testExpectedAccessKeyID) {
		t.Fatal("Agent-visible access-key ID leaked into upstream Authorization")
	}
	assertRequestBody(t, agentRequest, body)
}

func TestResignAWSSigV4HashesAndPreservesBody(t *testing.T) {
	body := "Action=ListBuckets"
	payloadHash := sha256Hex(body)
	req := newAWSRequest(t, "https://s3.eu-west-1.amazonaws.com/", body)
	// Sign with the payload hash without setting X-Amz-Content-Sha256. The
	// proxy must hash through the bounded GetBody path and keep Body untouched.
	signRequest(t, req, aws.Credentials{
		AccessKeyID:     testExpectedAccessKeyID,
		SecretAccessKey: testDecoySecret,
	}, "s3", "eu-west-1", payloadHash)
	originalBody := req.Body

	_, err := resignAWSSigV4(context.Background(), req, AWSCredentials{
		AccessKeyID:     testLiveAccessKeyID,
		SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if req.Body != originalBody {
		t.Fatal("GetBody hashing path mutated the original request body")
	}
	assertRequestBody(t, req, body)
}

func TestResignAWSSigV4ReplacesOrStripsSessionToken(t *testing.T) {
	const decoyToken = "decoy-session-token"
	tests := []struct {
		name      string
		liveToken string
	}{
		{name: "strip stale token"},
		{name: "replace token", liveToken: "live-session-token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", "")
			req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
			signRequest(t, req, aws.Credentials{
				AccessKeyID:     testExpectedAccessKeyID,
				SecretAccessKey: testDecoySecret,
				SessionToken:    decoyToken,
			}, "sts", "us-east-1", emptyPayloadSHA256)

			_, err := resignAWSSigV4(context.Background(), req, AWSCredentials{
				AccessKeyID:     testLiveAccessKeyID,
				SecretAccessKey: testLiveSecret,
				SessionToken:    test.liveToken,
			}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("X-Amz-Security-Token"); got != test.liveToken {
				t.Fatalf("X-Amz-Security-Token = %q, want %q", got, test.liveToken)
			}
			authorization := req.Header.Get("Authorization")
			if strings.Contains(authorization, decoyToken) {
				t.Fatal("decoy session token leaked into Authorization")
			}
			_, signed := parseAuthorizationSignedHeaders(t, authorization)["x-amz-security-token"]
			if signed != (test.liveToken != "") {
				t.Fatalf("session token signed=%v, live token present=%v", signed, test.liveToken != "")
			}
		})
	}
}

func TestResignAWSSigV4FailsClosedWithoutMutatingHeaders(t *testing.T) {
	valid := func(t *testing.T) *http.Request {
		t.Helper()
		req := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", "")
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
		signRequest(t, req, aws.Credentials{
			AccessKeyID:     testExpectedAccessKeyID,
			SecretAccessKey: testDecoySecret,
		}, "sts", "us-east-1", emptyPayloadSHA256)
		return req
	}

	tests := []struct {
		name    string
		failure AWSSigV4Failure
		mutate  func(*testing.T, *http.Request, *AWSCredentials, *AWSSigV4Options)
	}{
		{
			name: "missing authorization", failure: AWSSigV4MissingAuthorization,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Del("Authorization")
			},
		},
		{
			name: "unsupported algorithm", failure: AWSSigV4UnsupportedAlgorithm,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Set("Authorization", "AWS4-ECDSA-P256-SHA256 Credential=redacted")
			},
		},
		{
			name: "malformed signature", failure: AWSSigV4MalformedAuthorization,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"),
					"Signature=", "Signature=not-hex", 1))
			},
		},
		{
			name: "duplicate authorization", failure: AWSSigV4MalformedAuthorization,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Add("Authorization", req.Header.Get("Authorization"))
			},
		},
		{
			name: "decoy mismatch", failure: AWSSigV4AccessKeyMismatch,
			mutate: func(_ *testing.T, _ *http.Request, _ *AWSCredentials, options *AWSSigV4Options) {
				options.ExpectedAccessKeyID = "AKIAOTHERDECOY000000"
			},
		},
		{
			name: "missing live secret", failure: AWSSigV4MissingCredential,
			mutate: func(_ *testing.T, _ *http.Request, live *AWSCredentials, _ *AWSSigV4Options) {
				live.SecretAccessKey = ""
			},
		},
		{
			name: "invalid signing time", failure: AWSSigV4InvalidSigningTime,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Set("X-Amz-Date", "not-a-date")
			},
		},
		{
			name: "service does not match host", failure: AWSSigV4ScopeMismatch,
			mutate: func(t *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Del("Authorization")
				signRequest(t, req, aws.Credentials{
					AccessKeyID:     testExpectedAccessKeyID,
					SecretAccessKey: testDecoySecret,
				}, "s3", "us-east-1", emptyPayloadSHA256)
			},
		},
		{
			name: "configured scope mismatch", failure: AWSSigV4ScopeMismatch,
			mutate: func(_ *testing.T, _ *http.Request, _ *AWSCredentials, options *AWSSigV4Options) {
				options.ExpectedRegion = "eu-west-1"
			},
		},
		{
			name: "invalid payload hash", failure: AWSSigV4InvalidPayloadHash,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Set("X-Amz-Content-Sha256", "not-a-hash")
			},
		},
		{
			name: "host authority mismatch", failure: AWSSigV4InvalidRequest,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Host = "sts.us-east-1.amazonaws.com:8443"
			},
		},
		{
			name: "streaming payload", failure: AWSSigV4UnsupportedStreaming,
			mutate: func(_ *testing.T, req *http.Request, _ *AWSCredentials, _ *AWSSigV4Options) {
				req.Header.Set("Content-Encoding", "aws-chunked")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := valid(t)
			live := AWSCredentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}
			options := AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID}
			test.mutate(t, req, &live, &options)
			before := req.Header.Clone()
			_, err := resignAWSSigV4(context.Background(), req, live, options)
			assertSigV4Error(t, err, test.failure)
			if !reflect.DeepEqual(req.Header, before) {
				t.Fatalf("request headers mutated on failure\n got: %#v\nwant: %#v", req.Header, before)
			}
		})
	}
}

func TestResignAWSSigV4DoesNotCommitPartialSignerMutation(t *testing.T) {
	req := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", "")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	req.Header.Set("X-Amz-Security-Token", "decoy-session-token")
	signRequest(t, req, aws.Credentials{
		AccessKeyID:     testExpectedAccessKeyID,
		SecretAccessKey: testDecoySecret,
		SessionToken:    "decoy-session-token",
	}, "sts", "us-east-1", emptyPayloadSHA256)
	before := req.Header.Clone()

	originalSigner := awsSigner
	awsSigner = mutatingFailingSigner{err: errors.New("DO-NOT-LOG-SIGNER-DETAIL")}
	t.Cleanup(func() { awsSigner = originalSigner })

	_, err := resignAWSSigV4(context.Background(), req, AWSCredentials{
		AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
	assertSigV4Error(t, err, AWSSigV4SigningFailed)
	if !reflect.DeepEqual(req.Header, before) {
		t.Fatalf("partial signer mutation was committed\n got: %#v\nwant: %#v", req.Header, before)
	}
	if strings.Contains(err.Error(), "DO-NOT-LOG") {
		t.Fatalf("signer error detail leaked: %v", err)
	}
}

func TestResignAWSSigV4RejectsPresignedAndStreamingSignatures(t *testing.T) {
	presigned := newAWSRequest(t,
		"https://s3.us-east-1.amazonaws.com/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=SECRET&X-Amz-Signature=SECRET",
		"")
	_, err := resignAWSSigV4(context.Background(), presigned, AWSCredentials{
		AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
	assertSigV4Error(t, err, AWSSigV4UnsupportedPresigned)

	streaming := newAWSRequest(t, "https://s3.us-east-1.amazonaws.com/bucket/key", "body")
	const streamingHash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streaming.Header.Set("X-Amz-Content-Sha256", streamingHash)
	signRequest(t, streaming, aws.Credentials{
		AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret,
	}, "s3", "us-east-1", streamingHash)
	_, err = resignAWSSigV4(context.Background(), streaming, AWSCredentials{
		AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
	assertSigV4Error(t, err, AWSSigV4UnsupportedStreaming)
}

func TestResignAWSSigV4BoundsAndRestoresOneShotBody(t *testing.T) {
	const body = "body-is-over-the-limit"
	req := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", body)
	payloadHash := sha256Hex(body)
	req.GetBody = nil
	req.ContentLength = -1
	signRequest(t, req, aws.Credentials{
		AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret,
	}, "sts", "us-east-1", payloadHash)
	beforeHeaders := req.Header.Clone()

	_, err := resignAWSSigV4(context.Background(), req, AWSCredentials{
		AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID, MaxBodyBytes: 8})
	assertSigV4Error(t, err, AWSSigV4BodyTooLarge)
	if !reflect.DeepEqual(req.Header, beforeHeaders) {
		t.Fatal("headers changed after body limit rejection")
	}
	assertRequestBody(t, req, body)
}

func TestAWSSigV4ErrorsAreRedacted(t *testing.T) {
	const secretMarker = "DO-NOT-LOG-THIS-SECRET"
	req := newAWSRequest(t, "https://sts.us-east-1.amazonaws.com/", "")
	req.Body = errorReader{err: errors.New(secretMarker)}
	req.GetBody = nil
	req.ContentLength = -1
	signRequest(t, req, aws.Credentials{
		AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret,
	}, "sts", "us-east-1", emptyPayloadSHA256)

	_, err := resignAWSSigV4(context.Background(), req, AWSCredentials{
		AccessKeyID: testLiveAccessKeyID, SecretAccessKey: secretMarker,
	}, AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID})
	assertSigV4Error(t, err, AWSSigV4BodyReadFailed)
	for _, forbidden := range []string{secretMarker, testLiveAccessKeyID, testExpectedAccessKeyID} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked sensitive value %q: %v", forbidden, err)
		}
	}
}

func TestDeriveAWSHostScope(t *testing.T) {
	tests := []struct {
		host    string
		service string
		region  string
		known   bool
	}{
		{host: "sts.us-east-1.amazonaws.com", service: "sts", region: "us-east-1", known: true},
		{host: "ssmmessages.eu-central-1.amazonaws.com", service: "ssmmessages", region: "eu-central-1", known: true},
		{host: "bucket.s3.eu-west-1.amazonaws.com", service: "s3", region: "eu-west-1", known: true},
		{host: "bucket.s3-accelerate.amazonaws.com", service: "s3", known: true},
		{host: "bucket.s3-ap-south-1.amazonaws.com", service: "s3", region: "ap-south-1", known: true},
		{host: "abc.execute-api.us-gov-west-1.amazonaws.com", service: "execute-api", region: "us-gov-west-1", known: true},
		{host: "search-domain.us-west-2.es.amazonaws.com", service: "es", region: "us-west-2", known: true},
		{host: "function.lambda-url.ap-southeast-2.on.aws", service: "lambda", region: "ap-southeast-2", known: true},
		{host: "s3.amazonaws.com", service: "s3", known: true},
		// A virtual-hosted bucket name that merely looks region-like must not
		// be treated as the endpoint's region.
		{host: "bucket-name-1.s3.amazonaws.com", service: "s3", known: true},
		{host: "account.r2.cloudflarestorage.com", known: false},
		{host: "127.0.0.1", known: false},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			service, region, known := deriveAWSHostScope(test.host)
			if service != test.service || region != test.region || known != test.known {
				t.Fatalf("deriveAWSHostScope(%q) = %q, %q, %v; want %q, %q, %v",
					test.host, service, region, known, test.service, test.region, test.known)
			}
		})
	}
}

func TestParseSigV4Authorization(t *testing.T) {
	req := newAWSRequest(t, "https://s3.eu-west-1.amazonaws.com/", "")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	signRequest(t, req, aws.Credentials{
		AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret,
	}, "s3", "eu-west-1", emptyPayloadSHA256)
	scope, err := parseSigV4Authorization(req.Header.Get("Authorization"))
	if err != nil {
		t.Fatal(err)
	}
	if scope.accessKeyID != testExpectedAccessKeyID || scope.date != "20260712" ||
		scope.region != "eu-west-1" || scope.service != "s3" {
		t.Fatalf("unexpected scope: %+v", scope)
	}
}

func newAWSRequest(t *testing.T, rawURL, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	return req
}

func signRequest(
	t *testing.T,
	req *http.Request,
	credentials aws.Credentials,
	service, region, payloadHash string,
) {
	t.Helper()
	if err := v4.NewSigner().SignHTTP(
		context.Background(), credentials, req, payloadHash, service, region, testSigningTime,
	); err != nil {
		t.Fatal(err)
	}
}

func parseAuthorizationSignedHeaders(t *testing.T, authorization string) map[string]struct{} {
	t.Helper()
	scope, err := parseSigV4Authorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	return scope.signedHeader
}

func assertRequestBody(t *testing.T, req *http.Request, want string) {
	t.Helper()
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != want {
		t.Fatalf("request body = %q, want %q", got, want)
	}
}

func assertSigV4Error(t *testing.T, err error, failure AWSSigV4Failure) {
	t.Helper()
	var typed *AWSSigV4Error
	if !errors.As(err, &typed) {
		t.Fatalf("error %v has type %T, want *AWSSigV4Error", err, err)
	}
	if typed.Failure != failure {
		t.Fatalf("SigV4 failure = %q, want %q (error: %v)", typed.Failure, failure, err)
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
func (r errorReader) Close() error             { return nil }

type mutatingFailingSigner struct{ err error }

func (s mutatingFailingSigner) SignHTTP(
	_ context.Context,
	_ aws.Credentials,
	req *http.Request,
	_, _, _ string,
	_ time.Time,
	_ ...func(*v4.SignerOptions),
) error {
	req.Header.Set("Authorization", "partially-mutated")
	req.Header.Set("X-Amz-Security-Token", "partially-mutated")
	return s.err
}

func TestResignAWSSigV4PassesThroughUnsignedChunkedTrailerUpload(t *testing.T) {
	const payloadHash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	chunked := "47\r\n" + strings.Repeat("a", 71) + "\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n"
	build := func(credentials aws.Credentials, service, host, contentSHA256 string, chunkedEncoding bool) *http.Request {
		req := newAWSRequest(t, "https://"+host+"/bucket/key", chunked)
		req.Method = http.MethodPut
		if chunkedEncoding {
			req.Header.Set("Content-Encoding", "aws-chunked")
		}
		req.Header.Set("X-Amz-Decoded-Content-Length", "71")
		req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc64nvme")
		req.Header.Set("X-Amz-Content-Sha256", contentSHA256)
		signRequest(t, req, credentials, service, "eu-central-1", contentSHA256)
		return req
	}
	decoy := aws.Credentials{AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret}
	live := AWSCredentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}
	options := AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID}
	const s3Host = "bucket.s3.eu-central-1.amazonaws.com"

	agentRequest := build(decoy, "s3", s3Host, payloadHash, true)
	result, err := resignAWSSigV4(context.Background(), agentRequest, live, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Service != "s3" || result.Region != "eu-central-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	reference := build(aws.Credentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}, "s3", s3Host, payloadHash, true)
	if got, want := agentRequest.Header.Get("Authorization"), reference.Header.Get("Authorization"); got != want {
		t.Fatalf("re-signed authorization differs from direct signing\n got: %s\nwant: %s", got, want)
	}
	for header, want := range map[string]string{
		"Content-Encoding": "aws-chunked", "X-Amz-Decoded-Content-Length": "71",
		"X-Amz-Trailer": "x-amz-checksum-crc64nvme", "X-Amz-Content-Sha256": payloadHash,
	} {
		if got := agentRequest.Header.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	assertRequestBody(t, agentRequest, chunked)

	_, err = resignAWSSigV4(context.Background(), build(decoy, "s3", s3Host, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", true), live, options)
	assertSigV4Error(t, err, AWSSigV4UnsupportedStreaming)
	_, err = resignAWSSigV4(context.Background(), build(decoy, "sts", "sts.eu-central-1.amazonaws.com", payloadHash, true), live, options)
	assertSigV4Error(t, err, AWSSigV4UnsupportedStreaming)
	_, err = resignAWSSigV4(context.Background(), build(decoy, "s3", s3Host, payloadHash, false), live, options)
	assertSigV4Error(t, err, AWSSigV4UnsupportedStreaming)
}

func TestResignAWSSigV4SignsS3KeysEncodedOnceAndOtherServicesTwice(t *testing.T) {
	s3Options := func(options *v4.SignerOptions) { options.DisableURIPathEscaping = true }
	signWith := func(req *http.Request, credentials aws.Credentials, service, region string, options ...func(*v4.SignerOptions)) {
		t.Helper()
		if err := v4.NewSigner().SignHTTP(context.Background(), credentials, req, emptyPayloadSHA256, service, region, testSigningTime, options...); err != nil {
			t.Fatal(err)
		}
	}
	decoy := aws.Credentials{AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret}
	liveSDK := aws.Credentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}
	live := AWSCredentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}
	options := AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID}

	// The AWS CLI percent-encodes every reserved character in an S3 key once and
	// signs that exact path: space, plus, equals, ampersand, parentheses, star,
	// colon, comma and UTF-8 bytes.
	const encodedKey = "/a%20b%2Bc%3Dd%26e%28f%29%2Ag%3Ah%2Ci%E2%9C%93"
	build := func(rawURL string, credentials aws.Credentials, service, region string, signerOptions ...func(*v4.SignerOptions)) *http.Request {
		req, err := http.NewRequest(http.MethodHead, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = req.URL.Host
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
		signWith(req, credentials, service, region, signerOptions...)
		return req
	}
	const s3URL = "https://bucket.s3.eu-central-1.amazonaws.com" + encodedKey
	agentRequest := build(s3URL, decoy, "s3", "eu-central-1", s3Options)
	if _, err := resignAWSSigV4(context.Background(), agentRequest, live, options); err != nil {
		t.Fatal(err)
	}
	reference := build(s3URL, liveSDK, "s3", "eu-central-1", s3Options)
	if got, want := agentRequest.Header.Get("Authorization"), reference.Header.Get("Authorization"); got != want {
		t.Fatalf("S3 re-signed authorization differs from the S3 client's signing convention\n got: %s\nwant: %s", got, want)
	}
	if agentRequest.URL.EscapedPath() != encodedKey {
		t.Fatalf("request path was rewritten to %q", agentRequest.URL.EscapedPath())
	}

	// Every other service keeps SigV4's default double-encoded canonical path.
	const apiURL = "https://abc123.execute-api.eu-central-1.amazonaws.com/prod/items/a%20b%2Bc"
	apiRequest := build(apiURL, decoy, "execute-api", "eu-central-1")
	if _, err := resignAWSSigV4(context.Background(), apiRequest, live, options); err != nil {
		t.Fatal(err)
	}
	apiReference := build(apiURL, liveSDK, "execute-api", "eu-central-1")
	if got, want := apiRequest.Header.Get("Authorization"), apiReference.Header.Get("Authorization"); got != want {
		t.Fatalf("execute-api re-signed authorization differs from default signing\n got: %s\nwant: %s", got, want)
	}
}

func TestResignAWSSigV4AcceptsRepeatedOrdinarySignedHeaders(t *testing.T) {
	decoy := aws.Credentials{AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret, SessionToken: "decoy-session-token"}
	putObject := func(credentials aws.Credentials) *http.Request {
		req := newAWSRequest(t, "https://bucket.s3.us-east-1.amazonaws.com/key", "hello")
		req.Method = http.MethodPut
		req.Header.Set("X-Amz-Content-Sha256", sha256Hex("hello"))
		req.Header.Add("X-Amz-Meta-Color", "red")
		req.Header.Add("X-Amz-Meta-Color", "blue")
		signRequest(t, req, credentials, "s3", "us-east-1", sha256Hex("hello"))
		return req
	}
	live := AWSCredentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret}
	options := AWSSigV4Options{ExpectedAccessKeyID: testExpectedAccessKeyID}
	req := putObject(decoy)
	if _, err := resignAWSSigV4(context.Background(), req, live, options); err != nil {
		t.Fatal(err)
	}
	reference := putObject(aws.Credentials{AccessKeyID: testLiveAccessKeyID, SecretAccessKey: testLiveSecret})
	if got, want := req.Header.Get("Authorization"), reference.Header.Get("Authorization"); got != want {
		t.Fatalf("re-signed authorization differs from direct signing\n got: %s\nwant: %s", got, want)
	}

	for name, failure := range map[string]AWSSigV4Failure{
		"X-Amz-Date":           AWSSigV4InvalidSigningTime,
		"X-Amz-Content-Sha256": AWSSigV4InvalidPayloadHash,
		"X-Amz-Security-Token": AWSSigV4MalformedAuthorization,
	} {
		repeated := putObject(decoy)
		repeated.Header.Add(name, repeated.Header.Get(name))
		_, err := resignAWSSigV4(context.Background(), repeated, live, options)
		assertSigV4Error(t, err, failure)
	}
}

func TestRedactAWSSigV4ResponseKeepsETag(t *testing.T) {
	const etag = `"5eb63bbbe01eeed093cb22bb8f5acdc3"`
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Etag": {etag}, "Content-Length": {"11"}},
		Body:       io.NopCloser(strings.NewReader("hello world")),
	}
	if err := RedactAWSSigV4Response(response, []CredentialRedaction{{Live: testLiveSecret, AgentVisible: testDecoySecret}}); err != nil {
		t.Fatal(err)
	}
	if got := response.Header.Get("ETag"); got != etag {
		t.Fatalf("ETag = %q, want %q", got, etag)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "hello world" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}
