package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// newSTSRequest builds a request shaped like what the proxy sees after MITM:
// an absolute https URL, Host set, and an STS query-protocol body.
func newSTSRequest(t *testing.T) *http.Request {
	t.Helper()
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "sts.amazonaws.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	return req
}

func sign(t *testing.T, req *http.Request, akid, secret, service, region string, ts time.Time, payloadHash string) {
	t.Helper()
	err := v4.NewSigner().SignHTTP(context.Background(),
		aws.Credentials{AccessKeyID: akid, SecretAccessKey: secret},
		req, payloadHash, service, region, ts)
	if err != nil {
		t.Fatal(err)
	}
}

// TestResignAWSMatchesDirectLiveSigning is the core correctness proof: a request
// the agent signed with the DUMMY key, after resignAWS with the LIVE key, must
// carry the exact Authorization a client would produce signing directly with the
// live key. Equality proves the scope/service/region/time/payload-hash the proxy
// recovered from the incoming request reconstruct the identical signing inputs.
func TestResignAWSMatchesDirectLiveSigning(t *testing.T) {
	const (
		dummyAKID   = awsDummyAccessKeyID
		dummySecret = awsDummySecretAccessKey
		liveAKID    = "AKIALIVEEXAMPLE00000"
		liveSecret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		service     = "sts"
		region      = "us-east-1"
		payloadHash = "ab821ae955788b0e33ebd34c208442ccc1a2b3d3e4f5a6b7c8d9e0f1a2b3c4d5"
	)
	ts := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

	// 1. Agent signs with the dummy credential (what the proxy receives).
	agentReq := newSTSRequest(t)
	agentReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
	sign(t, agentReq, dummyAKID, dummySecret, service, region, ts, payloadHash)
	if !strings.Contains(agentReq.Header.Get("Authorization"), dummyAKID) {
		t.Fatalf("expected dummy AKID in agent authz, got %q", agentReq.Header.Get("Authorization"))
	}

	// 2. Proxy re-signs with the live credential.
	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	secrets := map[string]string{
		awsDefaultAccessKeyIDSecret:     liveAKID,
		awsDefaultSecretAccessKeySecret: liveSecret,
	}
	label, applied := resignAWS(agentReq, b, secrets)
	if !applied {
		t.Fatalf("resignAWS did not apply: %s", label)
	}
	got := agentReq.Header.Get("Authorization")
	if strings.Contains(got, dummyAKID) {
		t.Fatalf("dummy AKID leaked into re-signed authz: %q", got)
	}
	if !strings.Contains(got, liveAKID) {
		t.Fatalf("live AKID missing from re-signed authz: %q", got)
	}

	// 3. Reference: sign a fresh identical request DIRECTLY with the live cred.
	refReq := newSTSRequest(t)
	refReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
	sign(t, refReq, liveAKID, liveSecret, service, region, ts, payloadHash)
	want := refReq.Header.Get("Authorization")

	if got != want {
		t.Fatalf("re-signed authz != direct live signing\n got: %s\nwant: %s", got, want)
	}

	// Body must survive re-signing intact.
	data, _ := io.ReadAll(agentReq.Body)
	if string(data) != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Fatalf("body corrupted after re-sign: %q", data)
	}
}

// TestAgentEnvAWSInjectsRealIdentifiers: only the SECRET access key may be faked;
// the access key id and username are non-secret and injected as their real values.
func TestAgentEnvAWSInjectsRealIdentifiers(t *testing.T) {
	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	const realSecret = "realSecretMustNeverBeInjected0000000000"
	env := b.AgentEnv(map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAREALEXAMPLE00000",
		"AWS_SECRET_ACCESS_KEY": realSecret,
		"AWS_IAM_USERNAME":      "svc-agent",
	})
	if env["AWS_ACCESS_KEY_ID"] != "AKIAREALEXAMPLE00000" {
		t.Errorf("access key id should be the REAL value, got %q", env["AWS_ACCESS_KEY_ID"])
	}
	if env["AWS_IAM_USERNAME"] != "svc-agent" {
		t.Errorf("username should be real, got %q", env["AWS_IAM_USERNAME"])
	}
	if env["AWS_SECRET_ACCESS_KEY"] == realSecret {
		t.Fatal("SECURITY: the real secret access key leaked into the agent env")
	}
	if env["AWS_SECRET_ACCESS_KEY"] != awsDummySecretAccessKey {
		t.Errorf("secret access key should be the dummy, got %q", env["AWS_SECRET_ACCESS_KEY"])
	}

	// No live lease → fall back to a dummy AKID so the client stays on env creds
	// (not ambient ~/.aws), rather than injecting an empty value.
	env2 := (&Binding{Inject: Inject{Scheme: "aws-sigv4"}}).AgentEnv(map[string]string{})
	if env2["AWS_ACCESS_KEY_ID"] != awsDummyAccessKeyID {
		t.Errorf("no-lease fallback should inject the dummy AKID, got %q", env2["AWS_ACCESS_KEY_ID"])
	}
}

func TestParseSigV4Scope(t *testing.T) {
	authz := "AWS4-HMAC-SHA256 Credential=AKIA123/20260705/eu-west-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef"
	date, region, service, ok := parseSigV4Scope(authz)
	if !ok || date != "20260705" || region != "eu-west-1" || service != "s3" {
		t.Fatalf("got date=%q region=%q service=%q ok=%v", date, region, service, ok)
	}
	if _, _, _, ok := parseSigV4Scope("Bearer xyz"); ok {
		t.Fatal("expected non-SigV4 header to fail parsing")
	}
}

// TestResignAWSPresignedNotApplied: query-string (presigned) auth is detected and
// labeled accurately rather than mislabeled "unsigned".
func TestResignAWSPresignedNotApplied(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://s3.amazonaws.com/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20260705%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=abc",
		nil)
	req.Host = "s3.amazonaws.com"
	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	label, applied := resignAWS(req, b, map[string]string{
		awsDefaultAccessKeyIDSecret: "AKIALIVE", awsDefaultSecretAccessKeySecret: "s",
	})
	if applied {
		t.Fatal("presigned request must not be re-signed (not supported)")
	}
	if !strings.Contains(label, "presigned") {
		t.Fatalf("expected presigned label, got %q", label)
	}
}

// TestResignAWSStreamingNotApplied: chunked/streaming uploads are surfaced, not
// silently forwarded (their per-chunk signatures can't be re-signed here).
func TestResignAWSStreamingNotApplied(t *testing.T) {
	req := newSTSRequest(t)
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	sign(t, req, awsDummyAccessKeyID, awsDummySecretAccessKey, "s3", "us-east-1",
		time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	label, applied := resignAWS(req, b, map[string]string{
		awsDefaultAccessKeyIDSecret: "AKIALIVE", awsDefaultSecretAccessKeySecret: "s",
	})
	if applied {
		t.Fatal("streaming upload must not be re-signed")
	}
	if !strings.Contains(label, "streaming") {
		t.Fatalf("expected streaming label, got %q", label)
	}
}

// TestResignAWSSessionToken: when a live session token is present, the re-signed
// request carries X-Amz-Security-Token (STS/temporary-credential support).
func TestResignAWSSessionToken(t *testing.T) {
	req := newSTSRequest(t)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	sign(t, req, awsDummyAccessKeyID, awsDummySecretAccessKey, "sts", "us-east-1",
		time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC), emptyPayloadSHA256)
	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	_, applied := resignAWS(req, b, map[string]string{
		awsDefaultAccessKeyIDSecret:     "AKIALIVE",
		awsDefaultSecretAccessKeySecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		awsDefaultSessionTokenSecret:    "FQoGZXIvYXdzEXAMPLESESSIONTOKEN",
	})
	if !applied {
		t.Fatal("expected re-sign to apply")
	}
	if req.Header.Get("X-Amz-Security-Token") == "" {
		t.Fatal("expected X-Amz-Security-Token on re-signed request with session token")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatalf("session token must be a signed header, got %q", req.Header.Get("Authorization"))
	}
}

// TestResignAWSNoLiveCreds: missing live creds must NOT apply (and must not
// forward the dummy identity as if it were real).
func TestResignAWSNoLiveCreds(t *testing.T) {
	req := newSTSRequest(t)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	sign(t, req, awsDummyAccessKeyID, awsDummySecretAccessKey, "sts", "us-east-1",
		time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC), emptyPayloadSHA256)

	b := &Binding{Inject: Inject{Scheme: "aws-sigv4"}}
	if label, applied := resignAWS(req, b, map[string]string{}); applied {
		t.Fatalf("expected no-apply with missing creds, got applied (%s)", label)
	}
}
