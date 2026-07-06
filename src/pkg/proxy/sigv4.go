package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// AWS SigV4 credential injection.
//
// Unlike a bearer token (a header the proxy can find-and-replace), an AWS
// request is SIGNED: the client computes an HMAC over a canonical form of the
// request using its secret key. Swapping the access key id alone would break the
// signature. So the proxy RE-SIGNS: the agent signs with a built-in dummy key,
// and the proxy recomputes the signature with the live IAM secret over the same
// request, then rewrites the Authorization header with the live access key id.
//
// The proxy reuses the service, region, and signing time the client already
// chose (read from the incoming Authorization scope + X-Amz-Date), and the
// client's payload hash (X-Amz-Content-Sha256). It never has to know which AWS
// service/region the agent is calling — it follows the request.

const (
	awsAuthzPrefix = "AWS4-HMAC-SHA256 "
	amzDateFormat  = "20060102T150405Z"
	// SHA-256 of the empty string; the required payload hash for body-less requests.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// The agent signs with a dummy SECRET access key; the proxy re-signs with the
	// live key upstream, so its value is cosmetic — it only needs a plausible shape
	// for the AWS CLI/SDK to sign without complaint. (The access key id itself is
	// NOT secret and the real one is injected; awsDummyAccessKeyID is only a
	// fallback so a client never falls back to ambient ~/.aws credentials.)
	awsDummyAccessKeyID     = "AKIAPHASE0PROXY0DUMY"
	awsDummySecretAccessKey = "phaseProxyDUMMYsecretKeyDoNotUse00000000"

	awsDefaultAccessKeyIDSecret     = "AWS_ACCESS_KEY_ID"
	awsDefaultSecretAccessKeySecret = "AWS_SECRET_ACCESS_KEY"
	awsDefaultUsernameSecret        = "AWS_IAM_USERNAME"
	awsDefaultSessionTokenSecret    = "AWS_SESSION_TOKEN"
)

var awsSigner = v4.NewSigner()

// isAWSSigV4 reports whether the binding uses the AWS SigV4 re-signing scheme.
func isAWSSigV4(scheme string) bool { return strings.EqualFold(scheme, "aws-sigv4") }

// awsSecretNames resolves the secret NAMES this binding reads live values from,
// applying the conventional defaults so an AWS_POLICY can omit them.
func awsSecretNames(in Inject) (akid, secret, user, token string) {
	akid, secret, user, token = in.AccessKeyID, in.SecretAccessKey, in.Username, in.SessionToken
	if akid == "" {
		akid = awsDefaultAccessKeyIDSecret
	}
	if secret == "" {
		secret = awsDefaultSecretAccessKeySecret
	}
	if user == "" {
		user = awsDefaultUsernameSecret
	}
	if token == "" {
		token = awsDefaultSessionTokenSecret
	}
	return
}

// resignAWS replaces the agent's dummy-signed SigV4 authorization with one signed
// by the live IAM credential. Returns an audit label + whether it re-signed.
func resignAWS(req *http.Request, b *Binding, secrets map[string]string) (string, bool) {
	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, awsAuthzPrefix) {
		// Query-string ("presigned") auth carries the signature in the URL, not a
		// header. Re-signing those needs PresignHTTP (with X-Amz-Expires) — not yet
		// supported; label it accurately instead of pretending it was unsigned.
		if req.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
			return "aws: presigned/query-auth not supported (passthrough)", false
		}
		// Genuinely unsigned request (anonymous / pre-flight); nothing to do.
		return "aws: unsigned request (passthrough)", false
	}

	akidName, secretName, _, tokenName := awsSecretNames(b.Inject)
	liveAKID, liveSecret := secrets[akidName], secrets[secretName]
	if liveAKID == "" || liveSecret == "" {
		return fmt.Sprintf("aws: live creds missing (%s/%s)", akidName, secretName), false
	}

	// Streaming/chunked bodies (aws s3 cp of large objects) sign each chunk off the
	// SEED signature; re-signing only the seed leaves the chunk signatures — chained
	// off the dummy — invalid upstream. Surface it rather than fail opaquely.
	if h := req.Header.Get("X-Amz-Content-Sha256"); strings.HasPrefix(h, "STREAMING-") {
		return "aws: streaming/chunked upload not supported (" + h + ")", false
	}

	_, region, service, ok := parseSigV4Scope(authz)
	if !ok {
		return "aws: could not parse SigV4 scope", false
	}

	signingTime := time.Now().UTC()
	if t, err := time.Parse(amzDateFormat, req.Header.Get("X-Amz-Date")); err == nil {
		signingTime = t
	}

	payloadHash := req.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		var err error
		if payloadHash, err = hashAndRewindBody(req); err != nil {
			return "aws: hashing body failed", false
		}
	}

	// The signer overwrites Authorization and X-Amz-Date; clear the stale signature
	// first so nothing of the dummy identity leaks if signing somehow no-ops.
	req.Header.Del("Authorization")
	creds := aws.Credentials{AccessKeyID: liveAKID, SecretAccessKey: liveSecret}
	// Session token is optional: real IAM-user keys have none (empty → the signer
	// omits X-Amz-Security-Token); an STS-based dynamic secret would supply one.
	if tok := secrets[tokenName]; tok != "" {
		creds.SessionToken = tok
	}
	if err := awsSigner.SignHTTP(context.Background(), creds, req, payloadHash, service, region, signingTime); err != nil {
		return "aws: re-sign failed: " + err.Error(), false
	}
	return fmt.Sprintf("aws-sigv4 resign %s/%s", service, region), true
}

// parseSigV4Scope pulls the region and service out of an Authorization header of
// the form:
//
//	AWS4-HMAC-SHA256 Credential=AKID/20250704/us-east-1/sts/aws4_request, SignedHeaders=..., Signature=...
func parseSigV4Scope(authz string) (date, region, service string, ok bool) {
	rest := strings.TrimPrefix(authz, awsAuthzPrefix)
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "Credential=") {
			continue
		}
		cred := strings.TrimPrefix(part, "Credential=")
		seg := strings.Split(cred, "/") // AKID / date / region / service / aws4_request
		if len(seg) < 5 {
			return "", "", "", false
		}
		return seg[1], seg[2], seg[3], true
	}
	return "", "", "", false
}

// hashAndRewindBody computes the hex SHA-256 of the request body and restores it
// so it can still be forwarded. Used only when the client omitted the
// X-Amz-Content-Sha256 header (uncommon for the AWS CLI/SDK).
func hashAndRewindBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return emptyPayloadSHA256, nil
	}
	data, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	if len(data) == 0 {
		return emptyPayloadSHA256, nil
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
