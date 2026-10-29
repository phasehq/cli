package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/phasehq/cli/internal/agentapi"
)

func injectionConnection(t *testing.T, injection map[string]any) agentapi.Connection {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"injection":      injection,
		"identifiers":    map[string]string{},
		"decoyMaterial":  map[string]string{"access_token": "decoy-value"},
		"agentEnv":       map[string]string{},
		"secretMaterial": map[string]string{"access_token": "live-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func awsSessionTokenConnection(t *testing.T, secretMaterial map[string]string) agentapi.Connection {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"injection": map[string]any{
			"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config",
			"valueFrom": map[string]any{
				"source": "credential",
				"fields": map[string]string{
					"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key", "sessionToken": "session_token",
				},
			},
		},
		"connectionConfig": map[string]string{"service": "sts", "region": "us-east-1"},
		"identifiers":      map[string]string{"accessKeyId": "AKIAOPTIONALTOKEN"},
		"decoyMaterial": map[string]string{
			"secretAccessKey": "decoy-secret", "sessionToken": "decoy-session-token",
		},
		"agentEnv":       map[string]string{"AWS_SESSION_TOKEN": "decoy-session-token"},
		"secretMaterial": secretMaterial,
	})
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func signedOptionalTokenRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", nil)
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256.Sum256(nil)
	hash := hex.EncodeToString(payloadHash[:])
	request.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: "AKIAOPTIONALTOKEN", SecretAccessKey: "decoy-secret", SessionToken: "decoy-session-token",
	}, request, hash, "sts", "us-east-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestHeaderInjectionRequiresExactDecoySwap(t *testing.T) {
	connection := injectionConnection(t, map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "access_token"},
	})
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.Header.Set("Authorization", "Bearer decoy-value")
	if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer live-value" {
		t.Fatalf("got %q", got)
	}

	request.Header.Set("Authorization", "Bearer some-other-value")
	_, err := ApplyHTTPInjection(context.Background(), request, connection)
	var injectionErr *InjectionError
	if !errors.As(err, &injectionErr) || injectionErr.Code != InjectionSwapMiss {
		t.Fatalf("expected swap miss, got %v", err)
	}
}

func TestReplacePathRegexRequiresCanonicalReplacement(t *testing.T) {
	base := map[string]any{
		"action": "replace_path_regex", "pattern": `/tokens/[^/]+`, "replacement": "/tokens/{value}",
		"valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"},
	}
	connection := injectionConnection(t, base)
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/tokens/decoy-value", nil)
	if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil {
		t.Fatal(err)
	}
	if request.URL.Path != "/tokens/live-value" {
		t.Fatalf("path = %q", request.URL.Path)
	}

	delete(base, "replacement")
	connection = injectionConnection(t, base)
	request, _ = http.NewRequest(http.MethodGet, "https://example.test/tokens/decoy-value", nil)
	_, err := ApplyHTTPInjection(context.Background(), request, connection)
	var injectionErr *InjectionError
	if !errors.As(err, &injectionErr) || injectionErr.Code != InjectionInvalidTemplate {
		t.Fatalf("empty replacement silently accepted: %v", err)
	}
}

func TestConsoleGoldenContractCamelMaterialInjectsThroughSnakeCaseValueFrom(t *testing.T) {
	payload, err := os.ReadFile("../../internal/agentapi/testdata/open_session_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var session agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatal(err)
	}
	if len(session.Connections) != 1 {
		t.Fatalf("golden connections=%d", len(session.Connections))
	}
	connection := session.Connections[0]
	accessKeyID, ok := agentapi.LookupMaterial(connection.Identifiers, "access_key_id")
	if !ok {
		t.Fatal("golden access key identifier did not resolve")
	}
	liveAccessKeyID, ok := connection.SecretMaterial.Get("access_key_id")
	if !ok || liveAccessKeyID == "" || liveAccessKeyID == accessKeyID {
		t.Fatal("golden contract did not separate live and Agent-visible access-key IDs")
	}
	decoySecret, ok := agentapi.LookupMaterial(connection.DecoyMaterial, "secret_access_key")
	if !ok {
		t.Fatal("golden decoy secret did not resolve")
	}
	decoyToken, ok := agentapi.LookupMaterial(connection.DecoyMaterial, "session_token")
	if !ok {
		t.Fatal("golden decoy session token did not resolve")
	}
	if agentToken, ok := connection.AgentEnv.Get("AWS_SESSION_TOKEN"); !ok || agentToken != decoyToken {
		t.Fatal("golden agent environment did not match the decoy session token")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	payloadHash := sha256.Sum256(nil)
	hash := hex.EncodeToString(payloadHash[:])
	request.Header.Set("X-Amz-Content-Sha256", hash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: accessKeyID, SecretAccessKey: decoySecret, SessionToken: decoyToken,
	}, request, hash, "sts", "us-east-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("X-Amz-Security-Token"); got != decoyToken {
		t.Fatalf("golden request session token=%q, want decoy", got)
	}
	decoyAuthorization := request.Header.Get("Authorization")
	result, err := ApplyHTTPInjection(context.Background(), request, connection)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "aws_sigv4" || result.AWSService != "sts" || result.AWSRegion != "us-east-1" {
		t.Fatalf("injection result=%+v", result)
	}
	if authorization := request.Header.Get("Authorization"); authorization == decoyAuthorization ||
		!strings.Contains(authorization, "Credential="+liveAccessKeyID+"/") || strings.Contains(authorization, accessKeyID) {
		t.Fatalf("golden request was not re-signed: %q", authorization)
	}
	if token := request.Header.Get("X-Amz-Security-Token"); token != "" {
		t.Fatalf("golden request retained decoy session token: %q", token)
	}
}

func TestAWSSigV4InjectionReplacesPresentLiveSessionToken(t *testing.T) {
	connection := awsSessionTokenConnection(t, map[string]string{
		"accessKeyId": "AKIAOPTIONALTOKEN", "secretAccessKey": "live-secret", "sessionToken": "live-session-token",
	})
	request := signedOptionalTokenRequest(t)
	if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("X-Amz-Security-Token"); got != "live-session-token" {
		t.Fatalf("session token=%q, want live token", got)
	}
}

func TestAWSSigV4InjectionRejectsInvalidPresentSessionToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "header break", token: "bad\r\ntoken"},
		{name: "null byte", token: "bad\x00token"},
		{name: "delete byte", token: "bad\x7ftoken"},
		{name: "oversized", token: strings.Repeat("x", maximumInjectionCredentialBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := awsSessionTokenConnection(t, map[string]string{
				"accessKeyId": "AKIAOPTIONALTOKEN", "secretAccessKey": "live-secret", "sessionToken": test.token,
			})
			request := signedOptionalTokenRequest(t)
			_, err := ApplyHTTPInjection(context.Background(), request, connection)
			var injectionErr *InjectionError
			if !errors.As(err, &injectionErr) || injectionErr.Code != InjectionUnsafeValue {
				t.Fatalf("invalid session token error=%+v, want %s", injectionErr, InjectionUnsafeValue)
			}
			if got := request.Header.Get("X-Amz-Security-Token"); got != "decoy-session-token" {
				t.Fatalf("failed injection mutated session token: %q", got)
			}
		})
	}
}

func TestAWSSigV4InjectionPreservesRedactedFailureSubtype(t *testing.T) {
	payload, err := os.ReadFile("../../internal/agentapi/testdata/open_session_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var session agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatal(err)
	}
	connection := session.Connections[0]
	request, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", nil)
	_, err = ApplyHTTPInjection(context.Background(), request, connection)
	var injectionErr *InjectionError
	if !errors.As(err, &injectionErr) || injectionErr.Code != InjectionFinalizerFailed ||
		injectionErr.AWSSigV4Failure != AWSSigV4MissingAuthorization {
		t.Fatalf("AWS injection error=%+v, want %s/%s", injectionErr, InjectionFinalizerFailed, AWSSigV4MissingAuthorization)
	}
	if err.Error() != "credential injection finalizer failed" {
		t.Fatalf("AWS injection error exposed failure detail: %q", err)
	}
}

func TestSemanticMaterialCollisionFailsInjectionClosed(t *testing.T) {
	connection := injectionConnection(t, map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "access_token"},
	})
	connection.DecoyMaterial["accessToken"] = "second-decoy"
	connection.Identifiers["access_token"] = "identifier-fallback"
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.Header.Set("Authorization", "Bearer identifier-fallback")
	_, err := ApplyHTTPInjection(context.Background(), request, connection)
	var injectionErr *InjectionError
	if !errors.As(err, &injectionErr) || injectionErr.Code != InjectionMissingMaterial {
		t.Fatalf("ambiguous material did not fail closed: %v", err)
	}
}

func TestAmbiguousOptionalAWSSessionTokenFailsInjectionClosed(t *testing.T) {
	tests := []struct {
		name           string
		fields         map[string]string
		secretMaterial map[string]string
		want           InjectionErrorCode
	}{
		{
			name: "material aliases",
			fields: map[string]string{
				"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key", "sessionToken": "session_token",
			},
			secretMaterial: map[string]string{
				"accessKeyId": "AKIAAMBIGUOUSTOKEN", "secretAccessKey": "live-secret",
				"sessionToken": "first-token", "session_token": "second-token",
			},
			want: InjectionMissingMaterial,
		},
		{
			name: "role aliases",
			fields: map[string]string{
				"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key",
				"sessionToken": "session_token", "session_token": "other_session_token",
			},
			secretMaterial: map[string]string{
				"accessKeyId": "AKIAAMBIGUOUSTOKEN", "secretAccessKey": "live-secret", "sessionToken": "one-token",
			},
			want: InjectionInvalidTemplate,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"injection": map[string]any{
					"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config",
					"valueFrom": map[string]any{"source": "credential", "fields": test.fields},
				},
				"connectionConfig": map[string]string{"service": "sts", "region": "us-east-1"},
				"identifiers":      map[string]string{"accessKeyId": "AKIAAMBIGUOUSTOKEN"},
				"decoyMaterial":    map[string]string{"secretAccessKey": "decoy-secret"},
				"agentEnv":         map[string]string{},
				"secretMaterial":   test.secretMaterial,
			})
			if err != nil {
				t.Fatal(err)
			}
			var connection agentapi.Connection
			if err := json.Unmarshal(payload, &connection); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", nil)
			payloadHash := sha256.Sum256(nil)
			hash := hex.EncodeToString(payloadHash[:])
			request.Header.Set("X-Amz-Content-Sha256", hash)
			if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
				AccessKeyID: "AKIAAMBIGUOUSTOKEN", SecretAccessKey: "decoy-secret",
			}, request, hash, "sts", "us-east-1", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			_, err = ApplyHTTPInjection(context.Background(), request, connection)
			var injectionErr *InjectionError
			if !errors.As(err, &injectionErr) || injectionErr.Code != test.want {
				t.Fatalf("ambiguous session token error=%v, want %s", err, test.want)
			}
		})
	}
}
