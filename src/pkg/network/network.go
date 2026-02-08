package network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	sdkmisc "github.com/phasehq/golang-sdk/phase/misc"
	sdknetwork "github.com/phasehq/golang-sdk/phase/network"
)

func createHTTPClient() *http.Client {
	client := &http.Client{}
	if !sdkmisc.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

func doRequest(req *http.Request) ([]byte, error) {
	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// FetchPhaseSecretsWithDynamic is like the SDK's FetchPhaseSecrets but adds dynamic/lease headers.
func FetchPhaseSecretsWithDynamic(tokenType, appToken, envID, host, path string, dynamic, lease bool, leaseTTL *int) ([]map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s/service/secrets/", host)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Environment", envID)
	if path != "" {
		req.Header.Set("Path", path)
	}
	if dynamic {
		req.Header.Set("dynamic", "true")
	}
	if lease {
		req.Header.Set("lease", "true")
	}
	if leaseTTL != nil {
		req.Header.Set("lease-ttl", fmt.Sprintf("%d", *leaseTTL))
	}

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}

	var secrets []map[string]interface{}
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode secrets response: %w", err)
	}
	return secrets, nil
}

// ListDynamicSecrets lists dynamic secrets for an app/env.
func ListDynamicSecrets(tokenType, appToken, host, appID, env, path string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	if path != "" {
		params.Set("path", path)
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// CreateDynamicSecretLease generates a lease for a dynamic secret.
func CreateDynamicSecretLease(tokenType, appToken, host, appID, env, secretID string, ttl *int) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	params.Set("id", secretID)
	params.Set("lease", "true")
	if ttl != nil {
		params.Set("ttl", fmt.Sprintf("%d", *ttl))
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// ListDynamicSecretLeases lists leases for dynamic secrets.
func ListDynamicSecretLeases(tokenType, appToken, host, appID, env, secretID string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	if secretID != "" {
		params.Set("secret_id", secretID)
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// RenewDynamicSecretLease renews a lease for a dynamic secret.
func RenewDynamicSecretLease(tokenType, appToken, host, appID, env, leaseID string, ttl int) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	reqURL += "?" + params.Encode()

	payload, _ := json.Marshal(map[string]interface{}{
		"lease_id": leaseID,
		"ttl":      ttl,
	})

	req, err := http.NewRequest("PUT", reqURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// RevokeDynamicSecretLease revokes a lease for a dynamic secret.
func RevokeDynamicSecretLease(tokenType, appToken, host, appID, env, leaseID string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	reqURL += "?" + params.Encode()

	payload, _ := json.Marshal(map[string]interface{}{
		"lease_id": leaseID,
	})

	req, err := http.NewRequest("DELETE", reqURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header = sdknetwork.ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")

	body, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// ExternalIdentityAuthAWS performs AWS IAM authentication against the Phase API.
// encodedURL, encodedHeaders, and encodedBody are already base64-encoded.
func ExternalIdentityAuthAWS(host, serviceAccountID string, ttl *int, encodedURL, encodedHeaders, encodedBody, method string) (map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s/service/public/identities/external/v1/aws/iam/auth/", host)

	payload := map[string]interface{}{
		"account": map[string]interface{}{
			"type": "service",
			"id":   serviceAccountID,
		},
		"awsIam": map[string]interface{}{
			"httpRequestMethod":  method,
			"httpRequestUrl":     encodedURL,
			"httpRequestHeaders": encodedHeaders,
			"httpRequestBody":    encodedBody,
		},
	}
	if ttl != nil {
		payload["tokenRequest"] = map[string]interface{}{
			"ttl": *ttl,
		}
	}

	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := doRequest(req)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}
	return result, nil
}
