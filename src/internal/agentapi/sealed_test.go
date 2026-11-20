package agentapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/golang-sdk/v2/phase/crypto"
)

const sealedLiveToken = "live-sealed-token-0123456789"

// agentKeyFixture is an Agent's key exchange keypair split the way the Console
// splits it when it mints a key-bearing Agent token.
type agentKeyFixture struct {
	token           string
	publicKey       string
	privateKey      string
	shareA          string
	wrapKey         string
	wrappedKeyShare string
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func newAgentKeyFixture(t *testing.T) agentKeyFixture {
	t.Helper()
	pair, err := crypto.RandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fixture := agentKeyFixture{
		publicKey: hex.EncodeToString(pair.PublicKey[:]), privateKey: hex.EncodeToString(pair.SecretKey[:]),
		shareA: randomHex(t, 32), wrapKey: randomHex(t, 32),
	}
	// share_b = private XOR share_a, wrapped with the token's wrap key.
	shareB, err := crypto.ReconstructSecret(fixture.privateKey, fixture.shareA)
	if err != nil {
		t.Fatal(err)
	}
	fixture.wrappedKeyShare = wrapShare(t, shareB, fixture.wrapKey)
	fixture.token = "pss_agent:v1:" + randomHex(t, 32) + ":" + fixture.publicKey + ":" + fixture.shareA + ":" + fixture.wrapKey
	return fixture
}

func wrapShare(t *testing.T, shareHex, wrapKeyHex string) string {
	t.Helper()
	wrapKeyBytes, err := hex.DecodeString(wrapKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	var wrapKey [32]byte
	copy(wrapKey[:], wrapKeyBytes)
	wrapped, err := crypto.EncryptRaw(shareHex, wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(wrapped)
}

// sealValue does what a member's browser and the Console do: a keypair for the
// Connection, the value sealed to it, and the Connection private key wrapped
// to the Agent's key exchange public key.
func sealValue(t *testing.T, readerPublicKey string, plaintext any) map[string]any {
	t.Helper()
	pair, err := crypto.RandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := hex.EncodeToString(pair.PublicKey[:])
	ciphertext, err := crypto.EncryptAsymmetric(string(encoded), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrappedKey, err := crypto.EncryptAsymmetric(hex.EncodeToString(pair.SecretKey[:]), readerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"version": 1, "keyVersion": 2, "publicKey": publicKey, "ciphertext": ciphertext, "wrappedKey": wrappedKey}
}

func sealedPlaintext(fields map[string]string, hosts ...map[string]any) map[string]any {
	if hosts == nil {
		hosts = []map[string]any{{"match": "exact", "value": "api.example.com", "port": 443}}
	}
	return map[string]any{"v": 1, "hosts": hosts, "fields": fields}
}

func customConnectionPayload(sealed map[string]any) map[string]any {
	connection := map[string]any{
		"grantId": "grant-example", "connectionId": "connection-example", "connectionName": "Example API",
		"credentialId": "connection-example", "credentialName": "Example API", "credentialProvider": "http",
		"credentialRevision": "3", "materialGeneration": "2.3", "serviceType": "http", "protocol": "http",
		"hosts": []any{map[string]any{"match": "exact", "value": "api.example.com", "port": 443, "path": "/v1/*"}},
		"injections": []any{map[string]any{
			"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
			"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
		}},
		"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": "sk-decoy-0123456789abcdef"},
		"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
		"authorization": map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
	}
	if sealed != nil {
		connection["sealedMaterial"] = sealed
	}
	return connection
}

func sessionPayload(wrappedKeyShare string, connections ...map[string]any) map[string]any {
	payload := map[string]any{
		"schemaVersion": 1, "sessionUid": "session-sealed", "sessionCredential": "backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{}, "connections": connections,
	}
	if wrappedKeyShare != "" {
		payload["agentKey"] = map[string]any{"wrappedKeyShare": wrappedKeyShare}
	}
	return payload
}

// openThroughConsole serves one session payload and opens it with a client
// built from token, the way the runtime does.
func openThroughConsole(t *testing.T, token string, payload map[string]any) (*Client, *OpenSessionResponse) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.OpenSession(context.Background(), OpenSessionRequest{WorkflowID: "workflow-1", IdempotencyKey: "proxy-start-sealed"})
	if err != nil {
		t.Fatal(err)
	}
	return client, response
}

func TestSealedLaneOpensTheValueIntoSecretMaterial(t *testing.T) {
	agent := newAgentKeyFixture(t)
	sealed := sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken}))
	var configPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/config/") {
			_ = json.NewEncoder(w).Encode(configPayload)
			return
		}
		_ = json.NewEncoder(w).Encode(sessionPayload(agent.wrappedKeyShare, customConnectionPayload(sealed)))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, agent.token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.OpenSession(context.Background(), OpenSessionRequest{IdempotencyKey: "proxy-start-sealed"})
	if err != nil {
		t.Fatal(err)
	}
	connection := response.Connections[0]
	if live, ok := connection.SecretMaterial.Get("token"); !ok || live != sealedLiveToken {
		t.Fatal("the sealed value was not opened into the secret material")
	}
	if connection.MaterialUnavailable() || connection.MaterialFailure() != "" {
		t.Fatalf("opened Connection reported as unavailable: %q", connection.MaterialFailure())
	}
	if connection.SealedMaterial.KeyVersion != 2 || connection.SealedMaterial.Ciphertext.Reveal() != "" ||
		connection.SealedMaterial.WrappedKey.Reveal() != "" || response.AgentKey != nil {
		t.Fatal("ciphertexts and the wrapped key share must not be kept once the value is open")
	}
	if values := ProxyOnlyCredentialValues(response.Connections); len(values) != 1 || values[0] != sealedLiveToken {
		t.Fatal("an opened value must be guarded like a resolved one")
	}
	if err := ValidateAgentVisibleEnvironment(map[string]string{"LEAK": "x" + sealedLiveToken}, response.Connections); err == nil {
		t.Fatal("an opened value was allowed into the Agent-visible environment")
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	printed := fmt.Sprintf("%v %+v %#v %v %+v %#v %s", response, response, response, connection, connection, connection, encoded) +
		fmt.Sprintf(" %v %+v %#v %v %#v", client, client, client, client.agentKey, *client.agentKey)
	for name, sensitive := range map[string]string{
		"live value": sealedLiveToken, "Agent private key": agent.privateKey, "token share": agent.shareA,
		"wrap key": agent.wrapKey, "wrapped key share": agent.wrappedKeyShare,
		"value ciphertext": sealed["ciphertext"].(string), "wrapped Connection key": sealed["wrappedKey"].(string),
	} {
		if strings.Contains(printed, sensitive) {
			t.Fatalf("%s leaked through formatting or encoding", name)
		}
	}

	// A member replaces the value: the refreshed payload carries a new
	// ciphertext under a new Connection key and no agentKey of its own.
	rotated := sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": "live-sealed-token-rotated"}))
	rotated["keyVersion"] = 3
	configPayload = sessionPayload("", customConnectionPayload(rotated))
	delete(configPayload, "sessionCredential")
	config, err := client.RefreshSession(context.Background(), "session-sealed", "backend-capability")
	if err != nil {
		t.Fatal(err)
	}
	if live, _ := config.Connections[0].SecretMaterial.Get("token"); live != "live-sealed-token-rotated" ||
		config.Connections[0].SealedMaterial.KeyVersion != 3 || config.Connections[0].MaterialUnavailable() {
		t.Fatal("a refreshed sealed value was not opened with the remembered Agent key share")
	}
}

func TestSealedLaneFailureLeavesOnlyThatConnectionUnusable(t *testing.T) {
	agent := newAgentKeyFixture(t)
	stranger := newAgentKeyFixture(t)
	good := sealedPlaintext(map[string]string{"token": sealedLiveToken})
	tamper := func(sealed map[string]any, member string) map[string]any {
		value := sealed[member].(string)
		last := value[len(value)-5]
		replacement := byte('A')
		if last == 'A' {
			replacement = 'B'
		}
		sealed[member] = value[:len(value)-5] + string(replacement) + value[len(value)-4:]
		return sealed
	}
	with := func(sealed map[string]any, member string, value any) map[string]any {
		sealed[member] = value
		return sealed
	}
	tests := []struct {
		name            string
		token           string
		wrappedKeyShare string
		connection      func() map[string]any
		want            string
	}{
		{name: "Connection key wrapped to another Agent", want: SealedFailureConnectionKey, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, stranger.publicKey, good))
		}},
		{name: "tampered wrapped Connection key", want: SealedFailureConnectionKey, connection: func() map[string]any {
			return customConnectionPayload(tamper(sealValue(t, agent.publicKey, good), "wrappedKey"))
		}},
		{name: "tampered value ciphertext", want: SealedFailureValue, connection: func() map[string]any {
			return customConnectionPayload(tamper(sealValue(t, agent.publicKey, good), "ciphertext"))
		}},
		{name: "value sealed to a different Connection key", want: SealedFailureValue, connection: func() map[string]any {
			other := sealValue(t, agent.publicKey, good)
			return customConnectionPayload(with(sealValue(t, agent.publicKey, good), "ciphertext", other["ciphertext"]))
		}},
		{name: "public key swapped", want: SealedFailureValue, connection: func() map[string]any {
			other := sealValue(t, agent.publicKey, good)
			return customConnectionPayload(with(sealValue(t, agent.publicKey, good), "publicKey", other["publicKey"]))
		}},
		{name: "value is not the sealed JSON shape", want: SealedFailureValue, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, "token="+sealedLiveToken))
		}},
		{name: "sealed for another host", want: SealedFailureHostMismatch, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
				map[string]any{"match": "exact", "value": "api.example.org", "port": 443})))
		}},
		{name: "sealed for another port", want: SealedFailureHostMismatch, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
				map[string]any{"match": "exact", "value": "api.example.com", "port": 8443})))
		}},
		{name: "sealed for an exact host, routed by suffix", want: SealedFailureHostMismatch, connection: func() map[string]any {
			connection := customConnectionPayload(sealValue(t, agent.publicKey, good))
			connection["hosts"] = []any{map[string]any{"match": "suffix", "value": "api.example.com", "port": 443}}
			return connection
		}},
		{name: "a host added after sealing", want: SealedFailureHostMismatch, connection: func() map[string]any {
			connection := customConnectionPayload(sealValue(t, agent.publicKey, good))
			connection["hosts"] = []any{
				map[string]any{"match": "exact", "value": "api.example.com", "port": 443},
				map[string]any{"match": "exact", "value": "collector.example.net", "port": 443},
			}
			return connection
		}},
		{name: "a sealed host no longer routed", want: SealedFailureHostMismatch, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
				map[string]any{"match": "exact", "value": "api.example.com", "port": 443},
				map[string]any{"match": "exact", "value": "eu.example.com", "port": 443})))
		}},
		{name: "sealed without a port, routed on one", want: SealedFailureHostMismatch, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
				map[string]any{"match": "exact", "value": "api.example.com"})))
		}},
		{name: "field an injection reads is missing", want: SealedFailureFieldMissing, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"apikey": sealedLiveToken})))
		}},
		{name: "field an injection reads is empty", want: SealedFailureFieldMissing, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": ""})))
		}},
		{name: "unsupported envelope version", want: SealedFailureVersion, connection: func() map[string]any {
			return customConnectionPayload(with(sealValue(t, agent.publicKey, good), "version", 2))
		}},
		{name: "unsupported value version", want: SealedFailureVersion, connection: func() map[string]any {
			value := sealedPlaintext(map[string]string{"token": sealedLiveToken})
			value["v"] = 2
			return customConnectionPayload(sealValue(t, agent.publicKey, value))
		}},
		{name: "value binds something this client does not check", want: SealedFailureValue, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
				map[string]any{"match": "exact", "value": "api.example.com", "port": 443, "path": "/v1/*"})))
		}},
		{name: "both lanes in one payload", want: SealedFailureLanes, connection: func() map[string]any {
			connection := customConnectionPayload(sealValue(t, agent.publicKey, good))
			connection["secretMaterial"] = map[string]string{"token": "resolved-by-the-console"}
			return connection
		}},
		{name: "session carries no Agent key share", want: SealedFailureAgentKey, wrappedKeyShare: "-", connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, good))
		}},
		{name: "Agent key share wrapped for another token", want: SealedFailureAgentKey, wrappedKeyShare: stranger.wrappedKeyShare, connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, good))
		}},
		{name: "Agent key share is not hex", want: SealedFailureAgentKey, wrappedKeyShare: "not-hex", connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, good))
		}},
		{name: "login is not an Agent token", want: SealedFailureAgentKey, token: testToken("pss_user", 1, ""), connection: func() map[string]any {
			return customConnectionPayload(sealValue(t, agent.publicKey, good))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, share := agent.token, agent.wrappedKeyShare
			if test.token != "" {
				token = test.token
			}
			switch test.wrappedKeyShare {
			case "":
			case "-":
				share = ""
			default:
				share = test.wrappedKeyShare
			}
			packaged := map[string]any{
				"grantId": "grant-pg", "connectionId": "connection-pg", "credentialId": "credential-pg",
				"credentialName": "Postgres", "credentialProvider": "postgres", "serviceType": "postgres", "protocol": "postgres",
				"hosts":     []any{map[string]any{"match": "exact", "value": "db.example", "port": 5432}},
				"injection": map[string]any{"action": "pg_handshake"}, "identifiers": map[string]string{"username": "db-user"},
				"decoyMaterial": map[string]string{"password": "pg-decoy"}, "agentEnv": map[string]string{},
				"secretMaterial": map[string]string{"username": "db-user", "password": "pg-live"},
			}
			second := customConnectionPayload(sealValue(t, agent.publicKey, good))
			second["connectionId"], second["grantId"], second["credentialId"] = "connection-second", "grant-second", "connection-second"
			_, response := openThroughConsole(t, token, sessionPayload(share, test.connection(), packaged, second))

			failed := response.Connections[0]
			if !failed.MaterialUnavailable() || failed.MaterialFailure() != test.want {
				t.Fatalf("failure = %q, want %q", failed.MaterialFailure(), test.want)
			}
			if live, ok := failed.SecretMaterial.Get("token"); ok || live != "" || len(failed.SecretMaterial.Clone()) != 0 {
				t.Fatal("a Connection whose sealed value was refused must hold no secret material")
			}
			if failed.SealedMaterial.Ciphertext.Reveal() != "" || failed.SealedMaterial.WrappedKey.Reveal() != "" {
				t.Fatal("refused ciphertexts must not be kept")
			}
			if live, _ := response.Connections[1].SecretMaterial.Get("password"); live != "pg-live" || response.Connections[1].MaterialUnavailable() {
				t.Fatal("a packaged Connection in the same session was affected")
			}
			sibling := response.Connections[2]
			siblingOpens := test.want != SealedFailureAgentKey
			if live, _ := sibling.SecretMaterial.Get("token"); (live == sealedLiveToken) != siblingOpens || sibling.MaterialUnavailable() == siblingOpens {
				t.Fatalf("sibling sealed Connection: opened=%t, want %t", live == sealedLiveToken, siblingOpens)
			}
		})
	}
}

func TestSealedHostsAreComparedAsNormalisedSets(t *testing.T) {
	agent := newAgentKeyFixture(t)
	connection := customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken},
		map[string]any{"match": "suffix", "value": "example.net", "port": 443},
		map[string]any{"match": "exact", "value": "api.example.com", "port": 443},
		map[string]any{"match": "exact", "value": "api.example.com"},
	)))
	// Order, case, a trailing dot, repeated rules and paths do not change the
	// set of hosts a value is bound to.
	connection["hosts"] = []any{
		map[string]any{"match": "exact", "value": "API.Example.com.", "port": 443, "path": "/v1/*"},
		map[string]any{"match": "exact", "value": "api.example.com", "port": 443, "path": "/v2/*"},
		map[string]any{"match": "exact", "value": "api.example.com"},
		map[string]any{"match": "suffix", "value": "example.net", "port": 443},
	}
	_, response := openThroughConsole(t, agent.token, sessionPayload(agent.wrappedKeyShare, connection))
	if response.Connections[0].MaterialUnavailable() {
		t.Fatalf("equal host sets were refused: %s", response.Connections[0].MaterialFailure())
	}
}

func TestSealedLaneCoversEveryInjectionField(t *testing.T) {
	agent := newAgentKeyFixture(t)
	injections := []any{
		map[string]any{"action": "set_header", "name": "X-Api-Key", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}},
		map[string]any{"action": "basic_auth", "name": "Authorization", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}},
	}
	partial := customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken})))
	partial["injections"], partial["identifiers"] = injections, map[string]string{"username": "alice"}
	complete := customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": sealedLiveToken, "password": "live-sealed-password"})))
	complete["injections"], complete["identifiers"] = injections, map[string]string{"username": "alice"}
	complete["connectionId"], complete["grantId"] = "connection-complete", "grant-complete"
	_, response := openThroughConsole(t, agent.token, sessionPayload(agent.wrappedKeyShare, partial, complete))
	if response.Connections[0].MaterialFailure() != SealedFailureFieldMissing {
		t.Fatalf("a value missing the Basic password was accepted: %q", response.Connections[0].MaterialFailure())
	}
	// The username is an identifier, not a sealed field.
	if password, _ := response.Connections[1].SecretMaterial.Get("password"); password != "live-sealed-password" || response.Connections[1].MaterialUnavailable() {
		t.Fatalf("a complete value was refused: %q", response.Connections[1].MaterialFailure())
	}
}

func TestOnlyAnAgentTokenCanOpenSealedMaterial(t *testing.T) {
	for prefix, want := range map[string]bool{"pss_agent": true, "pss_user": false} {
		client, err := NewClient("https://console.phase.dev", testToken(prefix, 1, ""), http.DefaultClient)
		if err != nil {
			t.Fatal(err)
		}
		if client.CanOpenSealedMaterial() != want {
			t.Fatalf("%s: CanOpenSealedMaterial() = %t, want %t", prefix, !want, want)
		}
	}
	serviceAccount, err := NewClient("https://console.phase.dev", testToken("pss_service", 2, ""), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	var missing *Client
	if serviceAccount.CanOpenSealedMaterial() || missing.CanOpenSealedMaterial() {
		t.Fatal("only an Agent token carries the Agent key shares")
	}
}

func TestResolvedLaneAndPackagedConnectionsAreUntouched(t *testing.T) {
	resolved := customConnectionPayload(nil)
	resolved["secretMaterial"] = map[string]string{"token": "resolved-by-the-console"}
	_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", resolved))
	connection := response.Connections[0]
	if live, _ := connection.SecretMaterial.Get("token"); live != "resolved-by-the-console" || connection.MaterialUnavailable() ||
		connection.SealedMaterial != nil || connection.MaterialFailure() != "" {
		t.Fatalf("the resolved lane changed: unavailable=%t", connection.MaterialUnavailable())
	}
	if injections := connection.EffectiveInjections(); len(injections) != 1 || injections[0].WhenAbsent != WhenAbsentAttach ||
		connection.PrimaryInjectionAction() != "set_header" {
		t.Fatalf("injections = %+v", injections)
	}
	packaged := Connection{Injection: Injection{Action: "aws_sigv4"}}
	if injections := packaged.EffectiveInjections(); len(injections) != 1 || injections[0].Action != "aws_sigv4" ||
		injections[0].WhenAbsent != "" || packaged.PrimaryInjectionAction() != "aws_sigv4" {
		t.Fatalf("packaged injections = %+v", injections)
	}
}
