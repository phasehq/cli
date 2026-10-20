package aiproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type postgresRemoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *postgresRemoteAddrConn) RemoteAddr() net.Addr { return c.remote }

type plaintextPostgresObservation struct {
	startupReceived   bool
	identityMatched   bool
	credentialMatched bool
	forwarded         map[string]string
	error             error
}

func startPlaintextPostgresUpstream(t *testing.T, expectedUser, expectedPassword, expectedDatabase string) (net.Listener, <-chan plaintextPostgresObservation) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	observed := make(chan plaintextPostgresObservation, 1)
	go func() {
		observation := plaintextPostgresObservation{}
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			observation.error = acceptErr
			observed <- observation
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		var sslRequest [8]byte
		if _, readErr := io.ReadFull(connection, sslRequest[:]); readErr != nil {
			observation.error = readErr
			observed <- observation
			return
		}
		if binary.BigEndian.Uint32(sslRequest[:4]) != 8 || binary.BigEndian.Uint32(sslRequest[4:]) != 80877103 {
			observation.error = errors.New("invalid SSLRequest")
			observed <- observation
			return
		}
		if _, writeErr := connection.Write([]byte{'N'}); writeErr != nil {
			observation.error = writeErr
			observed <- observation
			return
		}
		startup, readErr := readPGStartup(connection)
		if readErr != nil {
			// A non-loopback client must close immediately after the server refuses
			// TLS, before sending identity or credential material.
			observed <- observation
			return
		}
		observation.startupReceived = true
		params, parseErr := parsePGStartup(startup[4:])
		if parseErr != nil {
			observation.error = parseErr
			observed <- observation
			return
		}
		observation.identityMatched = params["user"] == expectedUser && params["database"] == expectedDatabase
		observation.forwarded = params
		if writeErr := writePGAuth(connection, 3, nil); writeErr != nil {
			observation.error = writeErr
			observed <- observation
			return
		}
		kind, payload, readErr := readPGMessage(connection)
		if readErr != nil {
			observation.error = readErr
			observed <- observation
			return
		}
		observation.credentialMatched = kind == 'p' && string(payload) == expectedPassword+"\x00"
		if writeErr := writePGAuth(connection, 0, nil); writeErr != nil {
			observation.error = writeErr
			observed <- observation
			return
		}
		// A real server announces its session parameters and backend key
		// before ReadyForQuery; the adapter must relay the former and hide the
		// latter.
		_ = writePGParameter(connection, "server_version", "16.3")
		_ = writePGParameter(connection, "client_encoding", params["client_encoding"])
		_ = writePGMessage(connection, 'K', []byte{1, 2, 3, 4, 5, 6, 7, 8})
		if writeErr := writePGMessage(connection, 'Z', []byte{'I'}); writeErr != nil {
			observation.error = writeErr
		}
		observed <- observation
	}()
	return listener, observed
}

func TestPostgresPlaintextUpstreamIsRestrictedToEstablishedLoopback(t *testing.T) {
	const user, password, database = "phase-user", "test-live-password", "phase-db"
	binding := &binding{connection: agentapi.Connection{
		Protocol: "postgres",
		Hosts:    []agentapi.HostRule{{Match: "exact", Value: "database.internal", Port: 5432}},
	}}

	t.Run("established loopback", func(t *testing.T) {
		listener, observed := startPlaintextPostgresUpstream(t, user, password, database)
		adapters := &protocolAdapters{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		}}
		params := map[string]string{
			"user": "agent-decoy-user", "database": database, "application_name": "psql",
			"options": "-c search_path=tenant", "client_encoding": "LATIN1", "DateStyle": "ISO, DMY",
			"replication": "off", "_pq_.protocol": "x",
		}
		connection, statuses, err := adapters.connectPostgresUpstream(context.Background(), binding, user, password, params)
		if err != nil {
			t.Fatalf("loopback plaintext PostgreSQL was rejected: %v", err)
		}
		_ = connection.Close()
		observation := <-observed
		if observation.error != nil || !observation.startupReceived || !observation.identityMatched || !observation.credentialMatched {
			t.Fatalf("loopback plaintext handshake failed: %+v", observation)
		}
		for key, want := range map[string]string{
			"application_name": "psql", "options": "-c search_path=tenant", "client_encoding": "LATIN1", "DateStyle": "ISO, DMY",
		} {
			if got := observation.forwarded[key]; got != want {
				t.Fatalf("startup %s forwarded as %q, want %q (all: %v)", key, got, want, observation.forwarded)
			}
		}
		for _, dropped := range []string{"replication", "_pq_.protocol"} {
			if _, present := observation.forwarded[dropped]; present {
				t.Fatalf("startup %s must not reach the upstream: %v", dropped, observation.forwarded)
			}
		}
		got := map[string]string{}
		for _, status := range statuses {
			parts := bytesSplitNUL(status)
			if len(parts) >= 2 {
				got[parts[0]] = parts[1]
			}
		}
		if got["server_version"] != "16.3" || got["client_encoding"] != "LATIN1" {
			t.Fatalf("upstream parameter statuses were not collected: %v", got)
		}
	})

	t.Run("non-loopback established peer", func(t *testing.T) {
		listener, observed := startPlaintextPostgresUpstream(t, user, password, database)
		adapters := &protocolAdapters{dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			connection, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return &postgresRemoteAddrConn{
				Conn:   connection,
				remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5432},
			}, nil
		}}
		connection, _, err := adapters.connectPostgresUpstream(context.Background(), binding, user, password, map[string]string{"user": user, "database": database})
		if connection != nil || !errors.Is(err, errPostgresUpstreamTLSRequired) {
			t.Fatalf("non-loopback plaintext result=(%v,%v), want TLS-required failure", connection, err)
		}
		observation := <-observed
		if observation.error != nil || observation.startupReceived || observation.identityMatched || observation.credentialMatched {
			t.Fatalf("credential material was sent after non-loopback TLS refusal: %+v", observation)
		}
	})
}

func TestPostgresUpstreamErrorsAreSafelyClassified(t *testing.T) {
	if code := postgresErrorSQLState([]byte("SERROR\x00C28P01\x00Mpassword authentication failed\x00\x00")); code != "28P01" {
		t.Fatalf("SQLSTATE=%q", code)
	}
	tests := []struct {
		err      error
		message  string
		sqlState string
		reason   string
	}{
		{errPostgresUpstreamCredentialRejected, "PostgreSQL upstream rejected the configured credential", "28P01", "upstream_credential_rejected"},
		{errPostgresUpstreamDatabaseUnavailable, "PostgreSQL upstream database is unavailable", "3D000", "upstream_database_unavailable"},
		{errPostgresUpstreamTLSRequired, "PostgreSQL upstream does not offer TLS; plaintext is allowed only for a loopback endpoint", "08006", "upstream_tls_required"},
		{errPostgresUpstreamUnavailable, "PostgreSQL upstream is unreachable", "08001", "upstream_unavailable"},
	}
	for _, test := range tests {
		message, sqlState, reason := postgresUpstreamClientFailure(test.err)
		if message != test.message || sqlState != test.sqlState || reason != test.reason {
			t.Fatalf("classification for %v = (%q,%q,%q)", test.err, message, sqlState, reason)
		}
	}
	setting := &postgresStartupSettingError{sqlState: "42704", message: "unrecognized configuration parameter \"bogus\"\x01\n" + strings.Repeat("z", 300)}
	message, sqlState, reason := postgresUpstreamClientFailure(fmt.Errorf("wrapped: %w", setting))
	if !strings.HasPrefix(message, "PostgreSQL upstream rejected a client startup setting: unrecognized configuration parameter \"bogus\"") ||
		strings.ContainsAny(message, "\x01\n") || len(message) > 260 || sqlState != "42704" || reason != "upstream_rejected_startup_setting" {
		t.Fatalf("setting rejection classified as (%q,%q,%q)", message, sqlState, reason)
	}
	if postgresErrorField([]byte("SFATAL\x00C42704\x00Munrecognized configuration parameter\x00\x00"), 'M') != "unrecognized configuration parameter" {
		t.Fatal("message field was not extracted")
	}
}

func TestPostgresSnapshotRejectsRefreshedCredential(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}

	initial := postgresRefreshSession(t, client, 1, "old-live-password")
	state, err := newRuntimeStateWithCapability(initial, "postgres-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	snapshot, err := state.protocolBinding("grant-pg", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.release()
	identity, _, err := postgresIdentity(snapshot.binding)
	if err != nil {
		t.Fatal(err)
	}

	refreshed := postgresRefreshSession(t, client, 2, "rotated-live-password")
	if err := state.replaceConfig(&refreshed.Config.SessionConfig); err != nil {
		t.Fatal(err)
	}
	if err := state.validateProtocolBinding(snapshot); err == nil {
		t.Fatal("stale PostgreSQL snapshot survived a config generation")
	}
	current, err := state.protocolBinding("grant-pg", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer current.release()
	refreshedIdentity, _, err := postgresIdentity(current.binding)
	if err != nil || refreshedIdentity == identity {
		t.Fatalf("refreshed PostgreSQL identity did not change: err=%v", err)
	}
}

func TestProtocolConnectionClosesPromptlyOnSessionRevocation(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(postgresRefreshSession(t, client, 1, "live-password"), "postgres-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	snapshot, err := state.protocolBinding("grant-pg", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	route, err := routeForBinding(snapshot.binding, "postgres", 5432)
	if err != nil {
		t.Fatal(err)
	}
	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()
	adapters := &protocolAdapters{state: state}
	stop := make(chan struct{})
	go adapters.watchProtocolRoute(context.Background(), proxySide, "grant-pg", route, 5432, stop)
	state.markRevoked()
	_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err := clientSide.Read(value[:]); err == nil {
		t.Fatal("revoked protocol connection remained open")
	}
	close(stop)
}

func postgresRefreshSession(t *testing.T, client *agentapi.Client, generation int, password string) *airuntime.ProxySession {
	t.Helper()
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "refresh-pg", "sessionCredential": "refresh-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": generation, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-pg", "connectionId": "pg", "credentialId": "pg-cred", "serviceType": "postgres", "protocol": "postgres",
			"hosts":       []any{map[string]any{"match": "exact", "value": "database.internal", "port": 5432}},
			"injection":   map[string]any{"action": "pg_handshake", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}},
			"identifiers": map[string]string{"username": "agent_db_user"}, "decoyMaterial": map[string]string{"password": "decoy-db-password"}, "agentEnv": map[string]string{},
			"secretMaterial": map[string]string{"username": "agent_db_user", "password": password},
			"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		}},
	})
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &airuntime.ProxySession{Config: session, Client: client, CA: ca}
}

func TestPGStartupPacketForwardsClientSettingsDeterministically(t *testing.T) {
	packet := pgStartupPacket("managed", "appdb", map[string]string{
		"options": "-c search_path=tenant", "DateStyle": "ISO", "user": "ignored", "database": "ignored",
	})
	if binary.BigEndian.Uint32(packet[:4]) != uint32(len(packet)) || binary.BigEndian.Uint32(packet[4:8]) != 196608 {
		t.Fatalf("startup header=%x", packet[:8])
	}
	if got, want := string(packet[8:]), "user\x00managed\x00database\x00appdb\x00application_name\x00phase-ai-proxy\x00DateStyle\x00ISO\x00options\x00-c search_path=tenant\x00\x00"; got != want {
		t.Fatalf("startup payload=%q, want %q", got, want)
	}
	named := string(pgStartupPacket("managed", "appdb", map[string]string{"application_name": "psql"})[8:])
	if strings.Contains(named, "phase-ai-proxy") || !strings.Contains(named, "application_name\x00psql\x00") {
		t.Fatalf("client application_name was not kept: %q", named)
	}
	for value, want := range map[string]bool{"": false, "off": false, "0": false, "false": false, "true": true, "database": true, "1": true} {
		if got := postgresReplicationRequested(value); got != want {
			t.Fatalf("replication=%q requested=%v, want %v", value, got, want)
		}
	}
}
