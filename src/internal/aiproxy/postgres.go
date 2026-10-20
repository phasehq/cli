package aiproxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" // PostgreSQL's legacy wire authentication requires MD5.
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

const maxPGMessageBytes = 16 << 20

var (
	errPostgresUpstreamUnavailable         = errors.New("PostgreSQL upstream is unavailable")
	errPostgresUpstreamTLSRequired         = errors.New("PostgreSQL upstream TLS is required")
	errPostgresUpstreamTLSFailed           = errors.New("PostgreSQL upstream TLS verification failed")
	errPostgresUpstreamCredentialRejected  = errors.New("PostgreSQL upstream rejected the credential")
	errPostgresUpstreamDatabaseUnavailable = errors.New("PostgreSQL upstream database is unavailable")
	errPostgresUpstreamRejected            = errors.New("PostgreSQL upstream rejected the connection")
	errPostgresUpstreamProtocol            = errors.New("PostgreSQL upstream protocol is unsupported")
	errPostgresUpstreamStartupSetting      = errors.New("PostgreSQL upstream rejected a client startup setting")
)

type pgSessionIdentity struct {
	route        protocolRoute
	username     string
	passwordHash [sha256.Size]byte
}

func postgresIdentity(binding *binding) (pgSessionIdentity, string, error) {
	route, err := routeForBinding(binding, "postgres", 5432)
	if err != nil {
		return pgSessionIdentity{}, "", err
	}
	usernameField := tcpRoleField(binding.connection.Injection.ValueFrom.Fields, "username")
	passwordField := tcpRoleField(binding.connection.Injection.ValueFrom.Fields, "password")
	username, userOK := agentapi.LookupMaterial(binding.connection.Identifiers, usernameField)
	password, passOK := binding.connection.SecretMaterial.Get(passwordField)
	if !userOK || !passOK || username == "" || password == "" {
		return pgSessionIdentity{}, "", errors.New("PostgreSQL credential material is incomplete")
	}
	return pgSessionIdentity{route: route, username: username, passwordHash: sha256.Sum256([]byte(password))}, password, nil
}

func (a *protocolAdapters) handlePostgres(ctx context.Context, client net.Conn, grantID string) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	var err error
	watchDone := make(chan struct{})
	defer close(watchDone)

	certificate := a.serverCertificate
	if certificate == nil {
		certificate, err = a.ca.CertificateForHost("127.0.0.1")
		if err != nil {
			return
		}
	}
	startup, err := readPGStartup(client)
	if err != nil {
		return
	}
	if binary.BigEndian.Uint32(startup[:4]) != 80877103 {
		_ = writePGError(client, "TLS is required by the Phase PostgreSQL proxy")
		return
	}
	if _, err := client.Write([]byte{'S'}); err != nil {
		return
	}
	tlsClient := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12})
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		return
	}
	startup, err = readPGStartup(tlsClient)
	if err != nil {
		return
	}
	if binary.BigEndian.Uint32(startup[:4]) != 196608 {
		_ = writePGError(tlsClient, "unsupported PostgreSQL startup protocol")
		return
	}
	params, err := parsePGStartup(startup[4:])
	if err != nil {
		_ = writePGError(tlsClient, "invalid PostgreSQL startup message")
		return
	}
	if postgresReplicationRequested(params["replication"]) {
		_ = writePGError(tlsClient, "replication connections are not supported by the Phase PostgreSQL proxy")
		return
	}
	if err := writePGAuth(tlsClient, 3, nil); err != nil {
		return
	}
	typeByte, payload, err := readPGMessage(tlsClient)
	if err != nil || typeByte != 'p' {
		return
	}
	provided := strings.TrimSuffix(string(payload), "\x00")
	snapshot, err := a.state.selectProtocolBinding("postgres", params["user"], provided, grantID)
	if err != nil {
		_ = writePGError(tlsClient, "invalid Agent PostgreSQL binding credential")
		return
	}
	defer snapshot.release()
	grantID = snapshot.binding.connection.GrantID
	identity, password, err := postgresIdentity(snapshot.binding)
	if err != nil {
		_ = writePGError(tlsClient, "PostgreSQL credential material is incomplete")
		return
	}
	initialIdentity := identity
	authorization := snapshot.binding.authorizationDecision(time.Now())
	if !authorization.allowed {
		message := "Phase denied use of this Agent connection"
		_ = writePGError(tlsClient, message)
		a.emitProtocolEvent(snapshot.binding, "postgres", "CONNECT", "block", "denied", authorization.reason)
		return
	}
	go a.watchProtocolRoute(ctx, client, grantID, initialIdentity.route, 5432, watchDone)

	upstream, statuses, err := a.connectPostgresUpstream(ctx, snapshot.binding, identity.username, password, params)
	if err != nil {
		message, sqlState, reason := postgresUpstreamClientFailure(err)
		_ = writePGErrorCode(tlsClient, sqlState, message)
		a.emitProtocolEvent(snapshot.binding, "postgres", "AUTH", "error", "error", reason)
		return
	}
	defer upstream.Close()
	current, err := a.state.protocolBinding(grantID, "postgres")
	if err != nil {
		_ = writePGError(tlsClient, "Agent session is unavailable")
		return
	}
	defer current.release()
	currentIdentity, _, err := postgresIdentity(current.binding)
	if err != nil || currentIdentity != identity {
		_ = writePGError(tlsClient, "PostgreSQL credential changed; reconnect through Phase")
		return
	}
	if err := writePGAuth(tlsClient, 0, nil); err != nil {
		return
	}
	// The client sees the server's own ParameterStatus set (server_version,
	// client_encoding, DateStyle, ...) so drivers negotiate against the real
	// session. The backend key stays zeroed: cancellation is not relayed, and
	// the upstream key must not reach the Agent.
	for _, status := range statuses {
		if err := writePGMessage(tlsClient, 'S', status); err != nil {
			return
		}
	}
	_ = writePGMessage(tlsClient, 'K', make([]byte, 8))
	_ = writePGMessage(tlsClient, 'Z', []byte{'I'})
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	a.proxyPGMessages(tlsClient, upstream, grantID, identity, params["database"])
}

func readPGStartup(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length < 8 || length > 64<<10 {
		return nil, errors.New("invalid startup length")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func parsePGStartup(payload []byte) (map[string]string, error) {
	result := map[string]string{}
	parts := bytesSplitNUL(payload)
	if len(parts) < 1 {
		return nil, errors.New("invalid startup")
	}
	for index := 0; index+1 < len(parts); index += 2 {
		if parts[index] == "" {
			break
		}
		result[parts[index]] = parts[index+1]
	}
	if result["user"] == "" {
		return nil, errors.New("missing user")
	}
	if result["database"] == "" {
		result["database"] = result["user"]
	}
	return result, nil
}

func bytesSplitNUL(payload []byte) []string {
	raw := strings.Split(string(payload), "\x00")
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		if value == "" && len(result) > 0 && result[len(result)-1] == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func readPGMessage(reader io.Reader) (byte, []byte, error) {
	var kind [1]byte
	if _, err := io.ReadFull(reader, kind[:]); err != nil {
		return 0, nil, err
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(lengthBytes[:]))
	if length < 4 || length > maxPGMessageBytes {
		return 0, nil, errors.New("invalid PostgreSQL message length")
	}
	payload := make([]byte, length-4)
	_, err := io.ReadFull(reader, payload)
	return kind[0], payload, err
}
func writePGMessage(writer io.Writer, kind byte, payload []byte) error {
	frame := make([]byte, 5+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)+4))
	copy(frame[5:], payload)
	_, err := writer.Write(frame)
	return err
}
func writePGAuth(writer io.Writer, code uint32, data []byte) error {
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload, code)
	copy(payload[4:], data)
	return writePGMessage(writer, 'R', payload)
}
func writePGParameter(writer io.Writer, key, value string) error {
	return writePGMessage(writer, 'S', []byte(key+"\x00"+value+"\x00"))
}
func writePGError(writer io.Writer, message string) error {
	return writePGErrorCode(writer, "42501", message)
}
func writePGErrorCode(writer io.Writer, sqlState, message string) error {
	return writePGErrorResponse(writer, "ERROR", sqlState, message, "", "")
}
func writePGErrorResponse(writer io.Writer, severity, sqlState, message, detail, hint string) error {
	payload := []byte("S" + severity + "\x00C" + sqlState + "\x00M" + message + "\x00")
	if detail != "" {
		payload = append(payload, []byte("D"+detail+"\x00")...)
	}
	if hint != "" {
		payload = append(payload, []byte("H"+hint+"\x00")...)
	}
	payload = append(payload, 0)
	return writePGMessage(writer, 'E', payload)
}

// connectPostgresUpstream authenticates to the upstream as the managed
// identity and returns the established connection together with the
// ParameterStatus payloads the server announced, for replay to the client.
func (a *protocolAdapters) connectPostgresUpstream(ctx context.Context, binding *binding, username, password string, params map[string]string) (net.Conn, [][]byte, error) {
	host, address, err := upstreamAddress(binding.connection, 5432)
	if err != nil {
		return nil, nil, err
	}
	connection, err := a.dial(ctx, "tcp", address)
	if err != nil {
		return nil, nil, errPostgresUpstreamUnavailable
	}
	fail := func(err error) (net.Conn, [][]byte, error) { connection.Close(); return nil, nil, err }
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl, 8)
	binary.BigEndian.PutUint32(ssl[4:], 80877103)
	if _, err = connection.Write(ssl); err != nil {
		return fail(errPostgresUpstreamUnavailable)
	}
	var response [1]byte
	if _, err = io.ReadFull(connection, response[:]); err != nil {
		return fail(errPostgresUpstreamUnavailable)
	}
	switch response[0] {
	case 'S':
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if a.tlsConfig != nil {
			tlsConfig = a.tlsConfig.Clone()
			tlsConfig.ServerName = host
		}
		secure := tls.Client(connection, tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			return fail(errPostgresUpstreamTLSFailed)
		}
		connection = secure
	case 'N':
		// Stock local PostgreSQL containers commonly disable server TLS. The
		// decoy-facing adapter remains TLS-only, while its upstream leg may use
		// plaintext only when the established TCP peer itself is loopback. A
		// configured hostname is never trusted as evidence of locality.
		if !postgresUpstreamIsLoopback(connection) {
			return fail(errPostgresUpstreamTLSRequired)
		}
	default:
		return fail(errPostgresUpstreamProtocol)
	}
	startup := pgStartupPacket(username, params["database"], postgresForwardedStartupParams(params))
	if _, err = connection.Write(startup); err != nil {
		return fail(errPostgresUpstreamUnavailable)
	}
	scram := pgSCRAMState{}
	var statuses [][]byte
	for {
		kind, payload, readErr := readPGMessage(connection)
		if readErr != nil {
			return fail(errPostgresUpstreamUnavailable)
		}
		switch kind {
		case 'S':
			statuses = append(statuses, append([]byte(nil), payload...))
		case 'R':
			if len(payload) < 4 {
				return fail(errPostgresUpstreamProtocol)
			}
			code := binary.BigEndian.Uint32(payload[:4])
			data := payload[4:]
			switch code {
			case 0:
			case 3:
				if err = writePGMessage(connection, 'p', []byte(password+"\x00")); err != nil {
					return fail(errPostgresUpstreamUnavailable)
				}
			case 5:
				if len(data) != 4 {
					return fail(errPostgresUpstreamProtocol)
				}
				value := pgMD5Password(username, password, data)
				if err = writePGMessage(connection, 'p', []byte(value+"\x00")); err != nil {
					return fail(errPostgresUpstreamUnavailable)
				}
			case 10:
				initial, initErr := scram.start(username, password, data)
				if initErr != nil {
					return fail(errPostgresUpstreamProtocol)
				}
				if err = writePGMessage(connection, 'p', initial); err != nil {
					return fail(errPostgresUpstreamUnavailable)
				}
			case 11:
				final, finalErr := scram.continueChallenge(data)
				if finalErr != nil {
					return fail(errPostgresUpstreamProtocol)
				}
				if err = writePGMessage(connection, 'p', final); err != nil {
					return fail(errPostgresUpstreamUnavailable)
				}
			case 12:
				if err = scram.verify(data); err != nil {
					return fail(errPostgresUpstreamProtocol)
				}
			default:
				return fail(errPostgresUpstreamProtocol)
			}
		case 'E':
			switch sqlState := postgresErrorSQLState(payload); {
			case strings.HasPrefix(sqlState, "28"):
				return fail(errPostgresUpstreamCredentialRejected)
			case sqlState == "3D000":
				return fail(errPostgresUpstreamDatabaseUnavailable)
			case sqlState == "42704", sqlState == "22023", sqlState == "22P02", sqlState == "42501":
				// The forwarded client settings were refused (unknown parameter,
				// invalid value, or a privileged option); tell the client why.
				return fail(&postgresStartupSettingError{
					sqlState: sqlState, message: postgresErrorField(payload, 'M'),
				})
			default:
				return fail(errPostgresUpstreamRejected)
			}
		case 'Z':
			return connection, statuses, nil
		}
	}
}

// postgresForwardedStartupParams keeps the client's session settings (options,
// application_name, client_encoding, DateStyle, ...) for the upstream startup
// while dropping what the proxy owns or does not relay.
func postgresForwardedStartupParams(params map[string]string) map[string]string {
	forwarded := map[string]string{}
	for key, value := range params {
		switch {
		case key == "", key == "user", key == "database", key == "replication":
			continue
		case strings.HasPrefix(key, "_pq_."):
			continue
		}
		forwarded[key] = value
	}
	return forwarded
}

func postgresReplicationRequested(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "off", "no", "f", "n":
		return false
	}
	return true
}

func postgresUpstreamIsLoopback(connection net.Conn) bool {
	if connection == nil || connection.RemoteAddr() == nil {
		return false
	}
	if address, ok := connection.RemoteAddr().(*net.TCPAddr); ok {
		return address.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil {
		return false
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	return address != nil && address.IsLoopback()
}

func postgresErrorSQLState(payload []byte) string {
	return postgresErrorField(payload, 'C')
}

// postgresErrorField returns one field of an ErrorResponse payload ('C' for
// the SQLSTATE, 'M' for the message), or "" when it is absent.
func postgresErrorField(payload []byte, wanted byte) string {
	for len(payload) > 0 && payload[0] != 0 {
		field := payload[0]
		payload = payload[1:]
		end := bytes.IndexByte(payload, 0)
		if end < 0 {
			return ""
		}
		if field == wanted {
			return string(payload[:end])
		}
		payload = payload[end+1:]
	}
	return ""
}

// postgresSafeErrorText bounds an upstream message before it is relayed to
// the client: printable characters only, at most 200 of them.
func postgresSafeErrorText(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if builder.Len() >= 200 {
			break
		}
		builder.WriteRune(r)
	}
	return strings.TrimSpace(builder.String())
}

// postgresStartupSettingError carries the upstream's own explanation of a
// refused client startup setting, so the Agent can correct it.
type postgresStartupSettingError struct {
	sqlState string
	message  string
}

func (e *postgresStartupSettingError) Error() string {
	return errPostgresUpstreamStartupSetting.Error()
}
func (e *postgresStartupSettingError) Unwrap() error { return errPostgresUpstreamStartupSetting }

func postgresUpstreamClientFailure(err error) (message, sqlState, reason string) {
	var setting *postgresStartupSettingError
	switch {
	case errors.As(err, &setting):
		message = errPostgresUpstreamStartupSetting.Error()
		if detail := postgresSafeErrorText(setting.message); detail != "" {
			message += ": " + detail
		}
		return message, setting.sqlState, "upstream_rejected_startup_setting"
	case errors.Is(err, errPostgresUpstreamCredentialRejected):
		return "PostgreSQL upstream rejected the configured credential", "28P01", "upstream_credential_rejected"
	case errors.Is(err, errPostgresUpstreamDatabaseUnavailable):
		return "PostgreSQL upstream database is unavailable", "3D000", "upstream_database_unavailable"
	case errors.Is(err, errPostgresUpstreamTLSRequired):
		return "PostgreSQL upstream does not offer TLS; plaintext is allowed only for a loopback endpoint", "08006", "upstream_tls_required"
	case errors.Is(err, errPostgresUpstreamTLSFailed):
		return "PostgreSQL upstream TLS verification failed", "08006", "upstream_tls_failed"
	case errors.Is(err, errPostgresUpstreamUnavailable):
		return "PostgreSQL upstream is unreachable", "08001", "upstream_unavailable"
	case errors.Is(err, errPostgresUpstreamRejected):
		return "PostgreSQL upstream rejected the connection", "08004", "upstream_rejected"
	default:
		return "PostgreSQL upstream connection failed", "08006", "upstream_protocol_error"
	}
}

// pgStartupPacket builds the upstream StartupMessage for the managed identity.
// Client settings in extra follow user and database in a stable order; the
// application_name defaults to the proxy's own when the client sent none.
func pgStartupPacket(user, database string, extra map[string]string) []byte {
	keys := make([]string, 0, len(extra))
	for key := range extra {
		if key != "user" && key != "database" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var payload []byte
	payload = append(payload, "user\x00"+user+"\x00database\x00"+database+"\x00"...)
	if _, named := extra["application_name"]; !named {
		payload = append(payload, "application_name\x00phase-ai-proxy\x00"...)
	}
	for _, key := range keys {
		payload = append(payload, key+"\x00"+extra[key]+"\x00"...)
	}
	payload = append(payload, 0)
	packet := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(packet)))
	binary.BigEndian.PutUint32(packet[4:], 196608)
	copy(packet[8:], payload)
	return packet
}
func pgMD5Password(user, password string, salt []byte) string {
	first := md5.Sum([]byte(password + user))
	inner := hex.EncodeToString(first[:])
	second := md5.Sum(append([]byte(inner), salt...))
	return "md5" + hex.EncodeToString(second[:])
}

type pgSCRAMState struct {
	password, clientFirst, serverFirst, clientFinal string
	serverSignature                                 []byte
}

func (s *pgSCRAMState) start(user, password string, mechanisms []byte) ([]byte, error) {
	if !strings.Contains(string(mechanisms), "SCRAM-SHA-256\x00") {
		return nil, errors.New("SCRAM-SHA-256 unavailable")
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	escaped := strings.ReplaceAll(strings.ReplaceAll(user, "=", "=3D"), ",", "=2C")
	s.password = password
	s.clientFirst = "n=" + escaped + ",r=" + nonce
	message := "n,," + s.clientFirst
	payload := make([]byte, len("SCRAM-SHA-256")+1+4+len(message))
	offset := copy(payload, []byte("SCRAM-SHA-256\x00"))
	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(len(message)))
	copy(payload[offset+4:], message)
	return payload, nil
}
func (s *pgSCRAMState) continueChallenge(data []byte) ([]byte, error) {
	s.serverFirst = string(data)
	attrs := scramAttributes(s.serverFirst)
	nonce, saltRaw, iterationsRaw := attrs["r"], attrs["s"], attrs["i"]
	clientNonce := strings.TrimPrefix(strings.Split(s.clientFirst, ",r=")[1], "")
	if !strings.HasPrefix(nonce, clientNonce) {
		return nil, errors.New("invalid SCRAM nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltRaw)
	if err != nil {
		return nil, err
	}
	iterations, err := strconv.Atoi(iterationsRaw)
	if err != nil || iterations < 4096 || iterations > 1000000 {
		return nil, errors.New("invalid SCRAM iterations")
	}
	s.clientFinal = "c=biws,r=" + nonce
	authMessage := s.clientFirst + "," + s.serverFirst + "," + s.clientFinal
	salted, err := pbkdf2.Key(sha256.New, s.password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	clientKey := hmacSHA256(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	signature := hmacSHA256(stored[:], authMessage)
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ signature[i]
	}
	serverKey := hmacSHA256(salted, "Server Key")
	s.serverSignature = hmacSHA256(serverKey, authMessage)
	return []byte(s.clientFinal + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}
func (s *pgSCRAMState) verify(data []byte) error {
	attrs := scramAttributes(string(data))
	signature, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil || len(signature) != len(s.serverSignature) || subtle.ConstantTimeCompare(signature, s.serverSignature) != 1 {
		return errors.New("invalid SCRAM server signature")
	}
	return nil
}
func scramAttributes(value string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(part, "=")
		if ok {
			result[key] = val
		}
	}
	return result
}
func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (a *protocolAdapters) proxyPGMessages(client, upstream net.Conn, grantID string, identity pgSessionIdentity, database string) {
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	<-done
}
func tcpRoleField(fields map[string]string, role string) string {
	if value := fields[role]; value != "" {
		return value
	}
	camel := strings.ReplaceAll(role, "_", "")
	for key, value := range fields {
		if strings.EqualFold(strings.ReplaceAll(key, "_", ""), camel) {
			return value
		}
	}
	return ""
}
func (a *protocolAdapters) emitProtocolEvent(binding *binding, protocol, method, decision, outcome, reason string) {
	a.emitProtocolEventWithDetail(binding, protocol, method, decision, outcome, reason, map[string]any{})
}

func (a *protocolAdapters) emitProtocolEventWithDetail(binding *binding, protocol, method, decision, outcome, reason string, detail map[string]any) {
	a.events.Emit(agentapi.Event{EventID: randomEventID("event-"), CreatedAt: time.Now().UTC(), GrantID: binding.connection.GrantID, EventType: "request", Protocol: protocol, Method: method, Host: binding.connection.Hosts[0].Value, Provider: binding.connection.ServiceType, ProxyDecision: decision, Outcome: outcome, Reason: reason, CredentialAction: binding.connection.Injection.Action, Detail: detail})
}
