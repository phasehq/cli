package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

type pgEngine struct{}

func (pgEngine) Protocol() string { return "postgres" }

// Handle bridges an agent Postgres connection to the real upstream, injecting
// the real credential during the upstream auth handshake (the agent holds only a
// dummy), and governing + auditing statements. Governs BOTH the simple Query and
// the extended Parse protocol; pumps upstream responses only at the correct
// boundaries (after a Query, and after Sync) — never after every message.
func (pgEngine) Handle(agent net.Conn, dst string, b *Binding, secrets map[string]string, pol *StmtPolicy, who string) {
	be := pgproto3.NewBackend(agent, agent)

	// 1. Agent startup. Decline in-protocol TLS (v1; the agent presents a dummy
	//    and its identity is established out-of-band, so agent-side auth = trust).
	startup, err := pgReadStartup(be, agent)
	if err != nil {
		return
	}
	pol.Session(fmt.Sprintf("agent requested user=%q db=%q (ignored; injecting real creds) -> %s",
		startup.Parameters["user"], startup.Parameters["database"], dst))

	// 2. Connect upstream with the REAL credential. pgconn negotiates whatever the
	//    server requires (trust / md5 / SCRAM-SHA-256) using the real password.
	dsn, err := pgUpstreamDSN(dst, b, secrets)
	if err != nil {
		pgFatal(be, "08006", "proxy misconfigured: "+err.Error())
		return
	}
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		pgFatal(be, "08006", "proxy upstream config error")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	up, err := pgconn.ConnectConfig(ctx, cfg)
	cancel()
	if err != nil {
		pol.Session("UPSTREAM AUTH FAILED: " + err.Error())
		pgFatal(be, "08006", "proxy could not authenticate to the database")
		return
	}
	// Drain to a clean protocol boundary before stealing the raw conn.
	if err := up.SyncConn(context.Background()); err != nil {
		_ = up.Close(context.Background())
		return
	}
	hj, err := up.Hijack()
	if err != nil {
		return
	}
	defer hj.Conn.Close()
	fe := hj.Frontend
	pol.Session(fmt.Sprintf("upstream authenticated as user=%q db=%q @ %s:%d", cfg.User, cfg.Database, cfg.Host, cfg.Port))

	// 3. Complete the agent handshake from the upstream's negotiated state.
	be.Send(&pgproto3.AuthenticationOk{})
	for k, v := range hj.ParameterStatuses {
		be.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	be.Send(&pgproto3.BackendKeyData{ProcessID: hj.PID, SecretKey: hj.SecretKey})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: hj.TxStatus})
	if err := be.Flush(); err != nil {
		return
	}

	// 4. Bridge + govern.
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query: // simple protocol (may carry multiple ;-separated stmts)
			st := classify(m.String)
			if blocked, reason := pol.Blocked(m.String); blocked {
				pol.Block(st, reason)
				be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "blocked by Phase egress policy: " + reason})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if be.Flush() != nil {
					return
				}
				continue
			}
			pol.Allow(st)
			fe.Send(msg)
			if fe.Flush() != nil || pgPump(fe, be) != nil {
				return
			}
		case *pgproto3.Parse: // extended protocol (exactly one statement)
			st := classify(m.Query)
			if blocked, reason := pol.Blocked(m.Query); blocked {
				pol.Block(st, reason)
				be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "blocked by Phase egress policy: " + reason})
				// Discard the agent's pipelined Bind/Describe/Execute until Sync
				// (mirrors Postgres's own post-error recovery), then ReadyForQuery.
				if pgDiscardUntilSync(be) != nil {
					return
				}
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if be.Flush() != nil {
					return
				}
				continue
			}
			pol.Allow(st)
			fe.Send(msg)
			if fe.Flush() != nil {
				return
			}
		case *pgproto3.Sync: // extended-protocol batch boundary → pump responses
			fe.Send(msg)
			if fe.Flush() != nil || pgPump(fe, be) != nil {
				return
			}
		case *pgproto3.Terminate:
			fe.Send(msg)
			_ = fe.Flush()
			return
		default: // Bind/Describe/Execute/Close/CopyData/etc. — no SQL; forward.
			fe.Send(msg)
			if fe.Flush() != nil {
				return
			}
		}
	}
}

// pgReadStartup reads the first startup packet, declining in-protocol TLS/GSS.
func pgReadStartup(be *pgproto3.Backend, agent net.Conn) (*pgproto3.StartupMessage, error) {
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := agent.Write([]byte{'N'}); err != nil { // decline
				return nil, err
			}
		case *pgproto3.StartupMessage:
			return m, nil
		default:
			return nil, fmt.Errorf("unexpected startup message %T", m)
		}
	}
}

// pgPump forwards upstream backend messages to the agent until (and including)
// the next ReadyForQuery. Handles COPY: CopyIn switches to relaying the agent's
// bulk data upstream; CopyOut flows through as ordinary forwarded messages.
func pgPump(fe *pgproto3.Frontend, be *pgproto3.Backend) error {
	for {
		msg, err := fe.Receive()
		if err != nil {
			return err
		}
		be.Send(msg)
		switch msg.(type) {
		case *pgproto3.ReadyForQuery:
			return be.Flush()
		case *pgproto3.CopyInResponse:
			if err := be.Flush(); err != nil {
				return err
			}
			if err := pgRelayCopyIn(fe, be); err != nil {
				return err
			}
		}
	}
}

// pgRelayCopyIn relays the agent's CopyData/CopyDone/CopyFail upstream until the
// copy ends (no SQL to police in CopyData).
func pgRelayCopyIn(fe *pgproto3.Frontend, be *pgproto3.Backend) error {
	for {
		msg, err := be.Receive()
		if err != nil {
			return err
		}
		fe.Send(msg)
		if err := fe.Flush(); err != nil {
			return err
		}
		switch msg.(type) {
		case *pgproto3.CopyDone, *pgproto3.CopyFail:
			return nil
		}
	}
}

// pgDiscardUntilSync drops the agent's pipelined messages until Sync (used after
// blocking a Parse, mirroring Postgres's discard-until-Sync error recovery).
func pgDiscardUntilSync(be *pgproto3.Backend) error {
	for {
		msg, err := be.Receive()
		if err != nil {
			return err
		}
		if _, ok := msg.(*pgproto3.Sync); ok {
			return nil
		}
	}
}

// pgUpstreamDSN builds the upstream connection string from the binding + the live
// credential. If the secret is already a full DSN, it is used verbatim.
func pgUpstreamDSN(dst string, b *Binding, secrets map[string]string) (string, error) {
	cred := secrets[b.Inject.SecretKey]
	if cred == "" {
		return "", fmt.Errorf("credential %q not present", b.Inject.SecretKey)
	}
	if strings.HasPrefix(cred, "postgres://") || strings.HasPrefix(cred, "postgresql://") {
		return cred, nil
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		host, port = dst, "5432"
	}
	db := b.Inject.Database
	if db == "" {
		db = b.Inject.User
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(b.Inject.User, cred),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + db,
	}
	q := u.Query()
	q.Set("sslmode", "prefer") // try TLS, fall back to plaintext (dev/trust DBs)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func pgFatal(be *pgproto3.Backend, code, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = be.Flush()
}
