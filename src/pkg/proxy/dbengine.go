package proxy

import "net"

// DBEngine governs one database wire protocol. It bridges the agent to the real
// upstream — injecting the REAL credential during the auth handshake while the
// agent only ever holds a dummy — and enforces + audits statement policy via the
// shared, protocol-agnostic StmtPolicy. Adding another database (MySQL, …) is a
// new DBEngine + a classifier branch in dispatch; nothing else changes.
//
// Hard invariants (see research): (1) 1:1 bridge, NEVER pool — pooling
// reintroduces the whole pgbouncer/ProxySQL failure class. (2) Agent-facing auth
// is trust/dummy; the real challenge-response auth (SCRAM / caching_sha2) happens
// only on the upstream leg, because it cannot be byte-swapped or MITM-relayed.
type DBEngine interface {
	Protocol() string
	// Handle owns the agent conn for its lifetime. dst is the real upstream
	// host:port; b carries the injection config + deny rules; secrets holds the
	// live credential (keyed by b.Inject.SecretKey). agent already replays any
	// peeked bytes (it is a *bufConn).
	Handle(agent net.Conn, dst string, b *Binding, secrets map[string]string, pol *StmtPolicy, who string)
}

// dbEngines is the registry; dispatch selects by protocol. Add an engine here.
var dbEngines = map[string]DBEngine{
	"postgres": pgEngine{},
}

// Statement is one parsed SQL statement (v1: keyword-classified for the verb).
type Statement struct {
	Raw  string
	Verb string // leading keyword: SELECT / INSERT / DROP / ...
}
