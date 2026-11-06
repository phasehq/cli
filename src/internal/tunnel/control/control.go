// Package control is how the CLI and the engine talk to the privileged helper: one
// JSON message per line over a Unix socket that only the installing user can open.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// ProtocolVersion changes only when the helper and the CLI stop understanding each
// other. A newer CLI keeps using an older helper until then, so upgrading the CLI
// doesn't ask for a password again.
const ProtocolVersion = 1

// Operations.
const (
	OpStatus = "status"
	OpAttach = "attach"
	OpUpdate = "update"
	OpPing   = "ping"
	OpDown   = "down"
)

// Request is one message to the helper.
type Request struct {
	Op      string   `json:"op"`
	Attach  *Attach  `json:"attach,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// Attach hands the helper an engine. The connection it arrives on stays open for the
// engine's whole life: when it closes, or the engine stops answering, the helper
// steps aside at once.
type Attach struct {
	EnginePublicKey string   `json:"enginePublicKey"`
	EnginePort      int      `json:"enginePort"`
	Domains         []string `json:"domains"`
	Routes          []string `json:"routes"`
}

// Reply is the helper's answer.
type Reply struct {
	Error         string  `json:"error,omitempty"`
	Status        *Status `json:"status,omitempty"`
	PeerPublicKey string  `json:"peerPublicKey,omitempty"`
}

// Status is the helper's state. It holds no credential.
type Status struct {
	Protocol  int       `json:"protocol"`
	Version   string    `json:"version"`
	Device    string    `json:"device,omitempty"`
	Attached  bool      `json:"attached"`
	Capturing bool      `json:"capturing"`
	Reason    string    `json:"reason,omitempty"`
	Since     time.Time `json:"since"`
	Pinned    string    `json:"pinned,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
	Routes    []string  `json:"routes,omitempty"`
	Retry     time.Time `json:"retry,omitempty"`
}

// ErrNotRunning means nothing answered on the socket.
var ErrNotRunning = errors.New("the Phase tunnel helper isn't running")

// Conn is one open connection to the helper.
type Conn struct {
	conn    net.Conn
	reader  *bufio.Reader
	encoder *json.Encoder
}

// Dial opens the helper's socket.
func Dial(path string) (*Conn, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	return &Conn{conn: conn, reader: bufio.NewReader(conn), encoder: json.NewEncoder(conn)}, nil
}

// Wrap uses an existing connection, for the helper's side and tests.
func Wrap(conn net.Conn) *Conn {
	return &Conn{conn: conn, reader: bufio.NewReader(conn), encoder: json.NewEncoder(conn)}
}

// Send writes one message.
func (c *Conn) Send(message any) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.encoder.Encode(message)
}

// Receive reads one message, waiting at most wait.
func (c *Conn) Receive(message any, wait time.Duration) error {
	_ = c.conn.SetReadDeadline(time.Now().Add(wait))
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, message)
}

// Call sends a request and waits for the reply.
func (c *Conn) Call(request Request, wait time.Duration) (Reply, error) {
	var reply Reply
	if err := c.Send(request); err != nil {
		return reply, err
	}
	if err := c.Receive(&reply, wait); err != nil {
		return reply, err
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.conn.Close() }

// Ask makes one request on a fresh connection.
func Ask(path string, request Request, wait time.Duration) (Reply, error) {
	conn, err := Dial(path)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	return conn.Call(request, wait)
}
