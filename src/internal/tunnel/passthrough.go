package tunnel

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// relayTCP copies both ways until both directions have ended. A clean end is passed on
// as a half-close, because the other direction may have plenty still to send, and a
// failure ends both.
func relayTCP(client, upstream net.Conn, up, down *atomic.Int64) {
	var done sync.WaitGroup
	done.Add(2)
	go func() {
		defer done.Done()
		relayHalf(upstream, client, up)
	}()
	go func() {
		defer done.Done()
		relayHalf(client, upstream, down)
	}()
	done.Wait()
}

func relayHalf(dst, src net.Conn, total *atomic.Int64) {
	buf := make([]byte, 128<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total.Add(int64(n))
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				_ = src.Close()
				_ = dst.Close()
				return
			}
		}
		if errors.Is(err, io.EOF) {
			if closer, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = closer.CloseWrite()
				return
			}
			_ = dst.Close()
			return
		}
		if err != nil {
			_ = src.Close()
			_ = dst.Close()
			return
		}
	}
}

// peekClientHello returns the server name in a TLS hello, and the bytes it read so they
// can be sent on. Anything that isn't a TLS hello passes through.
func peekClientHello(client net.Conn) (string, []byte) {
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	defer client.SetReadDeadline(time.Time{})
	var head bytes.Buffer
	name := ""
	conn := tls.Server(helloRecorder{Conn: client, head: &head}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			return nil, errHelloSeen
		},
	})
	_ = conn.Handshake()
	return name, head.Bytes()
}

var errHelloSeen = errors.New("hello seen")

// helloRecorder keeps what's read, and swallows the alert a failed handshake would send.
type helloRecorder struct {
	net.Conn
	head *bytes.Buffer
}

func (r helloRecorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.head.Write(p[:n])
	return n, err
}

func (r helloRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r helloRecorder) Close() error                { return nil }

// relayUDP carries one UDP conversation until it has been idle for a while.
func relayUDP(client, upstream net.Conn, idle time.Duration, up, down *atomic.Int64) {
	if socket, ok := upstream.(*net.UDPConn); ok {
		_ = socket.SetReadBuffer(1 << 20)
		_ = socket.SetWriteBuffer(1 << 20)
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var done sync.WaitGroup
	done.Add(2)
	copyDatagrams := func(dst, src net.Conn, total *atomic.Int64) {
		defer done.Done()
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				total.Add(int64(n))
				if _, err := dst.Write(buf[:n]); err != nil && !isTemporaryUDP(err) {
					return
				}
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				if time.Since(time.Unix(0, last.Load())) > idle {
					return
				}
				continue
			}
			if err != nil && !isTemporaryUDP(err) {
				return
			}
		}
	}
	go copyDatagrams(upstream, client, up)
	go copyDatagrams(client, upstream, down)
	done.Wait()
}

// isTemporaryUDP is an ICMP error reported on a connected socket. The conversation
// carries on, as it would for a program talking to the destination directly.
func isTemporaryUDP(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EMSGSIZE)
}
