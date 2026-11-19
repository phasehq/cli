package aiproxy

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpClose        = 0x8

	// Close codes (RFC 6455 section 7.4.1): the endpoint is going away, and
	// the endpoint received a message that violates its policy.
	wsCloseGoingAway       = 1001
	wsClosePolicyViolation = 1008

	// wsBlockedReason is what the client is told when a message is blocked. A
	// close frame holds at most 123 bytes of it.
	wsBlockedReason = "Phase blocked a message: it holds a secret value that cannot be removed."

	// wsCloseWait is how long the proxy waits for the frame the service is
	// sending to finish before it gives up on a close frame of its own.
	wsCloseWait = 2 * time.Second
)

// wsFrameHeader is one frame's header as it was sent.
type wsFrameHeader struct {
	fin    bool
	rsv1   bool
	opcode byte
	masked bool
	mask   [4]byte
	length uint64
	raw    []byte
}

func readWSFrameHeader(reader *bufio.Reader) (*wsFrameHeader, error) {
	head := make([]byte, 2, 14)
	if _, err := io.ReadFull(reader, head); err != nil {
		return nil, err
	}
	frame := &wsFrameHeader{fin: head[0]&0x80 != 0, rsv1: head[0]&0x40 != 0, opcode: head[0] & 0x0f, masked: head[1]&0x80 != 0}
	frame.length = uint64(head[1] & 0x7f)
	switch frame.length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(reader, extended); err != nil {
			return nil, err
		}
		head = append(head, extended...)
		frame.length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(reader, extended); err != nil {
			return nil, err
		}
		head = append(head, extended...)
		frame.length = binary.BigEndian.Uint64(extended)
		if frame.length > 1<<63-1 {
			return nil, fmt.Errorf("frame length is invalid")
		}
	}
	if frame.masked {
		if _, err := io.ReadFull(reader, frame.mask[:]); err != nil {
			return nil, err
		}
		head = append(head, frame.mask[:]...)
	}
	frame.raw = head
	return frame, nil
}

func unmaskWS(payload []byte, mask [4]byte) {
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
}

// maskedClientFrame builds one complete client-to-server frame. Clients must
// mask what they send, and a server may refuse a frame that is not masked.
func maskedClientFrame(opcode byte, payload []byte) ([]byte, error) {
	frame := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, 0x80|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	default:
		frame = append(frame, 0x80|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(len(payload)))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return nil, err
	}
	frame = append(frame, mask[:]...)
	start := len(frame)
	frame = append(frame, payload...)
	unmaskWS(frame[start:], mask)
	return frame, nil
}

// wsClosePayload is a close frame's body: the code, then why. A control
// frame holds at most 125 bytes.
func wsClosePayload(code uint16, reason string) []byte {
	if len(reason) > 123 {
		reason = reason[:123]
	}
	return append(binary.BigEndian.AppendUint16(nil, code), reason...)
}

// wsDownstream carries the service's frames to the client one whole frame at
// a time, so that the proxy can put a close frame of its own between two of
// them. Written anywhere else it would land inside a frame the service is
// still sending, and the client would read it as that frame's data.
type wsDownstream struct {
	// mu is held for the length of one frame.
	mu     sync.Mutex
	client io.Writer
	// closed is set once the proxy's close frame went out. Nothing follows it.
	closed bool
	// wait is how long close waits for a frame to finish; zero means
	// wsCloseWait.
	wait time.Duration
}

// relay copies the service's frames to the client until either side ends or
// the proxy has closed the WebSocket.
func (d *wsDownstream) relay(upstream io.Reader) {
	reader := bufio.NewReader(upstream)
	for {
		frame, err := readWSFrameHeader(reader)
		if err != nil || !d.forward(frame, reader) {
			return
		}
	}
}

func (d *wsDownstream) forward(frame *wsFrameHeader, reader *bufio.Reader) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	if _, err := d.client.Write(frame.raw); err != nil {
		return false
	}
	_, err := io.CopyN(d.client, reader, int64(frame.length))
	return err == nil
}

// close tells the client the WebSocket is closed and why, once the frame the
// service is sending, if any, is through. A service that stalls inside a
// frame gets no close frame after it: the connection is dropped instead.
func (d *wsDownstream) close(code uint16, reason string) {
	wait := d.wait
	if wait <= 0 {
		wait = wsCloseWait
	}
	deadline := time.Now().Add(wait)
	for !d.mu.TryLock() {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	payload := wsClosePayload(code, reason)
	// A server's frame is not masked.
	_, _ = d.client.Write(append([]byte{0x80 | wsOpClose, byte(len(payload))}, payload...))
}

// pumpLeakFrames copies the client's frames upstream, holding each message
// until its last frame has arrived so it can be read whole. What it does with
// a message is what the policy says for a request body of the same kind
// (leak_policy.go): text, JSON or not, goes out as one new frame with what
// was found replaced; a binary message, and one compressed against the
// handshake, cannot be rewritten, so a known value or a Phase token in it
// blocks. Blocking a message ends the WebSocket: the client is sent a close
// frame that says its message broke policy, and the message is never sent.
// Control frames, and a message too long to hold, go out as the client framed
// them. It returns when the client side ends, a write upstream fails, or a
// message is blocked.
func (p *httpProxy) pumpLeakFrames(reader *bufio.Reader, upstream io.Writer, downstream *wsDownstream, request *http.Request, host string, port int, match *leakHostMatch) {
	guard := p.leak
	opts := guard.scanOptionsFor(match, request.URL.Path)
	var held [][]byte
	var message []byte
	var messageOpcode byte
	var compressed, passing bool
	write := func(chunks ...[]byte) bool {
		for _, chunk := range chunks {
			if _, err := upstream.Write(chunk); err != nil {
				return false
			}
		}
		return true
	}
	for {
		frame, err := readWSFrameHeader(reader)
		if err != nil {
			return
		}
		// Control frames may arrive between a message's frames; they are never
		// held.
		if frame.opcode >= wsOpClose {
			if frame.length > 125 || !write(frame.raw) {
				return
			}
			if _, err := io.CopyN(upstream, reader, int64(frame.length)); err != nil {
				return
			}
			continue
		}
		if frame.opcode != wsOpContinuation {
			messageOpcode = frame.opcode
		}
		// The rest of a message already passed on is streamed through without
		// being held.
		if passing {
			if !write(frame.raw) {
				return
			}
			if _, err := io.CopyN(upstream, reader, int64(frame.length)); err != nil {
				return
			}
			if frame.fin {
				passing = false
			}
			continue
		}
		if uint64(len(message))+frame.length > maxLeakBody {
			// Too long to hold: what was held goes out as it came, then the
			// rest of the message streams through.
			if !write(held...) || !write(frame.raw) {
				return
			}
			if _, err := io.CopyN(upstream, reader, int64(frame.length)); err != nil {
				return
			}
			scan := guard.newScan(match, "websocket", opts)
			scan.leaveUnread(leakReasonOverLimit, leakScopeMessage)
			p.emitLeakMessageEvent(request, host, port, scan)
			held, message, compressed = nil, nil, false
			passing = !frame.fin
			continue
		}
		payload := make([]byte, frame.length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}
		raw := append(frame.raw, payload...)
		if frame.masked {
			unmaskWS(payload, frame.mask)
		}
		held = append(held, raw)
		message = append(message, payload...)
		compressed = compressed || frame.rsv1
		if !frame.fin {
			continue
		}
		scan := guard.newScan(match, "websocket", opts)
		var rewritten []byte
		switch {
		case compressed:
			// The compression offer is removed from the handshake, so this is a
			// client that compressed anyway; its bytes are looked at as they came.
			scan.leaveUnread(leakReasonCompressed, leakScopeMessage)
			guard.readFixed(scan, leakPartOpaque, message, "message")
		case messageOpcode == wsOpText:
			rewritten = guard.readPayload(scan, message, "message")
		default:
			guard.readFixed(scan, leakPartBinary, message, "message")
		}
		out := held
		switch scan.verdict(rewritten != nil) {
		case leakBlock:
			p.blockLeakMessage(request, host, port, scan, upstream, downstream)
			return
		case leakReplace:
			replacement, err := maskedClientFrame(wsOpText, rewritten)
			if err != nil {
				return
			}
			out = [][]byte{replacement}
			scan.changed = true
		}
		p.emitLeakMessageEvent(request, host, port, scan)
		if !write(out...) {
			return
		}
		held, message, compressed = nil, nil, false
	}
}

// blockLeakMessage ends a WebSocket over a message that must not go out. The
// message's frames were held, so the service has seen none of them and is
// told only that the client is going away.
func (p *httpProxy) blockLeakMessage(request *http.Request, host string, port int, scan *leakScan, upstream io.Writer, downstream *wsDownstream) {
	if p.events != nil {
		p.events.Emit(p.leakEvent(nil, request, host, port, scan, "block", "denied", leakReasonFound, 0, time.Now()))
	}
	downstream.close(wsClosePolicyViolation, wsBlockedReason)
	if frame, err := maskedClientFrame(wsOpClose, wsClosePayload(wsCloseGoingAway, "")); err == nil {
		_, _ = upstream.Write(frame)
	}
}

func (p *httpProxy) emitLeakMessageEvent(request *http.Request, host string, port int, scan *leakScan) {
	p.emitLeakEvent(nil, request, host, port, scan, 0, time.Now())
}
