package aiproxy

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpClose        = 0x8
)

// wsFrameHeader is one frame's header as the client sent it.
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

// pumpLeakFrames copies the client's frames upstream, holding each text
// message until its last frame has arrived so it can be read whole. A text
// message that holds a secret goes out as one new frame with the value
// replaced; everything else (control frames, binary messages, a text message
// over the size limit, one that is not JSON) goes out as the client framed it.
// Binary messages are not read; the first one on a connection is reported.
// It returns when the client side ends or a write upstream fails.
func (p *httpProxy) pumpLeakFrames(reader *bufio.Reader, upstream io.Writer, request *http.Request, host string, port int, match *leakHostMatch) {
	guard := p.leak
	opts := guard.scanOptionsFor(match, request.URL.Path)
	binaryReported := false
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
			if messageOpcode != wsOpText && !binaryReported {
				binaryReported = true
				p.emitLeakMessageEvent(request, host, port, &leakScan{match: match, mode: guard.mode, protocol: "websocket", opts: opts, unread: leakReasonBinary})
			}
		}
		// Binary messages, and the rest of a message already passed on, are
		// streamed through without being held.
		if messageOpcode != wsOpText || passing {
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
			p.emitLeakMessageEvent(request, host, port, &leakScan{match: match, mode: guard.mode, protocol: "websocket", opts: opts, unread: leakReasonOverLimit})
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
		out := held
		scan := guard.newScan(match, "websocket", opts)
		if compressed {
			// The compression offer is removed from the handshake, so this is a
			// client that compressed anyway; its bytes are not readable here.
			scan.unread = leakReasonCompressed
		} else if rewritten := p.scanLeakMessage(scan, message); rewritten != nil && guard.mode == leakModeCensor {
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

// scanLeakMessage reads one whole text message. Only JSON is rewritten; any
// other text goes out as it was and is reported.
func (p *httpProxy) scanLeakMessage(scan *leakScan, message []byte) []byte {
	out, report, err := p.leak.index.RewriteJSON(message, scan.opts)
	if err != nil {
		scan.unread = leakReasonNotJSON
		return nil
	}
	scan.addReport(report, "message")
	if report == nil || !report.Changed {
		return nil
	}
	return out
}

func (p *httpProxy) emitLeakMessageEvent(request *http.Request, host string, port int, scan *leakScan) {
	p.emitLeakEvent(nil, request, host, port, scan, 0, time.Now())
}
