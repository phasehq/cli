package censor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// KeySize is the length of an exported Key in bytes.
const KeySize = 32

// Key is the secret that every hash in an index is keyed with. The daemon makes
// one per process and hands its bytes to each client that indexes values, so the
// client's entries and the daemon's scans agree. Without the key, the entries
// are opaque; with it, they still only confirm a guessed chunk.
type Key struct {
	raw     [KeySize]byte
	macKey  [32]byte
	ruleKey [32]byte
	table   [256]uint64
	base    uint64
	outPow  uint64
}

// NewKey makes a random key.
func NewKey() (*Key, error) {
	var raw [KeySize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	return deriveKey(raw), nil
}

// KeyFromBytes rebuilds a key exported with Bytes.
func KeyFromBytes(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("a censor key is %d bytes, not %d", KeySize, len(b))
	}
	var raw [KeySize]byte
	copy(raw[:], b)
	if raw == ([KeySize]byte{}) {
		return nil, errors.New("a censor key cannot be all zeros")
	}
	return deriveKey(raw), nil
}

// Bytes exports the key, for handing to a client that indexes values.
func (k *Key) Bytes() []byte {
	out := make([]byte, KeySize)
	copy(out, k.raw[:])
	return out
}

// deriveKey expands the raw key into the confirming hash's key, the rule
// numbering key and the rolling hash's byte table and base. Each use gets its
// own label so no two of them share material.
func deriveKey(raw [KeySize]byte) *Key {
	k := &Key{raw: raw}
	k.macKey = sha256.Sum256(append(raw[:], "phase-censor-v1-mac"...))
	k.ruleKey = sha256.Sum256(append(raw[:], "phase-censor-v1-rule"...))
	var stream []byte
	for counter := uint32(0); len(stream) < 8*257; counter++ {
		block := append(raw[:], "phase-censor-v1-roll"...)
		block = binary.BigEndian.AppendUint32(block, counter)
		sum := sha256.Sum256(block)
		stream = append(stream, sum[:]...)
	}
	for i := range k.table {
		k.table[i] = binary.LittleEndian.Uint64(stream[i*8:])
	}
	k.base = binary.LittleEndian.Uint64(stream[256*8:]) | 1
	k.outPow = 1
	for i := 0; i < chunkSize-1; i++ {
		k.outPow *= k.base
	}
	return k
}

// mac is the confirming hash: SHA-256 over the derived key and the bytes.
func (k *Key) mac(data []byte) [macSize]byte {
	var buf [32 + 64]byte
	var sum [32]byte
	if len(data) <= 64 {
		copy(buf[:32], k.macKey[:])
		n := copy(buf[32:], data)
		sum = sha256.Sum256(buf[:32+n])
	} else {
		h := sha256.New()
		h.Write(k.macKey[:])
		h.Write(data)
		h.Sum(sum[:0])
	}
	var out [macSize]byte
	copy(out[:], sum[:macSize])
	return out
}

// roll is the keyed polynomial hash the scan keeps rolling: keyed byte values,
// a keyed odd base, modulo 2^64.
func (k *Key) roll(data []byte) uint64 {
	var h uint64
	for _, b := range data {
		h = h*k.base + k.table[b]
	}
	return h
}
