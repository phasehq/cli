package censor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// KeySize is the length of each of a Key's two parts in bytes.
const KeySize = 32

// Key is a lookup key, shared, for the rolling hash a chunk is found by, and
// a confirming key, one per principal, for the SHA-256 that confirms it.
type Key struct {
	lookup     [KeySize]byte
	confirm    [KeySize]byte
	hasConfirm bool
	// macKey keys the confirming hash, and sharedMac that of scheme 1, whose
	// clients were handed one key for both roles.
	macKey    [32]byte
	sharedMac [32]byte
	table     [256]uint64
	base      uint64
	outPow    uint64
}

// NewKey makes a random key: a lookup key and a confirming key.
func NewKey() (*Key, error) {
	var raw [2 * KeySize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	return KeyFromBytes(raw[:KeySize], raw[KeySize:])
}

// KeyFromBytes rebuilds a key from its two parts, as LookupBytes and
// ConfirmBytes export them.
func KeyFromBytes(lookup, confirm []byte) (*Key, error) {
	k, err := LookupKeyFromBytes(lookup)
	if err != nil {
		return nil, err
	}
	return k.WithConfirm(confirm)
}

// LookupKeyFromBytes rebuilds a lookup key alone. It finds chunks and confirms
// none but those of scheme 1, which is all a daemon of that time handed out.
func LookupKeyFromBytes(lookup []byte) (*Key, error) {
	raw, err := keyPart(lookup)
	if err != nil {
		return nil, err
	}
	return deriveKey(raw), nil
}

// WithConfirm is the key with the same lookup key and another principal's
// confirming key.
func (k *Key) WithConfirm(confirm []byte) (*Key, error) {
	raw, err := keyPart(confirm)
	if err != nil {
		return nil, err
	}
	if raw == k.lookup {
		return nil, errors.New("a confirming key cannot be the lookup key")
	}
	with := *k
	with.confirm, with.hasConfirm = raw, true
	with.macKey = sha256.Sum256(append(raw[:], "phase-censor-v2-confirm"...))
	return &with, nil
}

func keyPart(b []byte) (raw [KeySize]byte, err error) {
	if len(b) != KeySize {
		return raw, fmt.Errorf("a censor key is %d bytes, not %d", KeySize, len(b))
	}
	copy(raw[:], b)
	if raw == ([KeySize]byte{}) {
		return raw, errors.New("a censor key cannot be all zeros")
	}
	return raw, nil
}

// LookupBytes exports the lookup key, which every client is handed.
func (k *Key) LookupBytes() []byte {
	out := make([]byte, KeySize)
	copy(out, k.lookup[:])
	return out
}

// ConfirmBytes exports the confirming key, for the principal it belongs to
// and no one else. It is nil for a lookup key alone.
func (k *Key) ConfirmBytes() []byte {
	if !k.hasConfirm {
		return nil
	}
	out := make([]byte, KeySize)
	copy(out, k.confirm[:])
	return out
}

// Supports reports whether the key can index values under a scheme: one
// whose confirming hash has a key of its own needs a confirming key.
func (k *Key) Supports(version int) bool {
	s := schemes[version]
	return s != nil && k.macFor(s) != nil
}

// macFor is the key of the confirming hash under a scheme, or nil when the
// scheme needs a confirming key and this is a lookup key alone.
func (k *Key) macFor(s *scheme) *[32]byte {
	switch {
	case s.sharedConfirm:
		return &k.sharedMac
	case k.hasConfirm:
		return &k.macKey
	}
	return nil
}

// deriveKey expands the lookup key into the rolling hash's byte table and
// base, and scheme 1's confirming key, each under its own label.
func deriveKey(raw [KeySize]byte) *Key {
	k := &Key{lookup: raw}
	k.sharedMac = sha256.Sum256(append(raw[:], "phase-censor-v1-mac"...))
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

// mac is the confirming hash: SHA-256 over a confirming key and the bytes.
func mac(key *[32]byte, data []byte) [macSize]byte {
	var buf [32 + 64]byte
	var sum [32]byte
	if len(data) <= 64 {
		copy(buf[:32], key[:])
		n := copy(buf[32:], data)
		sum = sha256.Sum256(buf[:32+n])
	} else {
		h := sha256.New()
		h.Write(key[:])
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
