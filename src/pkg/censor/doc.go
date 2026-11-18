// Package censor finds known secret values, and well-known credential formats,
// in the requests AI tools send to model providers, and replaces them with
// placeholders. It is leak protection against accidents and negligence, not
// against a process that sets out to get a value past it.
//
// # Indexing without plaintext
//
// A value is indexed where it is decrypted: IndexValue cuts each of its encoded
// forms (raw; base64 and base64url at all three alignments; hex in both cases;
// URL-encoded; JSON-escaped; newlines as a literal \n; each line of a PEM body)
// into non-overlapping 12-byte chunks and keeps, per chunk, a keyed rolling hash
// and a keyed SHA-256, with the chunk's index and the form's length. A JSON
// value is indexed leaf by leaf, and a URL's password on its own as well. The
// resulting Entries carry no plaintext and nothing derived from the value but
// keyed hashes and lengths. The daemon that scans makes the Key, hands its bytes
// to the indexing client, and adds the Entries it gets back to its Index, which
// validates them as untrusted input.
//
// Chunks that are structure rather than secret (PEM armour, a token's type
// prefix, a URL's scheme and host, a JWT's header and claims, and chunks under
// 2.8 bits per byte) never produce a partial match alone. A value under 12
// bytes or 2.5 bits per byte is not indexed and is reported as unprotected.
//
// # Scanning
//
// RewriteJSON walks a JSON body and rewrites string values in place, leaving
// every other byte as it was; JSON held inside a string is walked too, and
// base64-only strings of 16 KiB or more are skipped as images or files. Redact
// does the same for plain bytes, and Find reports byte ranges for bytes that
// cannot be rewritten, such as a URL or a header. Base64 and hex runs of 24 or
// more characters are decoded and rescanned, two levels deep, and gzip or zlib
// data inside a decoded run is inflated (to at most 1 MiB, and 256 times its
// size) and scanned; a match there replaces the whole run. Pattern rules, from
// the shipped rules.yaml or ParseRules, then catch formats such as Phase, AWS,
// GitHub, Slack and Stripe tokens, private keys, JWTs and high-entropy values
// written after a secret-sounding name. Key names count as keywords only under
// the request's conversation fields. ScanOptions.Rules limits one call to some
// of the rules (see Rules.Only); indexed values are found whatever it holds.
//
// Text the provider signed or encrypted and the client sends back as it was is
// scanned for the report only and never changed: the thinking, signature and
// data strings of a thinking or redacted_thinking block, and any string under
// an encrypted_content key. The provider refuses an edited block, and it wrote
// that text, so its findings have the action "left".
//
// A chunk that repeats within a form is indexed at its first place only, one
// rolling hash leads to a bounded number of chunks across the index, and a
// match already extended over a stretch is not tried again inside it, so a
// scan stays linear in the body whatever has been indexed.
//
// An indexed value is replaced by ph:<type>:<id>, as given when it was indexed;
// a rule match by ph:<label>:<n>, where n is the same for the same value for
// the life of the Index. Reports hold counts, placeholders, labels, form names
// and JSON pointers, never matched content.
//
// # Limits
//
//   - A fragment of an indexed value is only certain to be caught when it is at
//     least 23 bytes long (twice the chunk, less one); a fragment of 12 to 22
//     bytes is caught at some offsets only, and a shorter one never.
//   - A value transformed in any other way (reversed, split, re-encoded in a
//     form not listed above, encrypted, compressed without base64 around it, or
//     inside a base64 string of 16 KiB or more) is not found.
//   - JSON object keys are not scanned, only values.
//   - A value under 12 bytes, or with little entropy, is not protected at all.
//   - Pattern rules see a format only when it is written plainly; a random value
//     with no known format is found by them only next to a keyword.
//   - Whoever holds the Key can confirm a guessed 12-byte chunk against the
//     index, so the Key must stay with the daemon and the clients it trusts to
//     index values.
package censor
