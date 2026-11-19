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
// the shipped rules.yaml or ParseRules, then catch credential formats: Phase's
// own tokens, those of cloud and model providers, source hosts, package
// registries and other services, private keys, JWTs and high-entropy values
// written after a secret-sounding name. Key names count as keywords only under
// the request's conversation fields. ScanOptions.Rules limits one call to some
// of the rules (see Rules.Only); indexed values are found whatever it holds.
//
// A rule is a format's prefix, length and alphabet, and where the format has a
// checksum or a structure of its own, a validator for it. A validator that
// passes raises a match's score; one that fails never lowers it, so a value in
// a format's shape is replaced whether or not its checksum could be confirmed.
// A format with no prefix worth acting on is taken only after a keyword, and a
// format that is a secret under one name and public under another, as a Google
// API key is, only under a name that says which. A name that runs on past its
// keyword to say the value is something else (secretName, token_file,
// tokenizer) is not a secret's name. Documentation examples and test-mode
// values are left alone.
//
// Where matches that will be replaced overlap, their union is replaced, under
// the label of the one that scored highest, so that no part of a longer value
// stays behind; a token that runs on in its own alphabet past the length its
// rule allows is replaced whole. An escape just before a token (\n, \t, \r,
// %XX) is read as the character it stands for, so a token in a log line
// carried inside a string, or in an encoded URL, is found. No rule takes what
// begins at a placeholder or inside one, and a keyword inside one is no
// keyword: scanning text that was already rewritten changes nothing.
//
// A rule file may be newer than this package: a rule it cannot apply is left
// out and listed by Rules.Skipped, and the rest of the file applies. A rule
// whose validator alone is unknown is applied without it, and listed too. What
// would switch protection off quietly is an error: see ParseRules.
//
// Text the provider signed or encrypted and the client sends back as it was is
// scanned for the report only and never changed. That holds in two places of
// the request body, where the providers put such text, and nowhere else: the
// thinking, signature and data strings of a thinking or redacted_thinking
// block that is an item of a message's content (/messages/<n>/content/<m>),
// and an encrypted_content string directly on an item of the input
// (/input/<n>). The provider refuses an edited block, and it wrote that text,
// so its findings have the action "left". The same keys anywhere else, in a
// tool's input or result or in JSON held inside a string, are a tool's or a
// file's text, and nothing there is exempt.
//
// A chunk that repeats within a form is indexed at its first place only, one
// rolling hash leads to a bounded number of chunks across the index, and a
// match already extended over a stretch is not tried again inside it, so a
// scan stays linear in the body whatever has been indexed. One pass over a
// block finds every keyword and every place a rule's prefix begins, and what a
// rule may read from those places is bounded by the block, so the rules add a
// cost that is linear too, and nearly none on text that holds no prefix.
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
//     bytes is caught at some offsets only, and a shorter one never. Even at 23
//     bytes it is not caught when the one chunk it holds whole is too plain to
//     count (under 2.8 bits per byte, as about one chunk in 700 of a random
//     value is): it then needs a second chunk, and is certain from 35 bytes.
//   - A fragment of a base64 or hex form needs more when one chunk of the form
//     carries under 48 bits of the value, because other text of the same kind
//     then repeats such a chunk by chance. That is so for the base64 of a value
//     made of hex digits, of digits, or of one case of letters with or without
//     digits, and for the hex of any text. Such a fragment is caught only when
//     it holds two whole chunks next to each other: for certain from 35
//     characters, at some offsets from 24, and never below. The whole form is
//     found as before.
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
