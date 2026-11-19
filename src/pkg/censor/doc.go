// Package censor finds known secret values, and well-known credential formats,
// in the requests AI tools send to model providers, and replaces them with
// placeholders. It is leak protection against accidents and negligence, not
// against a process that sets out to get a value past it.
//
// # Indexing without plaintext
//
// A value is indexed where it is decrypted: IndexValue cuts each of its encoded
// forms (raw; base64 and base64url at all three alignments; hex in both cases;
// URL-encoded, with %XX in either case; JSON-escaped; newlines as a literal \n;
// each line that is one run of base64 or hex characters, as those of a PEM body
// are) into non-overlapping 12-byte chunks and keeps, per chunk, a keyed rolling
// hash and a keyed SHA-256, with the chunk's index and the form's length. A JSON
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
// base64-only strings of 16 KiB or more are skipped as images or files. The
// text of JSON held inside a string is also matched against the indexed values
// as it stands: that finds a value that is JSON with no string in it, and puts
// the placeholder where it was, so the string may no longer hold JSON. Redact
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
// # Bytes whose length must not change
//
// A protobuf message records the length of every string and nested message it
// holds, so a placeholder of another length cannot be put into one. For such
// bytes RewriteBinary overwrites what it finds where it sits. It reads the
// input as a protobuf message without a schema: a length-delimited field whose
// bytes parse completely as a message is descended into, anything else is a
// leaf, and each leaf is scanned on its own with the matcher above. Input that
// does not parse as a message is scanned whole. An extent of n bytes is
// overwritten with
//
//   - the placeholder, when it is n bytes long;
//   - the placeholder and then '*' up to n bytes, when it is shorter;
//   - the first n bytes of the placeholder, when it is longer. An extent is at
//     least 12 bytes for an indexed value and for every shipped rule, so this
//     is ph: and nine or more characters of the type and the id. A rule of
//     another file can match less: the extent is cut the same way, down to
//     "ph" or "p" for one of two bytes or one.
//
// A whole base64 or hex run that hides a value is one extent, as it is one
// replacement elsewhere. In a leaf that is valid UTF-8 an extent that would
// begin or end inside a character is widened to the character's edge. A leaf
// that is UTF-8 up to a last character its end cuts, as a field of a string
// that parses as a message can be, is treated the same up to that character,
// and an extent that reaches into it stops before it, so what was UTF-8 at
// any level still is. Text the provider signed is not known here: nothing is
// exempt.
//
// What it guarantees:
//
//   - The output is exactly as long as the input.
//   - Every byte outside a replaced extent is the input's. An extent found
//     in a leaf lies inside that leaf: it never crosses a field boundary and
//     never takes in a tag or a length.
//   - The output parses as the same protobuf structure as the input: every
//     field at every level that was descended into has the number, the wire
//     type and the length it had.
//   - A second pass over the output changes nothing. Placeholders and their
//     padding are never matched again: text that reads ph:<type>:<id> with any
//     '*' after it, or 12 or more bytes of the start of that, is left out of
//     every scan when the type is one this index writes (the type of an
//     indexed value, a rule's label, or secret, sealed or dynamic), and each
//     stretch between two of them is scanned on its own. A rule's placeholder
//     ends with its digits and a registered id where it ends; an id this index
//     does not know runs as far as an id can and stops where the matcher finds
//     a value beginning, so a value written right after a placeholder is read.
//     One call looks again at every leaf it wrote to, whole, until a look
//     changes nothing, so its last look is the first look of the next call. It stops after eight looks; only a value
//     broken into more pieces than that, each found once the one before it was
//     overwritten, is left for a later pass to finish.
//
// One case needs more than leaves. A short string of letters and digits
// parses as a message fairly often (a 20-character key id about once in
// forty, 64 hex characters about once in a hundred), and a value that is such
// a string would be looked for in the pieces between what read as its tags,
// and missed. So a message of up to 4 KiB that is also text is read as the
// one string it may be as well, for what only a string can hold: the verified
// bytes of an indexed value, or a regex rule's match, lying across what read
// as its fields. That is overwritten in every byte but those that make the
// string a message (its tags, its lengths and its varints of more than one
// byte), with the placeholder spelled by the bytes that are written. The
// output is still as long, still parses as it did, and a second pass still
// changes nothing; the few characters of the value that sit on a tag or a
// length stay. A real message is not touched by this: none holds twelve bytes
// of a registered value across a tag, and a token at the end of one of its
// strings is that string's own to find.
//
// The walk reads tags and lengths only, a step per field, each leaf is
// scanned once, and whether a message is text is settled for each byte once,
// so the cost is linear in the input however the fields are nested. Messages
// are followed 100 deep, and what lies deeper is a leaf.
//
// # Limits
//
//   - A fragment of an indexed value is certain to be caught only when it
//     holds, whole, one of the 12-byte chunks the value was cut into, and that
//     chunk counts: 2.8 bits per byte or more, and not structure. A fragment
//     of 23 bytes or more (twice the chunk, less one) always holds a chunk
//     whole, one of 12 to 22 bytes at some offsets only, and a shorter one
//     never. No length makes it certain, because every chunk a fragment holds
//     whole may be too plain to count. Of random letters and digits about one
//     chunk in 700 is, of hex digits one in 5 and of decimal digits two in 3:
//     a fragment of a value of hex digits is missed about once in 5 with one
//     chunk whole in it, once in 24 with two and once in 120 with three. The
//     start of a token is missed while all it holds whole is the token's type
//     prefix. The whole value is found whatever its chunks are.
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
//   - The body's JSON object keys are not scanned, only values. Numbers and
//     keys of JSON held inside a string are matched against the indexed values
//     and by no rule.
//   - In a protobuf message a value is found inside one string or bytes field.
//     One that a client splits over two fields is not, and neither is one
//     under 12 bytes. A field that ends inside a value holds a fragment of it,
//     which is caught or missed as any fragment is: RewriteBinary promises no
//     more of a piece of a value than the first limit above does. What is
//     missed stays as it was, and the report does not mention it.
//   - A value under 12 bytes, or with little entropy, is not protected at all.
//   - Pattern rules see a format only when it is written plainly; a random value
//     with no known format is found by them only next to a keyword.
//   - Whoever holds the Key can confirm a guessed 12-byte chunk against the
//     index, so the Key must stay with the daemon and the clients it trusts to
//     index values.
package censor
