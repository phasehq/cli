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
// hash and a keyed SHA-256, with the chunk's index and the form's length. A
// form made of hex digits, and the base64 of a value made of hex digits, is cut
// into 24-byte chunks instead (see Matching schemes). The
// resulting Entries carry no plaintext and nothing derived from the value but
// keyed hashes and lengths. The daemon that scans holds the Key, hands its bytes
// to the indexing client, and adds the Entries it gets back to its Index, which
// validates them as untrusted input. The daemon may keep the Key and the
// Entries for the daemon that starts after it: what that changes is under
// Limits.
//
// A document is indexed by what it holds, not as text. A JSON value is indexed
// string by string. So is text of two or more lines of which at least half are
// a name and a value (name: value or name=value, as in a kubeconfig, an env
// file or an INI file) and which does not begin with armour, as a PEM block
// does. Each value after a name is indexed on its own, without the quotes
// around it; so is a line that is neither a name and a value nor a comment, a
// header or a marker, as a value that has no name; and a line that is one run
// of base64 or hex characters is indexed as a line. Nothing else of such text
// is indexed: not its names, its comments or its headers, and not the text as
// a whole, so that a file of the same kind is not taken for it. A URL's
// password, or the token that is its user, is indexed on its own as well.
//
// Chunks that are structure rather than secret (PEM armour, as text or in
// base64, a token's type prefix, a URL's scheme and host, a JWT's header and
// claims, and chunks under 2.8 bits per byte) never produce a partial match
// alone. A value under 12 bytes or 2.5 bits per byte is not indexed and is
// listed as unprotected. So, in a document, are a string of a JSON value under
// 20 bytes and a value of text under 12, a URL with no credential in it, an
// email address and a certificate. Numbers next to strings in a JSON value
// are not indexed, and those that look like key material are listed: an array
// of 16 integers or more, and an integer of 12 digits or more.
//
// # Matching schemes
//
// Keyed hashes cannot be turned into other keyed hashes without the value, so
// Entries say how they were made: Entries.Version is their matching scheme,
// and EntriesVersion is the scheme IndexValue writes. A scheme version covers
// everything that decides whether entries made by one build are matched by
// another:
//
//   - the chunk sizes, and which forms are cut at which;
//   - the hash construction: how the confirming hash's key and the rolling
//     hash's table and base are derived from the Key, the rolling polynomial,
//     the confirming hash and its truncation, and what the tail hash covers;
//   - the set of encoded forms, their names, and how each is built from a
//     value (alignments, trimming, escaping, case), with how a value is split
//     into parts (JSON leaves, a URL's password, lines);
//   - how weak chunks are marked, and the minimum length and entropy below
//     which a value or a line is not indexed;
//   - the layout of Entries on the wire.
//
// A change to any of these that makes new entries differ from what an older
// build would write for the same value and key is a new scheme version. What
// the scan does with a verified chunk (how far a match is widened, when one
// chunk alone is enough, the decode pass) is not part of a scheme: it applies
// to entries of every scheme, and may change without one.
//
// The schemes so far:
//
//   - 1: every form in 12-byte chunks; the tail hash covers the bytes after
//     the last whole chunk.
//   - 2: as 1, but a form made of hex digits (the hex of any value, and a
//     value that is itself hex digits), and the base64 of a value made of hex
//     digits, are cut into 24-byte chunks, marked Wide; and the tail hash
//     covers the last whole chunk as well as the bytes after it. Nothing in
//     such entries is a hash of fewer than 24 characters of those forms, or of
//     fewer than 12 bytes of any form. A form too short for one 24-byte chunk
//     keeps a 12-byte one, so a short value is still found.
//
// An Index matches every scheme in SupportedSchemes side by side, each as it
// was made, so entries a daemon stored under an older scheme go on working
// after an upgrade. Nothing converts them: when the value is next indexed, by
// IndexValue under the current scheme, adding those entries replaces the
// older-scheme entries held for the same type and id. Entries of a scheme a
// build does not match are refused by ParseEntries and Add; a store keeps
// them as they are for the build that does, and reports them as needing to
// be registered again.
//
// A scheme is a value in scheme.go, and a later one is added beside the
// others: one that changes chunk sizes or the tail needs nothing else, and
// one that changes the hash construction or the forms adds its own beside
// those of the schemes still matched. A scheme is removed by deleting it,
// after which its entries are those of a scheme the build does not match.
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
// scan stays linear in the body whatever has been indexed. The scan makes one
// pass per chunk size that is indexed, and looks for 24-byte chunks only
// inside runs of letters and digits, which is all they can hold. One pass over a
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
//     made of digits, or of one case of letters with or without digits. Such a
//     fragment is caught only when it holds two whole chunks next to each
//     other: for certain from 35 characters, at some offsets from 24, and never
//     below. The whole form is found as before.
//   - A fragment of a form that scheme 2 cuts into 24-byte chunks needs one
//     of them whole: it is caught for certain from 47 characters (twice the
//     chunk, less one), at some offsets from 24, and never below. Those forms
//     are the hex of any value, a value that is itself hex digits (a 64-digit
//     key, say: 23 characters of it were enough under scheme 1), and the
//     base64 of such a value. The whole form is found as before, and so is
//     such a value in every other form. Entries of scheme 1 keep the lengths
//     of the item above for these forms.
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
//   - Of text that is names and values, only the values are found. A value
//     under 12 bytes there is not protected, where the same text indexed whole
//     was at times found by the lines around it, and nothing in a comment is.
//   - Pattern rules see a format only when it is written plainly; a random value
//     with no known format is found by them only next to a keyword.
//   - Whoever holds the Key and the Entries can confirm a guessed chunk: hash
//     the guess and compare. Without the Key the Entries say nothing that a
//     guess can be tested against, and without the Entries the Key says
//     nothing at all. So the Key must stay with the daemon and the clients it
//     trusts to index values, and a daemon that keeps both across restarts
//     must keep the Key apart from the Entries (the Phase AI proxy keeps it in
//     the system keystore and the Entries, sealed under a key derived from
//     it, in a file). Someone who gets both can try every value of a chunk
//     that holds few bits: 12 hex digits are 48 bits, which is within reach.
//     Scheme 2 therefore stores no hash of fewer than 24 hex digits (96 bits,
//     when the digits are the value's own). What stays within reach is a
//     chunk whose bytes are more predictable than that: 24 digits of the hex
//     of text carry about 72 bits, 24 characters of the base64 of a hex value
//     72, 24 digits of the hex of a hex value 48, a 12-byte chunk of a value
//     made of decimal digits 40, and a chunk of a value an attacker mostly
//     knows already very few. A hex value shorter than 24 digits keeps a
//     12-digit chunk, and entries stored under scheme 1 keep theirs until
//     the value is indexed again.
package censor
