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
// are) into non-overlapping 12-byte chunks and keeps, per chunk, 24 bits of a
// keyed rolling hash to look the chunk up by and a keyed SHA-256 to confirm it,
// with the chunk's index and the form's length. A form made of hex digits, and
// the base64 of a value made of hex digits, is cut into 24-byte chunks instead
// (see Matching schemes). The
// resulting Entries carry no plaintext and nothing derived from the value but
// keyed hashes and lengths.
//
// A Key is two secrets with two roles. The lookup key keys the rolling hash,
// and is one for every client of one tenant (for the Phase AI proxy, a
// Console, by the whole address it is served at, and an organisation), so a
// scan rolls one hash per position whoever of the tenant registered what.
// The confirming key keys the SHA-256 that
// confirms a chunk and the tail hash, and is one per principal: a login of
// the tenant. The daemon that scans acts as one principal. It holds the
// confirming key of every principal of its tenant, hands the lookup key and
// its own principal's confirming key to a client that says it is that login,
// and to no other, and adds the Entries it gets back to its Index under that
// principal (Index.AddKeyed), which validates them as untrusted input. A
// candidate is confirmed with the key of the principal whose entries it is
// from, so one Index matches the values of every login of the tenant.
// Nothing is shared between tenants: Add, AddKeyed and AddWithheld refuse
// entries made under another lookup key than the index's, and the same value
// indexed in two tenants gives unrelated lookup values and hashes.
//
// A daemon that keeps entries between runs takes two sets of them for one
// value from a client of its own login. Those made under the principal's key
// in the current scheme are what it keeps, and what the daemon that starts
// next knows the value by (Index.AddLoaded). Those made under a live key, one
// the daemon's process drew when it started and keeps nowhere, in scheme 1,
// are what it matches the value by while it runs (Index.AddLive): scheme 1
// finds shorter pieces of hex digits than a scheme that may be stored (see
// Limits), and its entries never leave the process. Both are one value to
// every count, and where both find it one placeholder is written. What the
// daemon loaded of a value that is registered with it again is told so
// (Index.Registered) and is no longer a store's alone, whichever of the two
// finds it. A daemon that keeps nothing has one key, its process's, and
// matches by scheme 1 alone.
//
// Entries of another login than the one a scan is for, which that login's
// own daemon took and kept, are added with Index.AddWithheld: the value is
// replaced by ph:<type> with no id, and no finding names the id, which the
// login a scan is for may not be allowed to see. Such a
// value is replaced only where a whole form of it stands (see Limits). Where
// the same value is also held with its id, the id is written. Two withheld
// values of one type share their placeholder; Finding.Withheld numbers them
// apart and is never written anywhere. How many there are is how their owner
// filed them, so what is told to the reader of a scan counts them as one.
//
// A client that does not say it is the daemon's own login (another login of
// its tenant, another tenant's, or one that cannot say whose it is) is a
// guest: it is handed a key that shares nothing with the index's, lookup key
// included, and its Entries are added with Index.AddGuest. They are withheld
// as above, found by a pass of their own over the scanned text while any are
// held, counted and bounded apart, and belong to the daemon's process alone:
// the Phase AI proxy derives a guest's key from what it drew when it started
// and keeps nowhere, and stores nothing made under it. Guests share a lookup
// key. A guest that states who it is has a confirming key of its own; those
// that state nothing share one, and are one guest: a value such a client
// registers again and again is then held once.
//
// The guests' share never refuses a guest. Each AddGuest that adds anything
// is an entry of its own, whatever is held under its type and id, so what it
// costs the share says nothing of an id; an entry added again is as new; and
// when the share is full the entries added longest ago are dropped to make
// room. Only one registration (GuestBatch) that is larger than the share by
// itself is refused, with ErrIndexFull, and none of its own entries is
// dropped for another of them.
//
// What an Index counts (IndexStats.Secrets) it counts once per principal
// that added a type and id, so no count says whether another principal holds
// an id; and what one principal may add is bounded apart from the whole
// (IndexOptions.MaxKeySecrets, MaxKeyChunks), so one client's volume leaves
// room for the others.
//
// The daemon may keep the keys and the Entries for the daemon that starts
// after it: what that changes, and what each party can do, is under Limits.
// Entries it reads back are added with Index.AddLoaded, and a Finding says so
// (Finding.Loaded) until a client adds the same entries again: a daemon can
// then treat what it only remembers more gently than what it was just told.
//
// IndexOptions.Public names texts every scanned request holds, such as a
// model host's name and the paths of its API. A value that stands whole in
// one is refused (ErrPublic): held, it would be found in every request. A
// chunk of a longer value that is a piece of one is structure, as below.
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
//   - the hash construction: which of the Key's two parts the confirming
//     hash is keyed from and how, how the rolling hash's table and base are
//     derived from the lookup key, the rolling polynomial, the confirming
//     hash and its truncation, and what the tail hash covers;
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
//   - 1: every form in 12-byte chunks, each with its whole 64-bit rolling
//     hash; the tail hash covers the bytes after the last whole chunk. Its
//     confirming hash is keyed from the lookup key, so whoever holds that
//     key can compute it. It is the scheme of what a running daemon matches a
//     value by (IndexValueScheme), under a key of its process alone, and no
//     entries of it are ever stored.
//   - 2: as 1, but a form made of hex digits (the hex of any value, and a
//     value that is itself hex digits), and the base64 of a value made of hex
//     digits, are cut into 24-byte chunks, marked Wide; and the tail hash
//     covers the last whole chunk as well as the bytes after it. Nothing in
//     such entries is a hash of fewer than 24 characters of those forms, or of
//     fewer than 12 bytes of any form. A form too short for one 24-byte chunk
//     keeps a 12-byte one, so a short value is still found. Of a chunk's
//     rolling hash the entries carry the top 24 bits (Form.Lookups) and never
//     the whole. The confirming hash and the tail hash are keyed from the
//     confirming key of the principal that registered, which IndexValue
//     requires: a lookup key alone indexes nothing under this scheme. It is
//     the scheme IndexValue writes, and the one a store keeps.
//
// An Index matches every scheme in SupportedSchemes side by side, each as it
// was made, so a client of an older version is still served. Nothing converts
// entries and none replaces another: a type and id may name several values (a
// key name is shared across apps and environments), and nothing in entries of
// two schemes says they are the same value, so a value indexed again under
// the current scheme is held under both until the older entries go with
// their index or their age. Entries of a scheme a build does not match are
// refused by ParseEntries and Add; a store keeps them as they are for the
// build that does, and reports them as needing to be registered again. Only
// schemes that carry no whole rolling hash may be stored (SchemeStorable).
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
// lookup value leads to a bounded number of chunks for each confirming key
// (so no party's chunks crowd out another's), and a match already extended
// over a stretch is not tried again inside it, so a scan stays linear in the
// body whatever has been indexed. A withheld form is led to by one chunk
// only, the first that is not structure. The scan makes one
// pass per chunk size that is indexed (and one more while scheme 1 entries
// are held), and looks for 24-byte chunks only inside runs of letters and
// digits, which is all they can hold. It keeps the whole rolling hash of the
// text and compares 24 bits of it, so a position whose 24 bits fit a chunk by
// chance costs one confirming hash, or four where the chunk leads to a
// withheld form: about one position in 700 with 23000
// chunks indexed (300 values), one in 16 at the index's cap. One pass over a
// block finds every keyword and every place a rule's prefix begins, and what a
// rule may read from those places is bounded by the block, so the rules add a
// cost that is linear too, and nearly none on text that holds no prefix.
//
// An indexed value is replaced by ph:<type>:<id>, as given when it was indexed
// (ph:<type> alone when its id is withheld, and then only where it is whole);
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
//   - A value a daemon knows only from a store, because it started again
//     and no client has registered the value with it since, is matched by
//     its entries of scheme 2, and a fragment of a form that scheme cuts
//     into 24-byte chunks needs one of them whole: it is caught for certain
//     from 47 characters (twice the chunk, less one), at some offsets from
//     24, and never below. Those forms are the hex of any value, a value that
//     is itself hex digits (a 64-digit key, say, of which 23 characters are
//     enough under scheme 1), and the base64 of such a value. The whole form
//     is found as before, and so is such a value in every other form. The
//     limit ends when a client registers the value with that daemon again: a
//     value registered with the running daemon is matched by entries of
//     scheme 1, which keep the lengths of the two items above for every form.
//   - A value whose id is withheld (another login's, or a guest's) is matched
//     whole or not at all: where every chunk and the tail of one of its
//     forms stand, which is the whole value in any encoding listed above, a
//     whole string of a JSON value or a whole value of text that is names
//     and values, or a URL's whole password or token. What this costs: a
//     fragment of such a value, a copy cut short by one character, and single
//     lines of a multi-line value such as a PEM body are not caught, at any
//     length, though the same value held with its id is caught by them as
//     the items above say. One edge is wider than that: a base64 form holds
//     only the characters made of the value's bits alone, which leaves out up
//     to four bits of the value's first and last characters. So inside
//     base64, at those alignments, a copy with its first or last character
//     cut or changed is still replaced when the character standing in that
//     place shares the bits the form does hold, as about four others do.
//     Whole or not at all is the price of not answering a guess: the
//     reader of a scan, who cannot name that value, would otherwise learn
//     from a replaced fragment that 12 guessed bytes are part of it, and
//     could work a value out chunk by chunk. Whole, a guess is the value.
//     What the time a scan takes still says of such a value is below.
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
//   - Entries are tested against with keys, and who holds which decides what
//     a party can do. A chunk's entry in scheme 2 is 24 bits of its rolling
//     hash, under the lookup key, and a keyed SHA-256 truncated to 128 bits,
//     under the confirming key of the principal that registered it. The
//     Phase AI proxy derives every key from one master in the system
//     keystore, which it hands to no one, by way of a root per tenant, and
//     keeps the Entries in a file, each record sealed under its tenant's
//     key. A proxy derives its own tenant's keys and no other's. Then:
//   - Between tenants nothing can be tested at all, by a client or by a
//     proxy: a session of one tenant holds no key of another, does not
//     open, load or match its records, and says nothing of them anywhere,
//     not even how many there are. A stored value of another tenant in a
//     request goes through as it is. A proxy's tenant and login are what the session
//     the Console opened for it says, never what a client says: a client
//     states its own, the proxy compares the two, and a command that is not
//     the proxy's own login (another account's token in its environment,
//     say, or another login of the same organisation) is a guest. Its values
//     are replaced by ph:<type> while that proxy runs and are never stored,
//     for the proxy's login or for its own. A proxy whose session names
//     nobody, as an older Console's does not, keeps nothing at all: it has
//     no tenant to keep apart, so every command is handed its one process
//     key and every value is held with its id, as before anything was kept.
//   - The file alone says nothing a guess can be tested against. In the
//     clear it shows how many records it holds in all and how long each is,
//     which grows with its value's length. Each record's head is sealed under
//     a key derived from the master, so the file does not show whose a record
//     is, of which login, when it was registered, or which records share a
//     tenant, a login or a placeholder; and it shows no hash.
//   - A client of a session (any process holding the proxy's capability, an
//     AI Agent included) is handed the lookup key and the confirming key of
//     the proxy's own login when it states that login, and otherwise keys
//     of that process alone. With the file as well it is where the file
//     alone is: no key it is handed opens a seal. If it had its
//     tenant's Entries out of their seal, it could confirm a guessed chunk
//     of its own principal's values, which it could read anyway. Of another
//     principal's it could hash nothing, having no confirming key of theirs,
//     but it would have their lookup values and the key they are under,
//     which is the tenant's. One lookup value is 24 bits of one chunk of one
//     form: one wrong guess of the chunk in 2^24 fits it, so by itself it
//     leaves a chunk of b unknown bits 2^(b-24) guesses and says nothing of
//     which is right. Together they say more, because a guess is tested
//     against every lookup value it would give. A guess of a whole value
//     gives all n of them, over every chunk of every form, and a wrong one
//     fits them all about once in 2^(24n): a value whose candidates this
//     client can list (one it has seen elsewhere, a short or patterned one)
//     is picked out with no confirming key. A guess of one chunk gives one
//     for each form its bytes stand in, as they are and in the value's hex
//     in both cases: up to 72 bits about 12 bytes, so of the guesses that
//     fit one form's value the others leave the right one, and listing them
//     is the work the process with the master has below. The 24 bits so hide a
//     chunk only while its guesses are too many to list, and a whole value
//     not at all once it can be guessed. It would also
//     have what Entries state openly: each form's length and which chunks
//     are structure. A client is trusted only to say it is the proxy's own
//     login, as leak protection is against accidents. One that states
//     another login of its tenant is handed nothing derived from the
//     master, as one of another tenant is: a right guess at that login's
//     value indexes, under what it holds, to hashes the stored ones are not.
//   - Such a client can still put guesses in a request and see whether the
//     proxy replaces them. Of a value of its own login that is one guess a
//     chunk's bytes of traffic. Of another login's, or a guest's, only a
//     guess of the whole value (or of a whole leaf, or a URL's whole
//     password) is answered, by ph:<type> and never its id: a chunk of such
//     a value is confirmed to no one. Nothing stored narrows either. Nor
//     does what the client registers: the chunks one lookup value leads to
//     are bounded for each confirming key apart, so forged entries under a
//     guess's lookup value push out no one's chunk but their owner's.
//   - Such a client can also time the proxy, and that still says something of
//     a value it cannot name. A withheld form is looked up by one chunk, the
//     first that is not structure. Where that chunk's 24 lookup bits turn up
//     and the form would fit, the scan hashes that chunk and three more, those
//     that are not structure first (all of a form of four chunks or fewer),
//     whether or not any confirms, and the rest of the form only when all of
//     those did, again all of it. So a scan takes the same time for a chunk
//     that confirms as for text that only has its lookup bits, and no time at
//     all for any other chunk of the value: no chunk is confirmed by timing,
//     and none but that one is even looked for. What a client that sends large
//     requests and times them can still tell: whether a guess of that one
//     chunk has the 24 lookup bits of a chunk that leads to some withheld
//     form, as a right guess always has and a wrong one about once in 2^24 for
//     each such form held (5 MB that repeat such a guess take about a tenth of
//     a second longer to scan); with the lookup key it holds, which lookup
//     values are in use that way, which narrows a guess of that chunk as the
//     stored lookup values of those chunks would (above: each form's leading
//     chunk has its own) and no further; and whether a guess
//     of those four chunks together is right, by the hashing that follows (48
//     characters, 96 of a form cut into pairs, and fewer unknown ones where a
//     value has under four chunks that are not structure). Keeping the lookup
//     values from a client would take a second lookup key, one no client of
//     another login is handed, for the entries a login cannot name, and so a
//     second pass over every request; no scan makes it. Even then a lookup
//     that hits would take longer than one that misses: nothing short of
//     hashing at every position hides that.
//   - A process of the same user that reads the keystore has the master, so
//     every key of every tenant, and the file opens to it. It confirms a
//     guessed chunk of any principal's value by hashing it, and the 24 bits come off the work:
//     the rolling hash is a polynomial in the chunk's bytes, and with the
//     lookup key it can be split in the middle, so the guesses that fit are
//     listed without trying the others. A chunk of b unknown bits costs
//     about 2^(b-24) confirming hashes (and a table of 2^(b/2)), not 2^b:
//     24 hex digits of a value that is hex, 96 bits, about 2^72; 12
//     characters of a value made of letters and digits, 71 bits, about 2^47;
//     12 characters of the base64 of random bytes, 24 hex digits of the hex
//     of text, and 24 characters of the base64 of a hex value, 72 bits
//     each, about 2^48. 2^47 hashes are days of work for hardware built for
//     it, so such a value is not safe from that process for long. A chunk
//     that holds few bits is found whatever is stored: 24 digits of the hex
//     of a hex value hold 48 bits (2^24 hashes), a 12-digit chunk of a hex
//     value shorter than 24 digits 48, a 12-byte chunk of a value made of
//     decimal digits 40, and a chunk of a value the holder mostly knows very
//     few. Such a process can also read the logins the keystore holds.
//   - So the master must stay with the daemon, a confirming key with its
//     own principal's clients, and a daemon that keeps Entries across
//     restarts must keep the master apart from them.
//   - Entries of scheme 1 hold the whole rolling hash, from which a
//     12-character chunk is found in about 2^36 steps and a 12-digit hex one
//     in 2^24, whatever the confirming hash is, and their confirming hash is
//     keyed from the lookup key every client holds. They are therefore never
//     stored. A daemon holds them in memory while it runs, when a client of
//     an older version registers them, and no build writes them now.
package censor
