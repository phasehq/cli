package censor

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phasehq/cli/internal/censortest"
)

// The tests build protobuf by hand: a tag, then a value. Nothing here uses the
// reader the walk uses.

func protoTag(b []byte, number, wire int) []byte {
	return binary.AppendUvarint(b, uint64(number)<<3|uint64(wire))
}

func protoString(b []byte, number int, payload []byte) []byte {
	b = protoTag(b, number, 2)
	b = binary.AppendUvarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func protoNumber(b []byte, number int, value uint64) []byte {
	return binary.AppendUvarint(protoTag(b, number, 0), value)
}

// builtLeaf is a string or bytes field of a built message: what the test
// knows the schema to be, which the walk has to work out.
type builtLeaf struct {
	start, end int
	kind       string
	// planted are the ids of the values put into it, each of which a scan is
	// meant to remove.
	planted []string
}

// builtMessage is a message and where its leaves are. Every byte outside a
// leaf is a tag, a length or a number.
type builtMessage struct {
	data   []byte
	leaves []builtLeaf
}

func (m *builtMessage) field(number int, payload []byte, leaves []builtLeaf) {
	m.data = protoTag(m.data, number, 2)
	m.data = binary.AppendUvarint(m.data, uint64(len(payload)))
	for _, leaf := range leaves {
		leaf.start += len(m.data)
		leaf.end += len(m.data)
		m.leaves = append(m.leaves, leaf)
	}
	m.data = append(m.data, payload...)
}

func (m *builtMessage) leaf(number int, kind string, payload []byte, planted ...string) {
	m.field(number, payload, []builtLeaf{{start: 0, end: len(payload), kind: kind, planted: planted}})
}

// planted is a value the fixture holds and a scan is meant to remove.
type plantedValue struct{ id, value string }

// binaryFixture indexes the fixture's values and returns those a scan removes.
func binaryFixture(t testing.TB) (*Index, []plantedValue, *censortest.Verifier) {
	t.Helper()
	fixture := censortest.NewFixture()
	var secrets []secret
	var candidates []plantedValue
	for _, entry := range fixture.Entries {
		if entry.Expect == "rule" {
			continue
		}
		secrets = append(secrets, secret{ID: entry.ID, Type: entry.Type, Value: entry.Value})
		if entry.Expect == "" || entry.Expect == "hit" {
			candidates = append(candidates, plantedValue{id: entry.ID, value: entry.Value})
		}
	}
	ix, verifier := build(t, secrets...), censortest.NewVerifier(fixture.Entries)
	// The values are random, and now and then one has a part too plain to be
	// indexed, which no scan removes: 21 digits fall under the entropy floor
	// about once in 140. What is asked of the walk is what the matcher can do.
	var values []plantedValue
	for _, candidate := range candidates {
		plain, _ := ix.Redact([]byte("the value " + candidate.value + " as text"))
		if len(unexpectedMisses(verifier, plain)) == 0 {
			values = append(values, candidate)
		} else {
			t.Logf("%s holds a part the matcher does not index and is not planted", candidate.id)
		}
	}
	return ix, values, verifier
}

// unexpectedMisses names what the verifier still finds and a scan is meant to
// have removed.
func unexpectedMisses(verifier *censortest.Verifier, payload []byte) []string {
	var left []string
	for _, miss := range verifier.Check(payload) {
		if !miss.Expected {
			left = append(left, miss.ID+" "+miss.Part+" as "+miss.Form)
		}
	}
	return left
}

var ordinaryWords = []string{
	"the", "build", "finished", "with", "warnings", "see", "the", "log", "for", "details", "naïve", "über", "日本語", "ordre", "größe",
	"retry", "after", "the", "deploy", "window", "closes", "🙂", "config", "loaded", "from", "disk", "é", "worker", "started",
}

// messageMaker makes messages of every shape the walk has to tell apart.
type messageMaker struct {
	rng    *rand.Rand
	values []plantedValue
}

func (g *messageMaker) words(count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = ordinaryWords[g.rng.Intn(len(ordinaryWords))]
	}
	return strings.Join(parts, " ")
}

// plant writes one value in one of the forms a request carries it in, between
// two pieces of text. What stands right next to it is a separator, or a
// character of several bytes.
func (g *messageMaker) plant() (string, string) {
	value := g.values[g.rng.Intn(len(g.values))]
	var encoded string
	switch g.rng.Intn(5) {
	case 0, 1:
		encoded = value.value
	case 2:
		encoded = base64.StdEncoding.EncodeToString([]byte(value.value))
	case 3:
		encoded = base64.StdEncoding.EncodeToString([]byte("deploy:" + value.value))
	default:
		encoded = hex.EncodeToString([]byte(value.value))
	}
	edges := []string{" ", "\n", ": ", "=", "\"", "é", "日", "🙂"}
	before, after := edges[g.rng.Intn(len(edges))], edges[g.rng.Intn(len(edges))]
	if after == "=" {
		after = " "
	}
	return value.id, g.words(1+g.rng.Intn(6)) + before + encoded + after + g.words(g.rng.Intn(6))
}

// accident is text that parses as a message from its first byte to its last:
// printable tags, each with the value its wire type needs.
func (g *messageMaker) accident(fields int) []byte {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var out []byte
	for i := 0; i < fields; i++ {
		var tags string
		width := 0
		switch g.rng.Intn(3) {
		case 0:
			tags, width = "(08@HPX`hpx", 1
		case 1:
			tags, width = "!)19AIQYaiqy", 8
		default:
			tags, width = "%-5=EMU]emu}", 4
		}
		out = append(out, tags[g.rng.Intn(len(tags))])
		for j := 0; j < width; j++ {
			out = append(out, letters[g.rng.Intn(len(letters))])
		}
	}
	return out
}

func (g *messageMaker) message(depth int) *builtMessage {
	m := &builtMessage{}
	for count := 1 + g.rng.Intn(7); count > 0; count-- {
		number := 1 + g.rng.Intn(18)
		if g.rng.Intn(12) == 0 {
			number = 1000 + g.rng.Intn(100000)
		}
		switch kind := g.rng.Intn(12); {
		case kind < 3:
			m.leaf(number, "string", []byte(g.words(g.rng.Intn(30))))
		case kind < 6:
			id, text := g.plant()
			m.leaf(number, "string", []byte(text), id)
		case kind == 6 && depth > 0:
			inner := g.message(depth - 1)
			m.field(number, inner.data, inner.leaves)
		case kind == 7 && depth > 0:
			// A repeated field: the same number several times over.
			for repeat := 2 + g.rng.Intn(3); repeat > 0; repeat-- {
				inner := g.message(depth - 1)
				m.field(number, inner.data, inner.leaves)
			}
		case kind == 8:
			raw := make([]byte, g.rng.Intn(64))
			g.rng.Read(raw)
			m.leaf(number, "bytes", raw)
		case kind == 9:
			var packed []byte
			for n := g.rng.Intn(40); n > 0; n-- {
				packed = binary.AppendUvarint(packed, g.rng.Uint64()>>uint(g.rng.Intn(64)))
			}
			m.leaf(number, "packed", packed)
		case kind == 10:
			m.leaf(number, "accident", g.accident(2+g.rng.Intn(12)))
		default:
			switch g.rng.Intn(3) {
			case 0:
				m.data = protoNumber(m.data, number, g.rng.Uint64()>>uint(g.rng.Intn(64)))
			case 1:
				m.data = binary.LittleEndian.AppendUint64(protoTag(m.data, number, 1), g.rng.Uint64())
			default:
				m.data = binary.LittleEndian.AppendUint32(protoTag(m.data, number, 5), g.rng.Uint32())
			}
		}
	}
	return m
}

// shapeField is a field as the test's own reader sees it.
type shapeField struct {
	number     uint64
	wire       int
	start, end int
}

// shapeOf reads data as one message with a reader of the test's own, or
// reports that it is not one.
func shapeOf(data []byte) ([]shapeField, bool) {
	var fields []shapeField
	for at := 0; at < len(data); {
		tag, size := binary.Uvarint(data[at:])
		if size <= 0 || tag>>3 == 0 || tag>>3 > 1<<29-1 {
			return nil, false
		}
		at += size
		field := shapeField{number: tag >> 3, wire: int(tag & 7), start: at}
		switch field.wire {
		case 0:
			_, size := binary.Uvarint(data[at:])
			if size <= 0 {
				return nil, false
			}
			field.end = at + size
		case 1:
			field.end = at + 8
		case 5:
			field.end = at + 4
		case 2:
			length, size := binary.Uvarint(data[at:])
			if size <= 0 || length > uint64(len(data)-at-size) {
				return nil, false
			}
			field.start = at + size
			field.end = field.start + int(length)
		default:
			return nil, false
		}
		if field.end > len(data) {
			return nil, false
		}
		fields = append(fields, field)
		at = field.end
	}
	return fields, len(fields) > 0
}

// sameShape reports whether after holds every field before holds, at every
// level down to depth: the same numbers, wire types and lengths in the same
// places. It descends wherever before parses as a message.
func sameShape(before, after []byte, depth int) error {
	fields, ok := shapeOf(before)
	if !ok || depth == 0 {
		return nil
	}
	now, ok := shapeOf(after)
	if !ok {
		return fmt.Errorf("a message of %d fields no longer parses", len(fields))
	}
	if len(now) != len(fields) {
		return fmt.Errorf("a message of %d fields has %d", len(fields), len(now))
	}
	for i, field := range fields {
		if now[i] != field {
			return fmt.Errorf("field %d was %+v and is %+v", i, field, now[i])
		}
		if field.wire == 2 {
			if err := sameShape(before[field.start:field.end], after[field.start:field.end], depth-1); err != nil {
				return err
			}
		}
	}
	return nil
}

// rewriteChecked runs RewriteBinary and checks everything it guarantees
// whatever the input is. It returns the output and the ranges written to.
func rewriteChecked(t testing.TB, ix *Index, input []byte, opts ScanOptions) ([]byte, *Report, [][2]int) {
	t.Helper()
	original := bytes.Clone(input)
	var written [][2]int
	out, report := ix.rewriteBinary(input, opts, func(start, end int) { written = append(written, [2]int{start, end}) })
	if !bytes.Equal(input, original) {
		t.Fatal("the input was written to")
	}
	if len(out) != len(input) {
		t.Fatalf("the output is %d bytes and the input %d", len(out), len(input))
	}
	inside := make([]bool, len(input))
	for _, extent := range written {
		if extent[0] < 0 || extent[1] > len(input) || extent[0] >= extent[1] {
			t.Fatalf("an extent of %v in %d bytes", extent, len(input))
		}
		for i := extent[0]; i < extent[1]; i++ {
			inside[i] = true
		}
	}
	for i := range input {
		if !inside[i] && out[i] != input[i] {
			t.Fatalf("byte %d changed outside every replaced extent", i)
		}
	}
	if changed := !bytes.Equal(out, input); changed != report.Changed || (len(written) > 0) != changed {
		t.Fatalf("changed = %v, the report says %v, %d extents", changed, report.Changed, len(written))
	}
	if !report.Changed && len(input) > 0 && &out[0] != &input[0] {
		t.Fatal("an unchanged input did not come back as it was")
	}
	if err := sameShape(input, out, maxBinaryDepth); err != nil {
		t.Fatalf("the output is not the message the input was: %v", err)
	}
	again, second := ix.RewriteBinary(out, opts)
	if !bytes.Equal(again, out) || second.Changed || second.Found() {
		t.Fatalf("a second pass changed the output: %+v", second)
	}
	return out, report, written
}

// The guarantees, over messages of every shape with the fixture's values in
// them raw, in base64 and in hex.
func TestBinaryGuaranteesOverGeneratedMessages(t *testing.T) {
	ix, values, verifier := binaryFixture(t)
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	maker := &messageMaker{rng: rng, values: values}
	messages := 150
	if testing.Short() || raceEnabled {
		messages = 40
	}
	replaced, leavesWithValues := 0, 0
	for i := 0; i < messages; i++ {
		built := maker.message(4)
		out, report, written := rewriteChecked(t, ix, built.data, ScanOptions{})

		// The test knows the schema: every byte that changed lies in a leaf of
		// it, and every extent of a leaf's own scan inside that one leaf.
		sort.Slice(built.leaves, func(a, b int) bool { return built.leaves[a].start < built.leaves[b].start })
		leafOf := func(at int) int {
			k := sort.Search(len(built.leaves), func(k int) bool { return built.leaves[k].end > at })
			if k == len(built.leaves) || built.leaves[k].start > at {
				return -1
			}
			return k
		}
		for at := range out {
			if out[at] != built.data[at] && leafOf(at) < 0 {
				t.Fatalf("seed %d message %d: byte %d, which is no part of a leaf, changed", seed, i, at)
			}
		}
		for _, extent := range written {
			if leafOf(extent[0]) < 0 || leafOf(extent[0]) != leafOf(extent[1]-1) {
				t.Fatalf("seed %d message %d: the extent %v is not inside one leaf", seed, i, extent)
			}
		}
		for _, leaf := range built.leaves {
			was, is := built.data[leaf.start:leaf.end], out[leaf.start:leaf.end]
			if utf8.Valid(was) && !utf8.Valid(is) {
				t.Fatalf("seed %d message %d: a string is no longer UTF-8", seed, i)
			}
			if len(leaf.planted) == 0 {
				continue
			}
			leavesWithValues++
			if bytes.Equal(was, is) {
				t.Fatalf("seed %d message %d: a leaf holding %v was left as it was", seed, i, leaf.planted)
			}
			if left := unexpectedMisses(verifier, is); len(left) > 0 {
				t.Fatalf("seed %d message %d: still there: %v", seed, i, left)
			}
		}
		replaced += report.Inventory + report.Redacted
	}
	if leavesWithValues == 0 || replaced < leavesWithValues {
		t.Fatalf("seed %d: %d leaves held values and %d were replaced", seed, leavesWithValues, replaced)
	}
	t.Logf("seed %d: %d messages, %d leaves with values, %d replacements", seed, messages, leavesWithValues, replaced)
}

// Every file of the fake-secret repository, sent as a string of a protobuf
// message, loses what it loses as a tool result of a JSON request: the same
// matcher reads both, and the independent verifier finds nothing left.
func TestBinaryFixtureEndToEnd(t *testing.T) {
	fixture := censortest.NewFixture()
	var secrets []secret
	for _, entry := range fixture.Entries {
		if entry.Expect != "rule" {
			secrets = append(secrets, secret{ID: entry.ID, Type: entry.Type, Value: entry.Value})
		}
	}
	ix := build(t, secrets...)
	verifier := censortest.NewVerifier(fixture.Entries)
	found := map[string]bool{}
	labels := map[string]int{}
	for name, content := range fixture.Files {
		message := protoString(protoString(protoNumber(nil, 1, 4), 2, []byte(name)), 3, protoString(nil, 1, []byte(content)))
		out, report, _ := rewriteChecked(t, ix, message, ScanOptions{})
		for _, finding := range report.Findings {
			if finding.Kind == kindInventory {
				found[strings.TrimPrefix(finding.Placeholder, "ph:"+placeholderType(finding.Placeholder)+":")] = true
			} else {
				labels[finding.Label]++
			}
		}
		// Nothing is left that the same file loses as plain text.
		plain, _ := ix.Redact([]byte(content))
		leftAsText := unexpectedMisses(verifier, plain)
		for _, left := range unexpectedMisses(verifier, out[len(out)-len(content):]) {
			if !slices.Contains(leftAsText, left) {
				t.Errorf("%s: still there: %s", name, left)
			}
		}
		// What the JSON path finds in the same file is what this finds. One
		// thing is the JSON path's alone: under a key that is a keyword it
		// takes the placeholder of an indexed value for a value once more.
		request := apply(ix, modelRequest(content))
		asJSON, asProtobuf := map[string]int{}, map[string]int{}
		for _, finding := range request.Rules {
			asJSON[finding.Label]++
		}
		for _, finding := range report.Findings {
			if finding.Kind == kindRule {
				asProtobuf[finding.Label]++
			}
		}
		if extra := asJSON["keyword_secret"] - asProtobuf["keyword_secret"]; extra > 0 {
			if asJSON["keyword_secret"] -= extra; asJSON["keyword_secret"] == 0 {
				delete(asJSON, "keyword_secret")
			}
		}
		if (len(request.Hits) > 0) != (report.Inventory > 0) || !reflect.DeepEqual(asJSON, asProtobuf) {
			t.Errorf("%s: as JSON %d values and rules %v, as protobuf %d and %v", name, len(request.Hits), asJSON, report.Inventory, asProtobuf)
		}
	}
	for _, entry := range fixture.Entries {
		if (entry.Expect == "" || entry.Expect == "hit") && !found[entry.ID] {
			t.Errorf("%s (%s) was never caught", entry.ID, entry.Where)
		}
	}
	if labels["keyword_secret"] < 3 || labels["phase_service_token"] == 0 || labels["phase_pat"] == 0 {
		t.Errorf("the values only a rule knows were not all caught: %v", labels)
	}
}

// What an extent is overwritten with, by how its length compares with the
// placeholder's.
func TestBinaryOverwriteShapes(t *testing.T) {
	value := "Q7tZ2mK9pL4vX8rN1wB6" // 20 bytes
	for _, c := range []struct {
		name, id, want string
	}{
		{"shorter than the extent", "db", "ph:secret:db********"},
		{"as long as the extent", "abcdefghij", "ph:secret:abcdefghij"},
		{"longer than the extent", "a-much-longer-identifier", "ph:secret:a-much-lon"},
	} {
		t.Run("the placeholder is "+c.name, func(t *testing.T) {
			ix := build(t, secret{ID: c.id, Value: value})
			text := "before " + value + " after"
			message := protoString(protoNumber(nil, 1, 7), 2, []byte(text))
			out, report, written := rewriteChecked(t, ix, message, ScanOptions{})
			want := protoString(protoNumber(nil, 1, 7), 2, []byte("before "+c.want+" after"))
			if !bytes.Equal(out, want) || report.Inventory != 1 || len(written) != 1 || written[0][1]-written[0][0] != len(value) {
				t.Fatalf("got %q, want %q (%+v)", out, want, report)
			}
			if report.Findings[0].Placeholder != "ph:secret:"+c.id {
				t.Fatalf("the report names %q", report.Findings[0].Placeholder)
			}
		})
	}
	// A pattern rule's match is overwritten the same way.
	ix := build(t)
	token := "ghp_" + randomString(t, alnum, 36)
	key := "AKIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	out, report, _ := rewriteChecked(t, ix, protoString(nil, 1, []byte("push with "+token+" as "+key+".")), ScanOptions{})
	want := "push with ph:github_token:1" + strings.Repeat("*", 40-len("ph:github_token:1")) + " as ph:aws_access_key_id."
	if string(out[2:]) != want || report.Redacted != 2 {
		t.Fatalf("got %q, want %q", out[2:], want)
	}
}

// An extent under 12 bytes can only come from a rule of another file. It is
// cut like any other, down to a piece of "ph:".
func TestBinaryExtentsShorterThanAPlaceholderCanSay(t *testing.T) {
	rules, err := ParseRules([]byte(`
rules:
  - id: door-code
    regex: '\bDOOR[0-9]{4}\b'
    label: door
  - id: short-code
    regex: '\bZQ\b'
    label: zq
`))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := NewIndex(newKey(t), IndexOptions{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	out, report, written := rewriteChecked(t, ix, protoString(nil, 3, []byte("the code is DOOR4821 and ZQ, nothing else")), ScanOptions{})
	if string(out[2:]) != "the code is ph:door: and ph, nothing else" || report.Redacted != 2 || len(written) != 2 {
		t.Fatalf("got %q (%+v)", out[2:], report)
	}
}

// A partial match is widened over what could still be the value, which can end
// inside a character of several bytes. The extent is widened to the
// character's edge, so the string stays UTF-8.
func TestBinaryExtentsEndAtCharacterEdges(t *testing.T) {
	// A piece of one chunk is found only when that chunk is not too plain to
	// count on its own, so the value is made of chunks that all count.
	var value string
	for plain := true; plain; {
		value = randomString(t, alnum, 48)
		plain = false
		for at := 0; at < len(value); at += chunkSize {
			plain = plain || entropy(value[at:at+chunkSize]) < weakChunkEntropy+0.2
		}
	}
	ix := build(t, secret{ID: "k", Value: value})
	for cut := 12; cut < 40; cut++ {
		for _, neighbour := range []string{"日本語のテキストが続きます", "ééééééééééééééééééééé", "🙂🙂🙂🙂🙂🙂🙂🙂", "ünïcödé téxt hérè"} {
			text := "à " + value[:cut] + neighbour + " and " + neighbour + value[len(value)-cut:] + " ça"
			out, _, written := rewriteChecked(t, ix, protoString(nil, 1, []byte(text)), ScanOptions{})
			leaf := out[len(out)-len(text):]
			if !utf8.Valid(leaf) {
				t.Fatalf("cut %d next to %q: the string is no longer UTF-8", cut, neighbour)
			}
			if bytes.Contains(leaf, []byte(value[:12])) || bytes.Contains(leaf, []byte(value[len(value)-12:])) {
				t.Fatalf("cut %d next to %q: a piece of the value is left: %q", cut, neighbour, leaf)
			}
			offset := len(out) - len(text)
			for _, extent := range written {
				if !utf8.RuneStart(text[extent[0]-offset]) || (extent[1]-offset < len(text) && !utf8.RuneStart(text[extent[1]-offset])) {
					t.Fatalf("cut %d next to %q: the extent %v cuts a character", cut, neighbour, extent)
				}
			}
			if !strings.HasPrefix(string(leaf), "à ph:secret:k") || !strings.HasSuffix(string(leaf), " ça") {
				t.Fatalf("cut %d next to %q: got %q", cut, neighbour, leaf)
			}
		}
	}
	// Bytes that are not UTF-8 to begin with are left to be what they are.
	raw := append([]byte{0xff, 0xfe}, value[:20]...)
	raw = append(raw, 0xe6, 0x97, 0xa5, 0xe6, 0x97)
	rewriteChecked(t, ix, protoString(nil, 1, raw), ScanOptions{})
}

// Where the matcher takes a whole base64 or hex run, the whole run is one
// extent, and so is a run that only inflates to the value.
func TestBinaryEncodedRunsAreOverwrittenWhole(t *testing.T) {
	value := "whsec_" + randomString(t, alnum, 32)
	ix := build(t, secret{ID: "webhook", Value: value})
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte(`{"release":"orders","config":{"signing":"` + value + `"}}`))
	_ = gz.Close()
	for name, run := range map[string]string{
		"base64":            base64.StdEncoding.EncodeToString([]byte(value)),
		"base64 in a blob":  base64.StdEncoding.EncodeToString([]byte(`{"user":"deploy","password":"` + value + `"}`)),
		"hex":               hex.EncodeToString([]byte(value)),
		"hex around base64": hex.EncodeToString([]byte(`{"signing":"` + base64.StdEncoding.EncodeToString([]byte(value)) + `"}`)),
		"gzip in base64":    base64.StdEncoding.EncodeToString(compressed.Bytes()),
	} {
		t.Run(name, func(t *testing.T) {
			// The string begins with a byte that is no tag, so it is a leaf
			// whatever the run holds.
			message := protoString(protoString(nil, 1, []byte("name")), 2, []byte("data: "+run+"\nnext line"))
			out, report, written := rewriteChecked(t, ix, message, ScanOptions{})
			want := "data: ph:secret:webhook" + strings.Repeat("*", len(run)-len("ph:secret:webhook")) + "\nnext line"
			if got := string(out[len(out)-len(want):]); got != want || report.Inventory == 0 || len(written) != 1 {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

// Input that is no protobuf message is one leaf.
func TestBinaryInputThatIsNoMessageIsOneLeaf(t *testing.T) {
	value := randomString(t, alnum, 40)
	ix := build(t, secret{ID: "k", Value: value})
	padded := "ph:secret:k" + strings.Repeat("*", 40-len("ph:secret:k"))
	for name, input := range map[string]string{
		"text":              "export TOKEN=" + value + "\n",
		"JSON":              `{"messages":[{"role":"user","content":"the key is ` + value + `"}]}`,
		"a truncated field": string(protoString(nil, 1, []byte("the key is "+value+" and more")))[:20+len(value)],
		"bytes after one":   string(protoString(nil, 1, []byte("the key is "+value))) + "\x07\x07\x07",
		"a group":           string(protoTag(protoString(protoTag(nil, 3, 3), 1, []byte("the key is "+value)), 3, 4)),
	} {
		out, report, _ := rewriteChecked(t, ix, []byte(input), ScanOptions{})
		if want := strings.Replace(input, value, padded, 1); string(out) != want || report.Inventory != 1 || report.Strings != 1 {
			t.Errorf("%s: got %q, want %q (%+v)", name, out, want, report)
		}
	}
	for _, input := range [][]byte{nil, {}, []byte("short"), bytes.Repeat([]byte{0xff}, 64), bytes.Repeat([]byte{0x80}, 64)} {
		if out, report, _ := rewriteChecked(t, ix, input, ScanOptions{}); report.Changed || !bytes.Equal(out, input) {
			t.Errorf("%q changed", input)
		}
	}
}

// Messages inside messages are followed, a hundred deep; what lies deeper is
// a leaf, and a value there is still found.
func TestBinaryNestingIsFollowedAndBounded(t *testing.T) {
	// It begins with a byte that is no tag, so alone in a field it is a leaf.
	value := "s" + randomString(t, alnum, 39)
	ix := build(t, secret{ID: "k", Value: value})
	padded := "ph:secret:k" + strings.Repeat("*", 40-len("ph:secret:k"))
	for _, depth := range []int{1, 2, 30, maxBinaryDepth - 1, maxBinaryDepth, maxBinaryDepth + 40, 2000} {
		message := protoString(protoNumber(nil, 1, 1), 2, []byte("the key is "+value))
		for i := 0; i < depth; i++ {
			message = protoString(protoNumber(nil, 1, uint64(i)), 3, message)
		}
		out, report, _ := rewriteChecked(t, ix, message, ScanOptions{})
		if want := bytes.Replace(message, []byte(value), []byte(padded), 1); !bytes.Equal(out, want) || report.Inventory != 1 {
			t.Fatalf("%d deep: the value was not overwritten where it sits (%+v)", depth, report)
		}
	}
	// Wide as well as deep: every field of a large message is a leaf of its own.
	var wide []byte
	for i := 0; i < 20000; i++ {
		wide = protoString(wide, 1+i%15, []byte("an ordinary line of output"))
	}
	wide = protoString(wide, 4, []byte(value))
	started := time.Now()
	out, report, _ := rewriteChecked(t, ix, wide, ScanOptions{})
	if !bytes.HasSuffix(out, []byte(padded)) || report.Strings != 20001 {
		t.Fatalf("a wide message: %+v", report)
	}
	t.Logf("20001 fields, %d bytes: %v with every check", len(wide), time.Since(started))
}

// The cost stays linear however fields are nested: a message whose every level
// reads as text almost to its end is walked in about the time of any other.
func TestBinaryWalkCostStaysLinear(t *testing.T) {
	limit := 2 * time.Second
	if raceEnabled {
		limit *= 10
	}
	ix := build(t, manySecrets(t, 50)...)
	// Printable tags and lengths all the way down, and one byte that is not
	// text at the end of each level.
	var chains []byte
	for len(chains) < 2<<20 {
		level := []byte("the innermost text of a chain of fields")
		for len(level) < 110 {
			level = append(protoString(nil, 4, level), 0x08, 0x01)
		}
		chains = protoString(chains, 2, level)
	}
	best := time.Hour
	for i := 0; i < 3; i++ {
		started := time.Now()
		if _, report := ix.RewriteBinary(chains, ScanOptions{}); report.Changed {
			t.Fatal("ordinary text was changed")
		}
		best = min(best, time.Since(started))
	}
	t.Logf("%d KB of nested fields in %v", len(chains)>>10, best)
	if best > limit {
		t.Fatalf("the walk took %v, over %v", best, limit)
	}
}

// A string that happens to parse as a message is scanned as a string too:
// a value in it is overwritten in everything but the bytes that read as tags
// and lengths, and it still parses as it did.
func TestBinaryTextThatParsesAsAMessageIsStillRead(t *testing.T) {
	// A key id of this shape parses as a message about once in forty.
	var parsing []string
	for attempts := 0; len(parsing) < 8; attempts++ {
		if attempts > 200000 {
			t.Fatal("no key id parsed as a message")
		}
		candidate := "AKIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
		if _, ok := shapeOf([]byte(candidate)); ok {
			parsing = append(parsing, candidate)
		}
	}
	for _, registered := range []bool{true, false} {
		for _, candidate := range parsing {
			ix := build(t)
			if registered {
				ix = build(t, secret{ID: "aws", Value: candidate})
			}
			// A field of its own, as a key and its value are sent.
			message := protoString(protoString(nil, 1, []byte("AWS_ACCESS_KEY_ID")), 2, []byte(candidate))
			out, report, _ := rewriteChecked(t, ix, message, ScanOptions{})
			left := 0
			leaf := out[len(out)-len(candidate):]
			for i := range leaf {
				if leaf[i] == candidate[i] {
					left++
				}
			}
			if left > 7 || report.Inventory+report.Redacted != 1 {
				t.Fatalf("registered=%v: %d of 20 characters are left (%+v)", registered, left, report)
			}
			if _, ok := shapeOf(leaf); !ok {
				t.Fatal("what was overwritten no longer parses as it did")
			}
		}
	}
	// A string that reads as one field holding the rest of it: its first two
	// bytes, a tag and a length, stay, and the placeholder follows them.
	wrapped := "2Is" + randomString(t, alnum, 37)
	ix := build(t, secret{ID: "k", Value: wrapped})
	text := wrapped + " is the key, in a string of its own"
	if fields, ok := shapeOf([]byte(text)); !ok || len(fields) != 1 || len(text) != 75 {
		t.Fatalf("the string does not parse as one field: %v", fields)
	}
	out, report, _ := rewriteChecked(t, ix, protoString(protoNumber(nil, 1, 3), 2, []byte(text)), ScanOptions{})
	if want := "2Iph:secret:k" + strings.Repeat("*", 38-len("ph:secret:k")) + " is the key, in a string of its own"; string(out[4:]) != want || report.Inventory != 1 {
		t.Fatalf("got %q, want %q (%+v)", out[4:], want, report)
	}

	// The same for a value that is only there encoded: a base64 run that
	// reads as several fields is overwritten around what reads as its tags,
	// and no longer decodes to the value.
	var hidden, run string
	for attempts := 0; ; attempts++ {
		if attempts > 2000000 {
			t.Fatal("no base64 run parsed as a message")
		}
		// 30 bytes make 40 characters and no padding, which would end the run
		// on a byte that is no whole field.
		hidden = randomString(t, alnum, 30)
		run = base64.StdEncoding.EncodeToString([]byte(hidden))
		if fields, ok := shapeOf([]byte(run)); ok && len(fields) > 1 {
			break
		}
	}
	ix = build(t, secret{ID: "webhook", Value: hidden})
	out, report, _ = rewriteChecked(t, ix, protoString(protoString(nil, 1, []byte("auth")), 2, []byte(run)), ScanOptions{})
	left := out[len(out)-len(run):]
	decoded, _ := base64.StdEncoding.DecodeString(string(left))
	same := 0
	for i := range left {
		if left[i] == run[i] {
			same++
		}
	}
	if report.Inventory == 0 || bytes.Contains(decoded, []byte(hidden[:12])) || bytes.Contains(decoded, []byte(hidden[18:])) || same > len(run)*2/3 {
		t.Fatalf("the run still holds the value: %d of %d characters are left (%+v)", same, len(run), report)
	}

	// A real message that happens to be all text keeps every field: a value in
	// one of its strings is overwritten there and nowhere else. The value
	// begins with a byte that is no tag, so the string is not such a message
	// itself.
	value := "s" + randomString(t, alnum, 39)
	ix = build(t, secret{ID: "k", Value: value})
	inner := protoString(protoString(nil, 4, []byte("a name of more than thirty-two bytes")), 6, []byte(value+" is the key, in a string of its own"))
	if firstNonText(inner) >= 0 {
		t.Fatalf("the message is not text: %q", inner)
	}
	message := protoString(protoNumber(nil, 1, 3), 2, inner)
	out, report, _ = rewriteChecked(t, ix, message, ScanOptions{})
	want := bytes.Replace(message, []byte(value), []byte("ph:secret:k"+strings.Repeat("*", 40-len("ph:secret:k"))), 1)
	if !bytes.Equal(out, want) || report.Inventory != 1 {
		t.Fatalf("got %q, want %q (%+v)", out, want, report)
	}
}

// A placeholder that is already there, padded, whole or cut short, is not
// matched again, and neither is what follows a keyword in it.
func TestBinaryPlaceholdersAreNeverMatchedAgain(t *testing.T) {
	value := randomString(t, alnum, 44)
	ix := build(t, secret{ID: "3f2a9c1e-7b64-4d0a-9e51-0c8d2f6a4b17", Value: value}, secret{ID: "stripe", Type: "sealed", Value: randomString(t, alnum, 32)})
	texts := []string{
		// As a model repeats them, and as an earlier pass left them.
		"the value is ph:secret:3f2a9c1e-7b64-4d0a-9e51-0c8d2f6a4b17******** as before",
		"token=ph:secret:3f2a9c1e-7b64-4d0a-9e51-0c8d2f6a4b17",
		"password: ph:sealed:stripe**************** then more",
		"ph:secret:3f2a9c1e-7b6 was cut inside its id, and ph:aws_access_key_id inside its type",
		"api_key=ph:keyword_secret:12************************ and secret-token:ph:secret_token:3*************",
		"two in a row ph:secret:3f2a9c1e-7b64ph:github_token:4*********************** end",
		"ph:phase_service_token:2" + strings.Repeat("*", 300),
		"Authorization: Bearer ph:jwt:9" + strings.Repeat("*", 120),
	}
	for _, text := range texts {
		message := protoString(protoNumber(nil, 1, 1), 2, []byte(text))
		out, report, _ := rewriteChecked(t, ix, message, ScanOptions{})
		if !bytes.Equal(out, message) || report.Found() {
			t.Errorf("%q was matched again: %q (%+v)", text, out[len(out)-len(text):], report)
		}
	}
	// Text that only holds "ph:" is read like any other: a name that ends in
	// ph before a colon does not hide the value after it.
	token := "ghp_" + randomString(t, alnum, 36)
	for text, want := range map[string]string{
		"postgres://joseph:" + value + "@db.internal/app":     value,
		"https://ralph:" + token + "@github.com/acme/app.git": token,
		"see graph:" + value:   value,
		"ph:" + value:          value,
		"ph:secretly " + value: value,
	} {
		out, report, _ := rewriteChecked(t, ix, protoString(nil, 2, []byte(text)), ScanOptions{})
		if bytes.Contains(out, []byte(want)) || !report.Found() {
			t.Errorf("%q: the value after ph: was left", strings.Replace(text, want, "<value>", 1))
		}
	}
}

// A value broken in two by a byte that could not belong to it is found in one
// call, both pieces, where a single look finds only the first.
func TestBinaryBrokenValueIsFinishedInOneCall(t *testing.T) {
	value := randomString(t, alnum, 72)
	ix := build(t, secret{ID: "k", Value: value})
	broken := value[:30] + "\"" + value[31:]
	text := "the key is " + broken + " here"
	once, _ := ix.Redact([]byte(text))
	if !bytes.Contains(once, []byte(value[36:60])) {
		t.Skip("a single look finds both pieces now")
	}
	out, report, written := rewriteChecked(t, ix, protoString(nil, 1, []byte(text)), ScanOptions{})
	if bytes.Contains(out, []byte(value[:12])) || bytes.Contains(out, []byte(value[36:60])) || len(written) != 2 || report.Inventory != 2 {
		t.Fatalf("a piece is left: %q (%+v)", out, report)
	}
}

// Rules limits a call as it limits the other scans; indexed values are found
// whatever it holds.
func TestBinaryRulesOption(t *testing.T) {
	value := randomString(t, alnum, 40)
	ix := build(t, secret{ID: "k", Value: value})
	phaseOnly, err := DefaultRules().Only("phase-user-token", "phase-service-token", "phase-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	token := "ghp_" + randomString(t, alnum, 36)
	phase := "pss_service:v2:" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32) + ":" + randomHex(t, 32)
	message := protoString(protoString(protoString(nil, 1, []byte("git token "+token)), 2, []byte("known "+value)), 3, []byte("phase "+phase))
	all, allReport, _ := rewriteChecked(t, ix, message, ScanOptions{})
	if bytes.Contains(all, []byte(token)) || bytes.Contains(all, []byte(value)) || bytes.Contains(all, []byte(phase)) || allReport.Redacted != 2 || allReport.Inventory != 1 {
		t.Fatalf("with every rule: %+v", allReport)
	}
	limited, report, _ := rewriteChecked(t, ix, message, ScanOptions{Rules: phaseOnly})
	if !bytes.Contains(limited, []byte(token)) || bytes.Contains(limited, []byte(value)) || bytes.Contains(limited, []byte(phase)) || report.Redacted != 1 || report.Inventory != 1 {
		t.Fatalf("with Phase's rules only: %+v", report)
	}
	// A base64 image in a string is skipped as it is in JSON.
	image := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("pixels"), 4<<10)))
	if _, report := ix.RewriteBinary(protoString(nil, 1, image), ScanOptions{}); report.SkippedBinary != 1 {
		t.Fatalf("an image was scanned: %+v", report)
	}
	if _, report := ix.RewriteBinary(protoString(nil, 1, image), ScanOptions{BinaryMinLength: -1}); report.SkippedBinary != 0 {
		t.Fatalf("a negative threshold skipped: %+v", report)
	}
}

// FuzzRewriteBinary holds the walk to its guarantees on whatever the fuzzer
// makes of real messages: it never panics, never changes a length or a field,
// and a second pass changes nothing.
func FuzzRewriteBinary(f *testing.F) {
	key, _ := NewKey()
	ix, _ := NewIndex(key, IndexOptions{})
	values := []plantedValue{{"a", "Zq8vLm2Rt5Xw9Kp3Hd7Nf4BcQ1"}, {"b", "sk_" + "live_51AbCdEfGh1234IjKlMnOp5678QrStUv"}, {"c", "postgres://app:Qw3Er5Ty7Ui9Op1As3Df5Gh@db/app"}}
	for _, value := range values {
		e, _ := IndexValue(key, "secret", value.id, value.value)
		_ = ix.Add(e)
	}
	maker := &messageMaker{rng: rand.New(rand.NewSource(7)), values: values}
	for i := 0; i < 24; i++ {
		f.Add(maker.message(3).data)
	}
	f.Add([]byte("token " + values[0].value + " ph:secret:a*************** é"))
	f.Add(protoString(nil, 1, maker.accident(9)))
	f.Fuzz(func(t *testing.T, data []byte) {
		rewriteChecked(t, ix, data, ScanOptions{})
	})
}

// binaryRequest is the corpus as a model request in protobuf: messages of a
// role and about 32 KB of text each, with a few secrets, as the JSON benchmark
// has them.
func binaryRequest(b *testing.B, size int, secrets []secret) []byte {
	text := corpus(b, size)
	var parts [][]byte
	for i := 0; i < len(text); i += 32 << 10 {
		parts = append(parts, text[i:min(i+(32<<10), len(text))])
	}
	for i := 0; i < 5 && i < len(parts) && len(secrets) > 0; i++ {
		at := i * len(parts) / 5
		parts[at] = append(bytes.Clone(parts[at]), "\nleaked "+secrets[i*7].Value...)
	}
	var request []byte
	request = protoString(request, 1, []byte("test-model"))
	for i, part := range parts {
		message := protoString(protoNumber(nil, 1, uint64(i)), 2, []byte("tool"))
		message = protoString(message, 3, protoString(protoString(nil, 1, []byte("Read")), 2, part))
		request = protoString(request, 2, message)
	}
	return request
}

func benchmarkBinary(b *testing.B, size int, withSecrets bool) {
	secrets := manySecrets(b, 300)
	ix := build(b, secrets...)
	planted := secrets
	if !withSecrets {
		planted = nil
	}
	request := binaryRequest(b, size, planted)
	b.SetBytes(int64(len(request)))
	b.ResetTimer()
	var report *Report
	for i := 0; i < b.N; i++ {
		_, report = ix.RewriteBinary(request, ScanOptions{})
	}
	b.StopTimer()
	if withSecrets && report.Inventory < 5 {
		b.Fatalf("expected at least 5 hits, got %d", report.Inventory)
	}
	b.ReportMetric(float64(report.Inventory), "hits")
}

func BenchmarkRewriteBinary1MB(b *testing.B)       { benchmarkBinary(b, 1<<20, true) }
func BenchmarkRewriteBinary10MB(b *testing.B)      { benchmarkBinary(b, 10<<20, true) }
func BenchmarkRewriteBinary10MBClean(b *testing.B) { benchmarkBinary(b, 10<<20, false) }
