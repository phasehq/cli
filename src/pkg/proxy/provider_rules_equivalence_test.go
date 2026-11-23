package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/agentapi/providerrulestest"
)

// The secret guard takes its rules from the Connection.
// testdata/provider_rules_equivalence.json holds requests (those the tests of
// the guard and the proxy sent, and a generated grid over every rule) with the
// answers the compiled tables gave before the rules moved into the session
// payload (gzip, as it is large). This test replays them through Connections
// decoded from testdata/provider_rules, as a session payload would carry them,
// and expects the same answers.
//
// The corpus was recorded once, by the last build that still had the compiled
// tables, so it cannot be regenerated. A deliberate rule change means editing
// the recorded answers it touches, or dropping them for tests of the new rule.

const equivalenceCorpusPath = "testdata/provider_rules_equivalence.json.gz"

type equivalenceRequest struct {
	ServiceType   string              `json:"serviceType"`
	Action        string              `json:"action,omitempty"`
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Host          string              `json:"host,omitempty"`
	Header        map[string][]string `json:"header,omitempty"`
	BodyKind      string              `json:"bodyKind"`
	Body          string              `json:"body,omitempty"`
	BodyError     bool                `json:"bodyError,omitempty"`
	ContentLength int64               `json:"contentLength"`
	Guard         *equivalenceGuard   `json:"guard,omitempty"`
}

type equivalenceGuard struct {
	Operation string `json:"operation,omitempty"`
	Error     string `json:"error,omitempty"`
	BodyAfter string `json:"bodyAfter,omitempty"`
}

type equivalenceCorpus struct {
	Requests []equivalenceRequest `json:"requests"`
}

// The corpus recorded this text for a body the guard stopped reading.
var errBodyNotCaptured = errors.New("body beyond what the classifier read")
var errRecordedBody = errors.New("recorded body read error")

type failAfterReader struct{ err error }

func (r failAfterReader) Read([]byte) (int, error) { return 0, r.err }

// build recreates the request with exactly the body the original call read:
// what it read, then EOF, the original read error, or (for a body it stopped
// reading) an error that would change the answer if more were read now.
func (r equivalenceRequest) build(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(r.Method, r.URL, nil)
	if err != nil {
		t.Fatalf("rebuild %s %s: %v", r.Method, r.URL, err)
	}
	req.Header = http.Header{}
	for name, values := range r.Header {
		req.Header[name] = append([]string(nil), values...)
	}
	req.Host = r.Host
	req.ContentLength = r.ContentLength
	data := []byte(r.Body)
	switch r.BodyKind {
	case "nil":
		req.Body = nil
	case "nobody":
		req.Body = http.NoBody
	case "data":
		var tail io.Reader = bytes.NewReader(nil)
		if r.BodyError {
			tail = failAfterReader{errRecordedBody}
		}
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), tail))
	case "partial":
		var tail io.Reader = failAfterReader{errBodyNotCaptured}
		if r.BodyError {
			tail = failAfterReader{errRecordedBody}
		}
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), tail))
	default:
		t.Fatalf("unknown body kind %q", r.BodyKind)
	}
	return req
}

func remainingBody(req *http.Request) string {
	if req.Body == nil || req.Body == http.NoBody {
		return ""
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return string(data) + "<error: " + err.Error() + ">"
	}
	return string(data)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runGuard(t *testing.T, input equivalenceRequest, connection agentapi.Connection) *equivalenceGuard {
	req := input.build(t)
	blocked, err := CredentialMintingBlocked(req, connection)
	result := &equivalenceGuard{Error: errorText(err), BodyAfter: remainingBody(req)}
	if blocked != nil {
		result.Operation = blocked.Operation
	}
	return result
}

func readEquivalenceCorpus(t *testing.T) equivalenceCorpus {
	t.Helper()
	file, err := os.Open(filepath.FromSlash(equivalenceCorpusPath))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var corpus equivalenceCorpus
	if err := json.NewDecoder(reader).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Requests) == 0 {
		t.Fatal("equivalence corpus is empty")
	}
	return corpus
}

func describeRequest(input equivalenceRequest) string {
	return input.ServiceType + " " + input.Method + " " + input.URL + " " + strings.ReplaceAll(input.Body, "\n", " ")
}

func equivalenceConnection(serviceType, action string) agentapi.Connection {
	protocol := "http"
	if serviceType == "postgres" {
		protocol = "postgres"
	}
	return providerrulestest.Apply(agentapi.Connection{ServiceType: serviceType, Protocol: protocol, Injection: agentapi.Injection{Action: action}})
}

func sameAnswer(t *testing.T, want, got any) bool {
	t.Helper()
	left, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(left, right)
}

func TestSecretGuardFromThePayloadAnswersAsTheCompiledTablesDid(t *testing.T) {
	corpus := readEquivalenceCorpus(t)
	for _, input := range corpus.Requests {
		connection := equivalenceConnection(input.ServiceType, input.Action)
		if got := runGuard(t, input, connection); !sameAnswer(t, input.Guard, got) {
			t.Errorf("guard %s: got %+v, recorded %+v", describeRequest(input), got, input.Guard)
		}
	}
	if len(corpus.Requests) < 10000 {
		t.Fatalf("only %d guard answers were compared", len(corpus.Requests))
	}
}
