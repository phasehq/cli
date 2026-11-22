package aiproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// heldBody runs advance when it is first read, as if the client sent its body
// only then.
type heldBody struct {
	reader  io.Reader
	advance func()
	read    bool
}

func (b *heldBody) Read(p []byte) (int, error) {
	if !b.read {
		b.read = true
		b.advance()
	}
	return b.reader.Read(p)
}

func (b *heldBody) Close() error { return nil }

func TestTemporaryAllowIsCheckedWhenTheBodyHasArrived(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	policy := policyDocument("allow", []any{classRule("delete", "ask")},
		map[string]any{"id": "allow-delete", "class": "delete", "expiresAt": expiry.Format(time.RFC3339)})
	_, proxy, upstream := policyProxy(t, awsPolicyConnection(policy))
	now := expiry.Add(-time.Minute)
	proxy.clock = func() time.Time { return now }
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	body := "Action=TerminateInstances&InstanceId.1=i-0abc&Version=2016-11-15"

	if r := processThrough(proxy, signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", body, form)); r.failure != nil {
		t.Fatalf("the temporary allow did not apply before it expired: %+v", r.failure)
	}
	request := signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", body, form)
	request.Body = &heldBody{reader: strings.NewReader(body), advance: func() { now = expiry.Add(time.Minute) }}
	result := processThrough(proxy, request)
	if result.failure == nil || result.failure.code != codeAccessPolicyAsk || upstream.calls.Load() != 1 {
		t.Fatalf("a body that arrived after the allow expired was sent: %+v (upstream calls %d)", result.failure, upstream.calls.Load())
	}
}

func TestBodyTheChecksReadMustArriveInTime(t *testing.T) {
	previous := bodyInspectionTimeout
	bodyInspectionTimeout = 200 * time.Millisecond
	t.Cleanup(func() { bodyInspectionTimeout = previous })
	state, proxy, upstream := policyProxy(t, awsPolicyConnection(nil))
	events, err := newEventBuffer(state, time.Hour, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Stop()
	proxy.events = events
	server := httptest.NewServer(proxy)
	defer server.Close()

	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	body := "Action=DescribeInstances&Version=2016-11-15"
	request := signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", body,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
	setProxyCapability(request, "runtime-policy")
	held, holder := io.Pipe()
	defer holder.Close()
	request.Body = held
	go func() { _ = request.WriteProxy(connection) }()
	// Half of the body, then nothing.
	go func() { _, _ = holder.Write([]byte(body[:10])) }()

	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatalf("no answer to a request whose body stopped: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || upstream.calls.Load() != 0 {
		t.Fatalf("status %d, upstream calls %d", response.StatusCode, upstream.calls.Load())
	}
}
