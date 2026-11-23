package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

const (
	customDecoy = "sk-decoy-0123456789abcdef"
	customLive  = "sk-live-proxy-only-value"
)

// customConnection builds a custom HTTP Connection as the Console compiles it:
// an injections list, one decoy per secret field and identifier fields.
func customConnection(t *testing.T, injections ...map[string]any) agentapi.Connection {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"serviceType": "http", "protocol": "http",
		"injections":     injections,
		"identifiers":    map[string]string{"username": "alice"},
		"decoyMaterial":  map[string]string{"token": customDecoy, "password": "decoy-password"},
		"agentEnv":       map[string]string{},
		"secretMaterial": map[string]string{"token": customLive, "password": "live-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func headerInjection(whenAbsent string) map[string]any {
	injection := map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"},
	}
	if whenAbsent != "" {
		injection["whenAbsent"] = whenAbsent
	}
	return injection
}

func queryInjection(whenAbsent string) map[string]any {
	injection := map[string]any{
		"action": "set_param", "name": "api_key", "valueFormat": "{value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"},
	}
	if whenAbsent != "" {
		injection["whenAbsent"] = whenAbsent
	}
	return injection
}

func basicInjection(whenAbsent string) map[string]any {
	injection := map[string]any{
		"action": "basic_auth", "name": "Authorization",
		"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}},
	}
	if whenAbsent != "" {
		injection["whenAbsent"] = whenAbsent
	}
	return injection
}

func basicValue(userpass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
}

func injectionCode(err error) InjectionErrorCode {
	var typed *InjectionError
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

// The rows are the contract's table: what the request carries at the
// injection point, crossed with whenAbsent.
func TestCustomInjectionTableForHeaderQueryAndBasic(t *testing.T) {
	type row struct {
		name       string
		whenAbsent string
		carry      func(*http.Request)
		wantCode   InjectionErrorCode
	}
	points := []struct {
		name      string
		injection func(string) map[string]any
		decoy     func(*http.Request)
		other     func(*http.Request)
		twice     func(*http.Request)
		live      func(*http.Request) bool
		untouched func(*http.Request) string
	}{
		{
			name: "header", injection: headerInjection,
			decoy: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+customDecoy) },
			other: func(r *http.Request) { r.Header.Set("Authorization", "Bearer something-else") },
			twice: func(r *http.Request) {
				r.Header.Add("Authorization", "Bearer "+customDecoy)
				r.Header.Add("Authorization", "Bearer "+customDecoy)
			},
			live:      func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+customLive },
			untouched: func(r *http.Request) string { return strings.Join(r.Header.Values("Authorization"), "|") },
		},
		{
			name: "query", injection: queryInjection,
			decoy: func(r *http.Request) { r.URL.RawQuery = "page=2&api_key=" + customDecoy },
			other: func(r *http.Request) { r.URL.RawQuery = "page=2&api_key=something-else" },
			twice: func(r *http.Request) { r.URL.RawQuery = "api_key=" + customDecoy + "&api_key=" + customDecoy },
			live: func(r *http.Request) bool {
				return r.URL.Query().Get("api_key") == customLive && len(r.URL.Query()["api_key"]) == 1
			},
			untouched: func(r *http.Request) string { return r.URL.RawQuery },
		},
		{
			name: "basic", injection: basicInjection,
			decoy: func(r *http.Request) { r.Header.Set("Authorization", basicValue("alice:decoy-password")) },
			other: func(r *http.Request) { r.Header.Set("Authorization", basicValue("alice:something-else")) },
			twice: func(r *http.Request) {
				r.Header.Add("Authorization", basicValue("alice:decoy-password"))
				r.Header.Add("Authorization", basicValue("alice:decoy-password"))
			},
			live:      func(r *http.Request) bool { return r.Header.Get("Authorization") == basicValue("alice:live-password") },
			untouched: func(r *http.Request) string { return strings.Join(r.Header.Values("Authorization"), "|") },
		},
	}
	for _, point := range points {
		rows := []row{
			{name: "decoy, attach", whenAbsent: "attach", carry: point.decoy},
			{name: "decoy, block", whenAbsent: "block", carry: point.decoy},
			{name: "decoy, unset", carry: point.decoy},
			{name: "nothing, attach", whenAbsent: "attach", carry: func(*http.Request) {}},
			{name: "nothing, block", whenAbsent: "block", carry: func(*http.Request) {}, wantCode: InjectionSwapMiss},
			{name: "nothing, unset means block", carry: func(*http.Request) {}, wantCode: InjectionSwapMiss},
			{name: "anything else, attach", whenAbsent: "attach", carry: point.other, wantCode: InjectionSwapMiss},
			{name: "anything else, block", whenAbsent: "block", carry: point.other, wantCode: InjectionSwapMiss},
			{name: "more than one value, attach", whenAbsent: "attach", carry: point.twice, wantCode: InjectionSwapMiss},
			{name: "more than one value, block", whenAbsent: "block", carry: point.twice, wantCode: InjectionSwapMiss},
		}
		for _, test := range rows {
			t.Run(point.name+"/"+test.name, func(t *testing.T) {
				connection := customConnection(t, point.injection(test.whenAbsent))
				request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
				test.carry(request)
				before := point.untouched(request)
				result, err := ApplyHTTPInjection(context.Background(), request, connection)
				if got := injectionCode(err); got != test.wantCode {
					t.Fatalf("error code = %q (%v), want %q", got, err, test.wantCode)
				}
				if test.wantCode != "" {
					if after := point.untouched(request); after != before {
						t.Fatalf("blocked request was rewritten: %q -> %q", before, after)
					}
					return
				}
				if !point.live(request) {
					t.Fatalf("request does not carry the live value: header=%q query=%q", request.Header.Values("Authorization"), request.URL.RawQuery)
				}
				if result.Action == "" {
					t.Fatal("result did not name the applied action")
				}
			})
		}
	}
}

func TestBasicAuthAcceptsOnlyTheExactDecoyForm(t *testing.T) {
	connection := customConnection(t, basicInjection("attach"))
	for name, presented := range map[string]string{
		"wrong username":       basicValue("bob:decoy-password"),
		"live password":        basicValue("alice:live-password"),
		"username only":        basicValue("alice"),
		"another scheme":       "Bearer " + base64.StdEncoding.EncodeToString([]byte("alice:decoy-password")),
		"not base64":           "Basic !!!not-base64!!!",
		"empty":                "",
		"trailing credentials": basicValue("alice:decoy-password") + " extra",
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
			request.Header.Set("Authorization", presented)
			_, err := ApplyHTTPInjection(context.Background(), request, connection)
			if injectionCode(err) != InjectionSwapMiss || request.Header.Get("Authorization") != presented {
				t.Fatalf("err=%v header=%q", err, request.Header.Get("Authorization"))
			}
		})
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
	request.Header.Set("Authorization", "basic "+base64.StdEncoding.EncodeToString([]byte("alice:decoy-password")))
	if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil ||
		request.Header.Get("Authorization") != basicValue("alice:live-password") {
		t.Fatalf("the scheme name is case-insensitive: err=%v header=%q", err, request.Header.Get("Authorization"))
	}
}

func TestBasicAuthRefusesUnusableMaterial(t *testing.T) {
	colon := customConnection(t, basicInjection("attach"))
	colon.Identifiers = map[string]string{"username": "ali:ce"}
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
	if _, err := ApplyHTTPInjection(context.Background(), request, colon); injectionCode(err) != InjectionUnsafeValue {
		t.Fatalf("a username with a colon must be refused: %v", err)
	}
	noIdentifier := customConnection(t, basicInjection("attach"))
	noIdentifier.Identifiers = map[string]string{}
	if _, err := ApplyHTTPInjection(context.Background(), request, noIdentifier); injectionCode(err) != InjectionMissingMaterial {
		t.Fatalf("a missing username must be refused: %v", err)
	}
	noRoles := customConnection(t, map[string]any{
		"action": "basic_auth", "whenAbsent": "attach",
		"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username"}},
	})
	if _, err := ApplyHTTPInjection(context.Background(), request, noRoles); injectionCode(err) != InjectionInvalidTemplate {
		t.Fatalf("a basic injection without a password role must be refused: %v", err)
	}
	if len(request.Header.Values("Authorization")) != 0 {
		t.Fatal("a refused request was given credentials")
	}
	// The header name defaults to Authorization when the injection omits it.
	unnamed := basicInjection("attach")
	delete(unnamed, "name")
	if _, err := ApplyHTTPInjection(context.Background(), request, customConnection(t, unnamed)); err != nil ||
		request.Header.Get("Authorization") != basicValue("alice:live-password") {
		t.Fatalf("err=%v header=%q", err, request.Header.Get("Authorization"))
	}
}

func TestInjectionListIsAppliedOnlyWhenEveryInjectionPasses(t *testing.T) {
	second := map[string]any{
		"action": "set_param", "name": "api_key", "valueFormat": "{value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "block",
	}
	third := map[string]any{
		"action": "set_header", "name": "X-Client", "valueFormat": "{value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
	}
	connection := customConnection(t, basicInjection("attach"), second, third)

	// The first and third injections would pass; the second finds nothing and
	// blocks, so nothing at all may be written.
	blocked, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items?page=2", nil)
	blocked.Header.Set("Authorization", basicValue("alice:decoy-password"))
	_, err := ApplyHTTPInjection(context.Background(), blocked, connection)
	if injectionCode(err) != InjectionSwapMiss {
		t.Fatalf("err=%v", err)
	}
	if blocked.Header.Get("Authorization") != basicValue("alice:decoy-password") || blocked.Header.Get("X-Client") != "" ||
		blocked.URL.RawQuery != "page=2" {
		t.Fatalf("request was half-rewritten: headers=%v query=%q", blocked.Header, blocked.URL.RawQuery)
	}

	// A failure in the last injection also leaves the earlier ones unapplied.
	lastFails, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items?api_key="+customDecoy, nil)
	lastFails.Header.Set("X-Client", "not-the-decoy")
	if _, err := ApplyHTTPInjection(context.Background(), lastFails, connection); injectionCode(err) != InjectionSwapMiss {
		t.Fatalf("err=%v", err)
	}
	if len(lastFails.Header.Values("Authorization")) != 0 || lastFails.URL.RawQuery != "api_key="+customDecoy {
		t.Fatalf("request was half-rewritten: headers=%v query=%q", lastFails.Header, lastFails.URL.RawQuery)
	}

	// Swap, swap and attach in one request.
	allowed, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items?page=2&api_key="+customDecoy, nil)
	allowed.Header.Set("Authorization", basicValue("alice:decoy-password"))
	result, err := ApplyHTTPInjection(context.Background(), allowed, connection)
	if err != nil || result.Action != "basic_auth" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if allowed.Header.Get("Authorization") != basicValue("alice:live-password") || allowed.Header.Get("X-Client") != customLive ||
		allowed.URL.Query().Get("api_key") != customLive || allowed.URL.Query().Get("page") != "2" {
		t.Fatalf("headers=%v query=%q", allowed.Header, allowed.URL.RawQuery)
	}
}

func TestInjectionListRefusesAmbiguousOrUnknownTemplates(t *testing.T) {
	request := func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
		return r
	}
	tests := map[string][]map[string]any{
		"two injections write one header":        {headerInjection("attach"), basicInjection("attach")},
		"header names differ only in case":       {headerInjection("attach"), {"action": "set_header", "name": "authorization", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"two injections write one parameter":     {queryInjection("attach"), queryInjection("attach")},
		"unknown whenAbsent":                     {headerInjection("always")},
		"unknown action":                         {{"action": "set_cookie", "name": "session", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"request signing inside a list":          {{"action": "aws_sigv4", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "token", "secretAccessKey": "password"}}}},
		"attach on a path injection":             {{"action": "set_path", "valueFormat": "/{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"unsafe header name":                     {{"action": "set_header", "name": "Host", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"proxy authorization header":             {{"action": "basic_auth", "name": "Proxy-Authorization", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"}},
		"parameter name with a separator":        {{"action": "set_param", "name": "a&b", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"value format without a placeholder":     {{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"credential source missing on an attach": {{"action": "set_header", "name": "Authorization", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "none"}, "whenAbsent": "attach"}},
		"remove header cannot attach":            {{"action": "remove_header", "name": "X-Debug", "valueFrom": map[string]any{"source": "none"}, "whenAbsent": "attach"}},
		"attach to a framing header":             {{"action": "set_header", "name": "Transfer-Encoding", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"attach to a hop-by-hop header":          {{"action": "set_header", "name": "upgrade", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach"}},
		"attach Basic auth to a trailer":         {{"action": "basic_auth", "name": "Trailer", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"}},
	}
	for name, injections := range tests {
		t.Run(name, func(t *testing.T) {
			r := request()
			_, err := ApplyHTTPInjection(context.Background(), r, customConnection(t, injections...))
			if injectionCode(err) != InjectionInvalidTemplate {
				t.Fatalf("err=%v, want an invalid template", err)
			}
			if len(r.Header) != 0 || r.URL.RawQuery != "" {
				t.Fatalf("refused request was rewritten: %v %q", r.Header, r.URL.RawQuery)
			}
		})
	}
}

func TestAttachKeepsTheExistingValueSafetyChecks(t *testing.T) {
	attach := func(t *testing.T, live string, injection map[string]any, rawQuery string) (*http.Request, error) {
		t.Helper()
		connection := customConnection(t, injection)
		payload, _ := json.Marshal(map[string]string{"token": live})
		if err := json.Unmarshal(payload, &connection.SecretMaterial); err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
		request.URL.RawQuery = rawQuery
		_, err := ApplyHTTPInjection(context.Background(), request, connection)
		return request, err
	}
	if r, err := attach(t, "line\r\nbreak", headerInjection("attach"), ""); injectionCode(err) != InjectionUnsafeValue || len(r.Header) != 0 {
		t.Fatalf("a value with a line break was attached: %v", err)
	}
	if r, err := attach(t, "nul\x00byte", queryInjection("attach"), ""); injectionCode(err) != InjectionUnsafeValue || r.URL.RawQuery != "" {
		t.Fatalf("a value with a NUL was attached: %v", err)
	}
	if r, err := attach(t, strings.Repeat("a", maximumInjectionCredentialBytes+1), headerInjection("attach"), ""); injectionCode(err) != InjectionUnsafeValue || len(r.Header) != 0 {
		t.Fatalf("a value over the size cap was attached: %v", err)
	}
	if r, err := attach(t, "", headerInjection("attach"), ""); injectionCode(err) != InjectionMissingMaterial || len(r.Header) != 0 {
		t.Fatalf("a Connection without a live value attached something: %v", err)
	}
	// A query the proxy cannot parse may hide a value for the parameter.
	if r, err := attach(t, customLive, queryInjection("attach"), "api_key=%zz"); injectionCode(err) != InjectionSwapMiss || r.URL.RawQuery != "api_key=%zz" {
		t.Fatalf("an unparseable query was treated as carrying nothing: %v %q", err, r.URL.RawQuery)
	}
	// An empty value is something, not nothing.
	if r, err := attach(t, customLive, queryInjection("attach"), "api_key="); injectionCode(err) != InjectionSwapMiss || r.URL.RawQuery != "api_key=" {
		t.Fatalf("an empty parameter was treated as carrying nothing: %v", err)
	}
	connection := customConnection(t, headerInjection("attach"))
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
	request.Header["Authorization"] = []string{""}
	if _, err := ApplyHTTPInjection(context.Background(), request, connection); injectionCode(err) != InjectionSwapMiss {
		t.Fatalf("an empty header was treated as carrying nothing: %v", err)
	}
}

// A request from a client still holding an earlier decoy generation is matched
// against that generation and rewritten to the live credential.
func TestPresentedGenerationIsMatchedButLiveMaterialIsWritten(t *testing.T) {
	live := customConnection(t, basicInjection("attach"), queryInjection("attach"))
	live.Identifiers = map[string]string{"username": "bob"}
	earlier := live
	earlier.Identifiers = map[string]string{"username": "alice"}
	earlier.DecoyMaterial = map[string]string{"token": "sk-decoy-earlier", "password": "decoy-password-earlier"}

	swapped, _ := http.NewRequest(http.MethodGet, "https://api.example.test/?api_key=sk-decoy-earlier", nil)
	swapped.Header.Set("Authorization", basicValue("alice:decoy-password-earlier"))
	if _, err := ApplyHTTPInjection(context.Background(), swapped, live); injectionCode(err) != InjectionSwapMiss {
		t.Fatalf("the current generation must not match an earlier decoy: %v", err)
	}
	if _, err := ApplyHTTPInjectionPresenting(context.Background(), swapped, live, earlier); err != nil {
		t.Fatal(err)
	}
	if swapped.Header.Get("Authorization") != basicValue("bob:live-password") || swapped.URL.Query().Get("api_key") != customLive {
		t.Fatalf("headers=%v query=%q", swapped.Header, swapped.URL.RawQuery)
	}

	// One injection presents the earlier decoy and the other carries nothing:
	// the attached value is built from the live identifier.
	mixed, _ := http.NewRequest(http.MethodGet, "https://api.example.test/?api_key=sk-decoy-earlier", nil)
	if _, err := ApplyHTTPInjectionPresenting(context.Background(), mixed, live, earlier); err != nil {
		t.Fatal(err)
	}
	if mixed.Header.Get("Authorization") != basicValue("bob:live-password") || mixed.URL.Query().Get("api_key") != customLive {
		t.Fatalf("headers=%v query=%q", mixed.Header, mixed.URL.RawQuery)
	}
}

// Packaged services send one injection and no whenAbsent. They keep requiring
// the decoy: nothing is ever attached for them.
func TestPackagedSingleInjectionStillRequiresTheDecoy(t *testing.T) {
	for name, injection := range map[string]map[string]any{
		"header": {"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
		"query":  {"action": "set_param", "name": "access_token", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
	} {
		t.Run(name, func(t *testing.T) {
			connection := injectionConnection(t, injection)
			if len(connection.Injections) != 0 || connection.Injection.WhenAbsent != "" {
				t.Fatalf("packaged payload decoded as a list: %+v", connection.Injections)
			}
			absent, _ := http.NewRequest(http.MethodGet, "https://example.test/?page=1", nil)
			if _, err := ApplyHTTPInjection(context.Background(), absent, connection); injectionCode(err) != InjectionSwapMiss {
				t.Fatalf("err=%v, want a swap miss", err)
			}
			if len(absent.Header) != 0 || absent.URL.RawQuery != "page=1" {
				t.Fatalf("a packaged Connection attached a credential: %v %q", absent.Header, absent.URL.RawQuery)
			}
			presented, _ := http.NewRequest(http.MethodGet, "https://example.test/?access_token=decoy-value", nil)
			presented.Header.Set("Authorization", "Bearer decoy-value")
			result, err := ApplyHTTPInjection(context.Background(), presented, connection)
			if err != nil || result.Action != injection["action"] {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if name == "header" && presented.Header.Get("Authorization") != "Bearer live-value" {
				t.Fatalf("header=%q", presented.Header.Get("Authorization"))
			}
			if name == "query" && presented.URL.Query().Get("access_token") != "live-value" {
				t.Fatalf("query=%q", presented.URL.RawQuery)
			}
		})
	}
	// A packaged signing Connection is still handed to the signer, and an
	// unsigned request is still refused by it rather than by the list engine.
	signing := awsSessionTokenConnection(t, map[string]string{"access_key_id": "AKIALIVE", "secret_access_key": "live-secret"})
	unsigned, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", nil)
	if _, err := ApplyHTTPInjection(context.Background(), unsigned, signing); injectionCode(err) != InjectionFinalizerFailed {
		t.Fatalf("err=%v, want the signer's failure", err)
	}
	signed := signedOptionalTokenRequest(t)
	if result, err := ApplyHTTPInjection(context.Background(), signed, signing); err != nil || result.Action != "aws_sigv4" ||
		!strings.Contains(signed.Header.Get("Authorization"), "Credential=AKIALIVE/") {
		t.Fatalf("result=%+v err=%v authorization=%q", result, err, signed.Header.Get("Authorization"))
	}
}

// An HTTP Connection's value never travels in the clear unless the
// Connection allows it: on plain HTTP nothing is swapped and nothing is
// attached. The rule covers packaged HTTP services as well as custom ones;
// AWS request signing keeps its own handling.
func TestCustomConnectionNeverInjectsOverPlainHTTPUnlessAllowed(t *testing.T) {
	carry := map[string]func(*http.Request){
		"swap":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+customDecoy) },
		"attach": func(*http.Request) {},
	}
	for name, present := range carry {
		t.Run(name, func(t *testing.T) {
			connection := customConnection(t, headerInjection("attach"), queryInjection("attach"))
			for _, target := range []string{"http://api.example.test/v1/items?page=2", "HTTP://api.example.test/v1/items?page=2", "//api.example.test/v1/items?page=2"} {
				request, _ := http.NewRequest(http.MethodGet, target, nil)
				present(request)
				before := request.Header.Get("Authorization")
				_, err := ApplyHTTPInjection(context.Background(), request, connection)
				if injectionCode(err) != InjectionPlainHTTP || request.Header.Get("Authorization") != before || request.URL.RawQuery != "page=2" {
					t.Fatalf("%s: err=%v headers=%v query=%q", target, err, request.Header, request.URL.RawQuery)
				}
				if _, err := ApplyHTTPInjectionPresenting(context.Background(), request, connection, connection); injectionCode(err) != InjectionPlainHTTP {
					t.Fatalf("%s: an earlier generation got through: %v", target, err)
				}
			}
			for _, target := range []string{"https://api.example.test/v1/items?page=2", "HTTPS://api.example.test/v1/items?page=2"} {
				request, _ := http.NewRequest(http.MethodGet, target, nil)
				present(request)
				if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil ||
					request.Header.Get("Authorization") != "Bearer "+customLive || request.URL.Query().Get("api_key") != customLive {
					t.Fatalf("%s: err=%v headers=%v", target, err, request.Header)
				}
			}
			connection.AllowPlainHTTP = true
			request, _ := http.NewRequest(http.MethodGet, "http://api.example.test/v1/items?page=2", nil)
			present(request)
			if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil ||
				request.Header.Get("Authorization") != "Bearer "+customLive || request.URL.Query().Get("api_key") != customLive {
				t.Fatalf("an allowed plain-HTTP request was refused: err=%v headers=%v", err, request.Header)
			}
		})
	}
	if message := (&InjectionError{Code: InjectionPlainHTTP}).Error(); !strings.Contains(message, "HTTPS") {
		t.Fatalf("the refusal does not say what to do: %q", message)
	}

	packaged := injectionConnection(t, map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "access_token"},
	})
	request, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.Header.Set("Authorization", "Bearer decoy-value")
	if _, err := ApplyHTTPInjection(context.Background(), request, packaged); injectionCode(err) != InjectionPlainHTTP || request.Header.Get("Authorization") != "Bearer decoy-value" {
		t.Fatalf("a packaged service was sent over plain HTTP: err=%v header=%q", err, request.Header.Get("Authorization"))
	}
	request, _ = http.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.Header.Set("Authorization", "Bearer decoy-value")
	if _, err := ApplyHTTPInjection(context.Background(), request, packaged); err != nil || request.Header.Get("Authorization") != "Bearer live-value" {
		t.Fatalf("a packaged service over HTTPS: err=%v header=%q", err, request.Header.Get("Authorization"))
	}
}
