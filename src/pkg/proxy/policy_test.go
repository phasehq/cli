package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

var policyTestNow = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

func testPolicy(t *testing.T, document string) *agentapi.AccessPolicy {
	t.Helper()
	var policy agentapi.AccessPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Unsupported() {
		t.Fatalf("test policy was not readable: %s", document)
	}
	return &policy
}

func policyRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestAccessPolicyEvaluation(t *testing.T) {
	future := policyTestNow.Add(time.Hour).Format(time.RFC3339)
	past := policyTestNow.Add(-time.Second).Format(time.RFC3339)
	atNow := policyTestNow.Format(time.RFC3339)
	tests := []struct {
		name      string
		policy    string
		method    string
		path      string
		class     string
		effect    string
		ruleIndex int
		allowedBy string
	}{
		// The default, with and without rules that do not match.
		{name: "empty policy allows", policy: `{}`, method: "DELETE", path: "/x", class: "delete", effect: "allow", ruleIndex: -1},
		{name: "default allow", policy: `{"version":1,"default":"allow","rules":[]}`, method: "GET", path: "/x", class: "read", effect: "allow", ruleIndex: -1},
		{name: "default left out is allow", policy: `{"version":1,"rules":[{"class":"delete","effect":"block"}]}`, method: "GET", path: "/x", class: "read", effect: "allow", ruleIndex: -1},
		{name: "default ask", policy: `{"version":1,"default":"ask","rules":[]}`, method: "GET", path: "/x", class: "read", effect: "ask", ruleIndex: -1},
		{name: "default block", policy: `{"version":1,"default":"block","rules":[]}`, method: "GET", path: "/x", class: "read", effect: "block", ruleIndex: -1},
		{name: "no matching rule falls to the default", policy: `{"version":1,"default":"ask","rules":[{"class":"delete","effect":"block"}]}`, method: "POST", path: "/x", class: "create", effect: "ask", ruleIndex: -1},

		// One class rule of each effect.
		{name: "class allow under default block", policy: `{"version":1,"default":"block","rules":[{"class":"read","effect":"allow"}]}`, method: "GET", path: "/x", class: "read", effect: "allow", ruleIndex: 0},
		{name: "class ask", policy: `{"version":1,"default":"allow","rules":[{"class":"create","effect":"ask"}]}`, method: "POST", path: "/x", class: "create", effect: "ask", ruleIndex: 0},
		{name: "class block", policy: `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "block", ruleIndex: 0},

		// Every pair of effects: the strongest wins, whatever the order.
		{name: "allow then ask", policy: `{"version":1,"rules":[{"class":"update","effect":"allow"},{"match":{"methods":["PUT"]},"effect":"ask"}]}`, method: "PUT", path: "/x", class: "update", effect: "ask", ruleIndex: 1},
		{name: "ask then allow", policy: `{"version":1,"rules":[{"match":{"methods":["PUT"]},"effect":"ask"},{"class":"update","effect":"allow"}]}`, method: "PUT", path: "/x", class: "update", effect: "ask", ruleIndex: 0},
		{name: "allow then block", policy: `{"version":1,"rules":[{"class":"update","effect":"allow"},{"match":{"path":"/x"},"effect":"block"}]}`, method: "PUT", path: "/x", class: "update", effect: "block", ruleIndex: 1},
		{name: "block then allow", policy: `{"version":1,"rules":[{"match":{"path":"/x"},"effect":"block"},{"class":"update","effect":"allow"}]}`, method: "PUT", path: "/x", class: "update", effect: "block", ruleIndex: 0},
		{name: "ask then block", policy: `{"version":1,"rules":[{"class":"update","effect":"ask"},{"match":{"methods":["PUT"],"path":"/x"},"effect":"block"}]}`, method: "PUT", path: "/x", class: "update", effect: "block", ruleIndex: 1},
		{name: "block then ask", policy: `{"version":1,"rules":[{"match":{"methods":["PUT"],"path":"/x"},"effect":"block"},{"class":"update","effect":"ask"}]}`, method: "PUT", path: "/x", class: "update", effect: "block", ruleIndex: 0},
		{name: "allow ask and block together", policy: `{"version":1,"default":"ask","rules":[{"class":"update","effect":"allow"},{"class":"update","effect":"ask"},{"class":"update","effect":"block"}]}`, method: "PUT", path: "/x", class: "update", effect: "block", ruleIndex: 2},
		{name: "a matching allow beats a stricter default", policy: `{"version":1,"default":"block","rules":[{"match":{"methods":["GET"],"path":"/v1/*"},"effect":"allow"}]}`, method: "GET", path: "/v1/items", class: "read", effect: "allow", ruleIndex: 0},
		{name: "the first of two equal effects is reported", policy: `{"version":1,"rules":[{"class":"delete","effect":"block"},{"match":{"methods":["DELETE"]},"effect":"block"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "block", ruleIndex: 0},

		// Match rules: methods only, path only, both.
		{name: "methods only matches", policy: `{"version":1,"rules":[{"match":{"methods":["POST","PUT"]},"effect":"block"}]}`, method: "PUT", path: "/anything", class: "update", effect: "block", ruleIndex: 0},
		{name: "methods only misses", policy: `{"version":1,"rules":[{"match":{"methods":["POST","PUT"]},"effect":"block"}]}`, method: "PATCH", path: "/anything", class: "update", effect: "allow", ruleIndex: -1},
		{name: "method case is the request's problem", policy: `{"version":1,"rules":[{"match":{"methods":["DELETE"]},"effect":"block"}]}`, method: "delete", path: "/x", class: "delete", effect: "block", ruleIndex: 0},
		{name: "path only matches any method", policy: `{"version":1,"rules":[{"match":{"path":"/v1/charges/*"},"effect":"block"}]}`, method: "GET", path: "/v1/charges/ch_1", class: "read", effect: "block", ruleIndex: 0},
		{name: "path only misses", policy: `{"version":1,"rules":[{"match":{"path":"/v1/charges/*"},"effect":"block"}]}`, method: "GET", path: "/v1/customers/cu_1", class: "read", effect: "allow", ruleIndex: -1},
		{name: "path glob spans segments like a host rule", policy: `{"version":1,"rules":[{"match":{"path":"/repos/*/delete"},"effect":"block"}]}`, method: "POST", path: "/repos/acme/x/delete", class: "create", effect: "block", ruleIndex: 0},
		{name: "an escaped path is matched decoded", policy: `{"version":1,"rules":[{"match":{"path":"/v1/charges/*"},"effect":"block"}]}`, method: "GET", path: "/v1/charges%2Fch_1", class: "read", effect: "block", ruleIndex: 0},
		{name: "the query is not part of the path", policy: `{"version":1,"rules":[{"match":{"path":"/v1/charges"},"effect":"block"}]}`, method: "GET", path: "/v1/charges?limit=3", class: "read", effect: "block", ruleIndex: 0},
		{name: "both match", policy: `{"version":1,"rules":[{"match":{"methods":["POST"],"path":"/v1/charges/*"},"effect":"block"}]}`, method: "POST", path: "/v1/charges/ch_1", class: "create", effect: "block", ruleIndex: 0},
		{name: "both: method misses", policy: `{"version":1,"rules":[{"match":{"methods":["POST"],"path":"/v1/charges/*"},"effect":"block"}]}`, method: "GET", path: "/v1/charges/ch_1", class: "read", effect: "allow", ruleIndex: -1},
		{name: "both: path misses", policy: `{"version":1,"rules":[{"match":{"methods":["POST"],"path":"/v1/charges/*"},"effect":"block"}]}`, method: "POST", path: "/v1/refunds/re_1", class: "create", effect: "allow", ruleIndex: -1},
		{name: "a class rule ignores other classes", policy: `{"version":1,"rules":[{"class":"update","effect":"block"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "allow", ruleIndex: -1},

		// A path the proxy cannot bring into canonical form matches every ask
		// or block path rule and no allow path rule.
		{name: "odd path spelling still hits a block", policy: `{"version":1,"rules":[{"match":{"path":"/v1/charges/*"},"effect":"block"}]}`, method: "GET", path: "/v1/x/../charges/ch_1", class: "read", effect: "block", ruleIndex: 0},
		{name: "odd path spelling still hits an ask", policy: `{"version":1,"rules":[{"match":{"methods":["GET"],"path":"/v1/charges/*"},"effect":"ask"}]}`, method: "GET", path: "/v1//charges/ch_1", class: "read", effect: "ask", ruleIndex: 0},
		{name: "odd path spelling never earns an allow", policy: `{"version":1,"default":"block","rules":[{"match":{"path":"/v1/public/*"},"effect":"allow"}]}`, method: "GET", path: "/v1/public/../private", class: "read", effect: "block", ruleIndex: -1},

		// Temporary allows: only against an ask, only until they expire.
		{name: "class temporary allow turns an ask into an allow", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "allow", ruleIndex: 0, allowedBy: "allow-1"},
		{name: "match temporary allow turns an ask into an allow", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-2","match":{"methods":["DELETE"],"path":"/repos/acme/x"},"expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/repos/acme/x", class: "delete", effect: "allow", ruleIndex: 0, allowedBy: "allow-2"},
		{name: "temporary allow covers a default ask", policy: `{"version":1,"default":"ask","rules":[],"temporaryAllows":[{"id":"allow-3","class":"read","expiresAt":"` + future + `"}]}`, method: "GET", path: "/x", class: "read", effect: "allow", ruleIndex: -1, allowedBy: "allow-3"},
		{name: "temporary allow for another path does not apply", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-2","match":{"methods":["DELETE"],"path":"/repos/acme/x"},"expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/repos/acme/y", class: "delete", effect: "ask", ruleIndex: 0},
		{name: "temporary allow for another class does not apply", policy: `{"version":1,"default":"ask","rules":[],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + future + `"}]}`, method: "PUT", path: "/x", class: "update", effect: "ask", ruleIndex: -1},
		{name: "temporary allow never changes a block", policy: `{"version":1,"rules":[{"class":"delete","effect":"block"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "block", ruleIndex: 0},
		{name: "temporary allow never changes a default block", policy: `{"version":1,"default":"block","rules":[],"temporaryAllows":[{"id":"allow-1","match":{"methods":["DELETE"],"path":"/x"},"expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "block", ruleIndex: -1},
		{name: "temporary allow does not lift a block that also asks", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"},{"match":{"path":"/x"},"effect":"block"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "block", ruleIndex: 1},
		{name: "expired temporary allow is ignored", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + past + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "ask", ruleIndex: 0},
		{name: "a temporary allow ends at its expiry, not after it", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"` + atNow + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "ask", ruleIndex: 0},
		{name: "a later live allow still applies after an expired one", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"old","class":"delete","expiresAt":"` + past + `"},{"id":"live","class":"delete","expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "allow", ruleIndex: 0, allowedBy: "live"},
		{name: "a path temporary allow never covers an odd path spelling", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-2","match":{"path":"/repos/acme/*"},"expiresAt":"` + future + `"}]}`, method: "DELETE", path: "/repos/acme/../other", class: "delete", effect: "ask", ruleIndex: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := policyRequest(t, test.method, "https://api.example.test"+test.path)
			decision := EvaluateAccessPolicy(testPolicy(t, test.policy), []ClassifiedCall{{Class: test.class}}, request, policyTestNow)
			if decision.Effect != test.effect || decision.RuleIndex != test.ruleIndex || decision.Class != test.class ||
				decision.TemporaryAllowID != test.allowedBy || (decision.Rule == nil) != (test.ruleIndex < 0) {
				t.Fatalf("decision = %+v, want effect %s by rule %d (temporary allow %q)", decision, test.effect, test.ruleIndex, test.allowedBy)
			}
		})
	}
}

// A temporary allow is read against the clock on every call, so it stops
// applying the moment it expires although the policy has not been refreshed.
func TestTemporaryAllowExpiresAtRequestTime(t *testing.T) {
	policy := testPolicy(t, `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"2026-11-14T10:30:00Z"}]}`)
	request := policyRequest(t, http.MethodDelete, "https://api.example.test/x")
	calls := []ClassifiedCall{{Class: agentapi.ClassDelete}}
	for moment, effect := range map[string]string{
		"2026-11-14T10:00:00Z": agentapi.PolicyAllow,
		"2026-11-14T10:29:59Z": agentapi.PolicyAllow,
		"2026-11-14T10:30:00Z": agentapi.PolicyAsk,
		"2026-11-14T11:00:00Z": agentapi.PolicyAsk,
	} {
		now, _ := time.Parse(time.RFC3339, moment)
		if got := EvaluateAccessPolicy(policy, calls, request, now).Effect; got != effect {
			t.Errorf("at %s the call was %s, want %s", moment, got, effect)
		}
	}
}

// A request that could belong to several classes is judged by the most
// restricted one, and the answer names that one.
func TestAccessPolicyTakesTheStrongestEffectAcrossCandidateClasses(t *testing.T) {
	policy := testPolicy(t, `{"version":1,"rules":[{"class":"delete","effect":"block"},{"class":"update","effect":"ask"}]}`)
	request := policyRequest(t, http.MethodPost, "https://api.example.test/v1/items/1")
	decision := EvaluateAccessPolicy(policy, []ClassifiedCall{
		{Class: agentapi.ClassCreate},
		{Class: agentapi.ClassUpdate, Method: http.MethodPut},
		{Class: agentapi.ClassDelete, Method: http.MethodDelete},
	}, request, policyTestNow)
	if decision.Effect != agentapi.PolicyBlock || decision.Class != agentapi.ClassDelete || decision.Method != http.MethodDelete {
		t.Fatalf("decision = %+v", decision)
	}
	if allowed := EvaluateAccessPolicy(nil, nil, request, policyTestNow); allowed.Effect != agentapi.PolicyAllow {
		t.Fatalf("no policy decided %+v", allowed)
	}
}

// Every HTTP call is classed by its method alone, whatever the Connection:
// GET, HEAD and OPTIONS read, POST create, PUT and PATCH update, DELETE
// delete, any other method update. A path or a body never changes the class.
func TestEveryHTTPCallIsClassedByItsMethodAlone(t *testing.T) {
	connections := map[string]agentapi.Connection{
		"custom":   {ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http"},
		"packaged": withProviderRules(t, agentapi.Connection{ServiceType: "github", Protocol: "http"}),
		"aws":      withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}}),
	}
	for method, class := range map[string]string{
		"GET": "read", "HEAD": "read", "OPTIONS": "read", "POST": "create", "PUT": "update", "PATCH": "update",
		"DELETE": "delete", "PROPFIND": "update", "TRACE": "update", "get": "read",
	} {
		for name, connection := range connections {
			for _, path := range []string{"/v1/items", "/graphql", "/v1/admin/users", "/"} {
				calls, err := ClassifyCall(policyRequest(t, method, "https://api.example.test"+path), connection)
				if err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: class}}) {
					t.Errorf("%s %s %s = %+v err=%v, want %s", name, method, path, calls, err, class)
				}
			}
		}
	}
}

func TestPolicyAppliesToEveryHTTPConnectionWithARestrictingPolicy(t *testing.T) {
	restricting := testPolicy(t, `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"ask"}]}`)
	onlyAllows := testPolicy(t, `{"version":1,"default":"allow","rules":[{"class":"read","effect":"allow"}],"managed":[{"id":"secret_guard","locked":true,"rules":[{"class":"credential_minting","effect":"block"}]}]}`)
	tests := map[string]struct {
		connection agentapi.Connection
		applies    bool
	}{
		"custom http with a restricting policy": {agentapi.Connection{ServiceType: "http", Protocol: "http", Policy: restricting}, true},
		"aws with a restricting policy":         {agentapi.Connection{ServiceType: "aws", Protocol: "http", Policy: restricting}, true},
		"no policy":                             {agentapi.Connection{ServiceType: "http", Protocol: "http"}, false},
		"a policy that only allows":             {agentapi.Connection{ServiceType: "aws", Protocol: "http", Policy: onlyAllows}, false},
		"an empty policy":                       {agentapi.Connection{ServiceType: "http", Protocol: "http", Policy: testPolicy(t, `{}`)}, false},
		"another packaged HTTP service":         {agentapi.Connection{ServiceType: "github", Protocol: "http", Policy: restricting}, true},
		"postgres":                              {agentapi.Connection{ServiceType: "postgres", Protocol: "postgres", Policy: restricting}, false},
	}
	for name, test := range tests {
		if got := PolicyApplies(test.connection); got != test.applies {
			t.Errorf("%s: applies = %t", name, got)
		}
	}
	// A policy that stops calls cannot be evaluated for PostgreSQL, so such a
	// Connection is unavailable rather than served without it.
	postgres := agentapi.Connection{ServiceType: "postgres", Protocol: "postgres", Policy: restricting}
	if postgres.AccessPolicyFailure() != agentapi.AccessPolicyUnsupported {
		t.Fatal("a PostgreSQL Connection with a restricting policy is served without it")
	}
	if allowed := (agentapi.Connection{ServiceType: "postgres", Protocol: "postgres", Policy: onlyAllows}); allowed.AccessPolicyFailure() != "" {
		t.Fatal("a PostgreSQL Connection with a policy that only allows is unavailable")
	}
	// Any other HTTP service is classified by method.
	packaged := agentapi.Connection{ServiceType: "github", Protocol: "http", Policy: restricting}
	if calls, err := ClassifyCall(policyRequest(t, http.MethodDelete, "https://api.github.com/repos/acme/x"), packaged); err != nil ||
		len(calls) != 1 || calls[0].Class != agentapi.ClassDelete {
		t.Fatalf("packaged HTTP call = %+v err=%v", calls, err)
	}
}

func TestExactPathGlobMatchesOnlyTheRequestPath(t *testing.T) {
	tests := map[string]struct {
		path  string
		glob  string
		exact bool
	}{
		"plain":                    {"/repos/acme/x", "/repos/acme/x", true},
		"escaped slash is decoded": {"/repos/acme%2Fx", "/repos/acme/x", true},
		"glob characters":          {"/files/a*b%3Fc[1]", "/files/a[*]b[?]c[[]1]", true},
		"trailing slash":           {"/repos/acme/", "/repos/acme/", true},
		"root":                     {"/", "/", true},
		"dot segments":             {"/repos/acme/../other", "", false},
		"doubled slash":            {"/repos//acme", "", false},
		"control character":        {"/repos/acme%0Ax", "", false},
		"too long":                 {"/" + strings.Repeat("a", 1024), "", false},
	}
	for name, test := range tests {
		request := policyRequest(t, http.MethodDelete, "https://api.example.test"+test.path)
		glob, exact := ExactPathGlob(request)
		if exact != test.exact || glob != test.glob {
			t.Errorf("%s: glob = %q exact=%t, want %q exact=%t", name, glob, exact, test.glob, test.exact)
			continue
		}
		if !exact {
			continue
		}
		canonical, _ := policyPath(request)
		if !globMatch(glob, canonical) || globMatch(glob, canonical+"x") || globMatch(glob, strings.Replace(canonical, "a", "b", 1)) && strings.Contains(canonical, "a") {
			t.Errorf("%s: glob %q does not match exactly %q", name, glob, canonical)
		}
	}
}

func TestClassifyCallFailsClosedOnARequestItCannotRead(t *testing.T) {
	custom := agentapi.Connection{ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http"}
	huge, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", strings.NewReader("_method=DELETE"))
	huge.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	huge.ContentLength = maximumMintingInspectionBytes + 1
	if _, err := ClassifyCall(huge, custom); !errors.Is(err, ErrCallUninspectable) {
		t.Fatalf("an oversized form body was classified: %v", err)
	}
	if _, err := ClassifyCall(nil, custom); !errors.Is(err, ErrCallUninspectable) {
		t.Fatalf("a missing request was classified: %v", err)
	}
	// AWS never reads _method from a body, so an AWS upload is never buffered.
	aws := withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	upload, _ := http.NewRequest(http.MethodPost, "https://bucket.s3.us-east-1.amazonaws.com/key?uploadId=1", errorReader{err: errors.New("the body was read")})
	upload.ContentLength = 5 << 30
	if calls, err := ClassifyCall(upload, aws); err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: agentapi.ClassCreate}}) {
		t.Fatalf("an AWS upload = %+v err=%v", calls, err)
	}
}
