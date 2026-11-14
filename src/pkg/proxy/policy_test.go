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
		{name: "a class rule ignores other classes", policy: `{"version":1,"rules":[{"class":"admin","effect":"block"}]}`, method: "DELETE", path: "/x", class: "delete", effect: "allow", ruleIndex: -1},

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
	request := policyRequest(t, http.MethodPost, "https://ec2.eu-central-1.amazonaws.com/")
	decision := EvaluateAccessPolicy(policy, []ClassifiedCall{
		{Class: agentapi.ClassRead, Operation: "ec2:DescribeInstances"},
		{Class: agentapi.ClassUpdate, Operation: "ec2:StopInstances"},
		{Class: agentapi.ClassDelete, Operation: "ec2:TerminateInstances"},
	}, request, policyTestNow)
	if decision.Effect != agentapi.PolicyBlock || decision.Class != agentapi.ClassDelete || decision.Operation != "ec2:TerminateInstances" {
		t.Fatalf("decision = %+v", decision)
	}
	if allowed := EvaluateAccessPolicy(nil, nil, request, policyTestNow); allowed.Effect != agentapi.PolicyAllow {
		t.Fatalf("no policy decided %+v", allowed)
	}
}

func TestCustomHTTPCallsAreClassifiedByOverridesThenMethod(t *testing.T) {
	overrides := `[
		{"match":{"methods":["POST"],"path":"/graphql"},"class":"read"},
		{"match":{"methods":["POST"],"path":"/v1/search/*"},"class":"read"},
		{"match":{"path":"/v1/admin/*"},"class":"admin"},
		{"match":{"methods":["PUT"]},"class":"create"},
		{"match":{"methods":["PUT"],"path":"/v1/never-reached"},"class":"delete"}
	]`
	var classes agentapi.OperationClasses
	if err := json.Unmarshal([]byte(overrides), &classes); err != nil || classes.Unsupported() || len(classes.Entries) != 5 {
		t.Fatalf("overrides = %+v err=%v", classes, err)
	}
	with := agentapi.Connection{ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http", OperationClasses: classes}
	without := agentapi.Connection{ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http"}
	tests := []struct {
		method, path string
		overridden   []string
		byMethod     string
	}{
		{"GET", "/v1/items", []string{"read"}, "read"},
		{"HEAD", "/v1/items", []string{"read"}, "read"},
		{"OPTIONS", "/v1/items", []string{"read"}, "read"},
		{"POST", "/v1/items", []string{"create"}, "create"},
		{"PATCH", "/v1/items/1", []string{"update"}, "update"},
		{"DELETE", "/v1/items/1", []string{"delete"}, "delete"},
		{"PROPFIND", "/v1/items", []string{"update"}, "update"},
		{"TRACE", "/v1/items", []string{"update"}, "update"},
		// Overrides, first match wins.
		{"POST", "/graphql", []string{"read"}, "create"},
		{"POST", "/v1/search/issues", []string{"read"}, "create"},
		{"GET", "/graphql", []string{"read"}, "read"},
		{"GET", "/v1/admin/users", []string{"admin"}, "read"},
		{"DELETE", "/v1/admin/users/7", []string{"admin"}, "delete"},
		{"PUT", "/v1/items/1", []string{"create"}, "update"},
		{"PUT", "/v1/never-reached", []string{"create"}, "update"},
		{"PUT", "/v1/admin/users/7", []string{"admin"}, "update"},
		// A path that cannot be compared keeps every class it might have.
		{"POST", "/v1/x/../search/issues", []string{"read", "admin", "create"}, "create"},
		{"GET", "/v1//admin/users", []string{"admin", "read"}, "read"},
		{"PUT", "/v1/./admin/users/7", []string{"admin", "create"}, "update"},
	}
	for _, test := range tests {
		request := policyRequest(t, test.method, "https://api.example.test"+test.path)
		classified, err := ClassifyCall(request, with)
		if err != nil {
			t.Fatalf("%s %s: %v", test.method, test.path, err)
		}
		got := make([]string, 0, len(classified))
		for _, call := range classified {
			if call.Operation != "" {
				t.Fatalf("%s %s: a custom HTTP call named an operation %q", test.method, test.path, call.Operation)
			}
			got = append(got, call.Class)
		}
		if !reflect.DeepEqual(got, test.overridden) {
			t.Errorf("%s %s with overrides = %v, want %v", test.method, test.path, got, test.overridden)
		}
		plain, err := ClassifyCall(request, without)
		if err != nil || len(plain) != 1 || plain[0].Class != test.byMethod {
			t.Errorf("%s %s by method = %+v err=%v, want %s", test.method, test.path, plain, err, test.byMethod)
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

func TestClassifyCallFailsClosedOnAnAWSRequestItCannotRead(t *testing.T) {
	aws := agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}}
	huge, _ := http.NewRequest(http.MethodPost, "https://ec2.eu-central-1.amazonaws.com/", strings.NewReader("Action=TerminateInstances"))
	huge.Header.Set("Content-Type", "text/plain")
	huge.ContentLength = maximumMintingInspectionBytes + 1
	if _, err := ClassifyCall(huge, aws); !errors.Is(err, ErrCallUninspectable) {
		t.Fatalf("an oversized query-protocol body was classified: %v", err)
	}
	repeated := signedQueryRequest(t, "dynamodb.eu-central-1.amazonaws.com", "{}")
	repeated.Header.Set("Content-Type", "application/x-amz-json-1.0")
	repeated.Header["X-Amz-Target"] = []string{"DynamoDB_20120810.GetItem", "DynamoDB_20120810.DeleteTable"}
	if _, err := ClassifyCall(repeated, aws); !errors.Is(err, ErrCallUninspectable) {
		t.Fatalf("a repeated X-Amz-Target was classified: %v", err)
	}
	if _, err := ClassifyCall(nil, aws); !errors.Is(err, ErrCallUninspectable) {
		t.Fatalf("a missing request was classified: %v", err)
	}
}
