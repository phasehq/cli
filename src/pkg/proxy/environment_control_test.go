package proxy

import "testing"

func TestRuntimeControlEnvironmentKey(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "NO_PROXY", "no_proxy", "ALL_PROXY", "PHASE_AI_ENABLED", "PHASE_AI_CA_BUNDLE", "SSL_CERT_FILE", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PGSSLROOTCERT", "JAVA_TOOL_OPTIONS"} {
		if !RuntimeControlEnvironmentKey(key) {
			t.Fatalf("%s must be a runtime control key", key)
		}
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "PGHOST", "PGPORT", "PGPASSWORD", "PGSSLMODE", "PATH"} {
		if RuntimeControlEnvironmentKey(key) {
			t.Fatalf("%s must stay exported without the proxy", key)
		}
	}
}
