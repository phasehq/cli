package proxy

import (
	"strings"
	"testing"
)

// However a host is spelled, it is one tenant. Another host, port, scheme
// or organisation is another.
func TestInventoryIdentityHasOneFormPerTenant(t *testing.T) {
	const organisation, account = "0b5e7c1a-1111-4222-8333-444455556666", "9f1c2d3e-aaaa-4bbb-8ccc-ddddeeeeffff"
	want := NewInventoryIdentity("https://console.phase.dev", organisation, InventoryLoginUser, account)
	if !want.Known() || want.Tenant != "https://console.phase.dev\norganisation\n"+organisation || want.Login != "https://console.phase.dev\nuser\n"+account {
		t.Fatalf("the canonical form: %q %q", want.Tenant, want.Login)
	}
	for _, host := range []string{
		"https://console.phase.dev:443/", "HTTPS://Console.Phase.dev", "https://console.phase.dev/", " https://console.phase.dev ",
		"https://console.phase.dev./", "https://CONSOLE.PHASE.DEV:443", "https://console.phase.dev/service/public", "https://console.phase.dev/service/public/v1/agents/",
		"https://console.phase.dev:0443", "https://console.phase.dev?x=1#y",
	} {
		if got := NewInventoryIdentity(host, " "+organisation+" ", InventoryLoginUser, account); got != want || !got.Is(want) {
			t.Errorf("%q split the tenant: %q", host, got.Tenant)
		}
	}
	seen := map[string]string{want.Tenant: "https://console.phase.dev"}
	for _, host := range []string{
		"https://console.phase.dev:8443", "http://console.phase.dev", "https://console.phase.dev.evil.test", "https://phase.dev",
		"https://console.phase.dev:444", "http://console.phase.dev:443", "https://[::1]:8000", "https://[::1]", "http://localhost:8000", "http://127.0.0.1:8000",
	} {
		got := NewInventoryIdentity(host, organisation, InventoryLoginUser, account)
		if !got.Known() {
			t.Errorf("%q names no tenant", host)
			continue
		}
		if first, merged := seen[got.Tenant]; merged {
			t.Errorf("%q and %q are one tenant: %q", host, first, got.Tenant)
		}
		seen[got.Tenant] = host
		if got.SameTenant(want) || got.Is(want) {
			t.Errorf("%q is the same tenant as console.phase.dev", host)
		}
	}
	// The same host and another organisation, and the same organisation id
	// on another host, are other tenants; another login is the same tenant.
	other := NewInventoryIdentity("https://console.phase.dev", "another-organisation", InventoryLoginUser, account)
	agent := NewInventoryIdentity("https://console.phase.dev", organisation, InventoryLoginAgent, account)
	if other.SameTenant(want) || !agent.SameTenant(want) || agent.Is(want) || agent.Login == want.Login {
		t.Fatalf("%q %q %q", other.Tenant, agent.Tenant, agent.Login)
	}
}

// What cannot be told is no identity at all: it is never half of one, and
// nothing that is not the canonical form is taken for one.
func TestInventoryIdentityUnknownIsEmpty(t *testing.T) {
	for name, got := range map[string]InventoryIdentity{
		"no scheme":          NewInventoryIdentity("console.phase.dev", "org", InventoryLoginUser, "id"),
		"another scheme":     NewInventoryIdentity("ftp://console.phase.dev", "org", InventoryLoginUser, "id"),
		"no host":            NewInventoryIdentity("https://", "org", InventoryLoginUser, "id"),
		"an empty host":      NewInventoryIdentity("", "org", InventoryLoginUser, "id"),
		"a bad port":         NewInventoryIdentity("https://console.phase.dev:99999", "org", InventoryLoginUser, "id"),
		"no organisation":    NewInventoryIdentity("https://console.phase.dev", "", InventoryLoginUser, "id"),
		"a blank one":        NewInventoryIdentity("https://console.phase.dev", "  ", InventoryLoginUser, "id"),
		"no id":              NewInventoryIdentity("https://console.phase.dev", "org", InventoryLoginUser, ""),
		"an unknown kind":    NewInventoryIdentity("https://console.phase.dev", "org", "account", "id"),
		"an id with a break": NewInventoryIdentity("https://console.phase.dev", "org\norganisation\nother", InventoryLoginUser, "id"),
		"a long id":          NewInventoryIdentity("https://console.phase.dev", strings.Repeat("a", 129), InventoryLoginUser, "id"),
	} {
		if got != (InventoryIdentity{}) || got.Known() {
			t.Errorf("%s made an identity: %q %q", name, got.Tenant, got.Login)
		}
	}
	good := NewInventoryIdentity("https://console.phase.dev", "org", InventoryLoginAgent, "agent-1")
	for name, got := range map[string]InventoryIdentity{
		"the zero value":             {},
		"a tenant alone":             {Tenant: good.Tenant},
		"a login alone":              {Login: good.Login},
		"a login of another host":    {Tenant: good.Tenant, Login: "https://other.test\nagent\nagent-1"},
		"a host not in its one form": {Tenant: "HTTPS://console.phase.dev\norganisation\norg", Login: "HTTPS://console.phase.dev\nagent\nagent-1"},
		"a default port written":     {Tenant: "https://console.phase.dev:443\norganisation\norg", Login: "https://console.phase.dev:443\nagent\nagent-1"},
		"a fourth part":              {Tenant: good.Tenant + "\nmore", Login: good.Login},
		"a tenant that is a login":   {Tenant: good.Login, Login: good.Login},
		"a kind of no login":         {Tenant: good.Tenant, Login: "https://console.phase.dev\norganisation\norg"},
	} {
		if got.Known() || got.Is(got) || got.SameTenant(good) || good.SameTenant(got) {
			t.Errorf("%s is taken for an identity", name)
		}
	}
	if !good.Known() || !good.Is(good) {
		t.Fatal("the canonical form is not known")
	}
}
