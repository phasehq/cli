package proxy

import (
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

// The kinds of login an inventory tells apart: a session's principal types.
const (
	InventoryLoginUser           = agentapi.IdentityUser
	InventoryLoginServiceAccount = agentapi.IdentityServiceAccount
	InventoryLoginAgent          = agentapi.IdentityAgent

	inventoryOrganisation = "organisation"
	// maxInventoryConsole bounds a Console's address in an identity, which a
	// command sends with every registration.
	maxInventoryConsole = 512
)

// InventoryIdentity says whose values an inventory holds. A tenant is a
// Console (the whole address it is served at, path included) and an
// organisation; a login is a kind and its account or Agent id.
type InventoryIdentity struct {
	// Tenant is "<console>\norganisation\n<organisation id>".
	Tenant string
	// Login is "<console>\n<kind>\n<id>": the Agent's id, a service account's,
	// or for a user the organisation member's, as a session's principal has it.
	Login string
}

// inventoryID is what an id of the Console may be made of.
var inventoryID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// NewInventoryIdentity is the one canonical form of an identity: the proxy
// and every registering client build theirs here. What cannot be told is empty.
func NewInventoryIdentity(host, organisationID, kind, id string) InventoryIdentity {
	console := inventoryConsole(host)
	organisationID, id = strings.TrimSpace(organisationID), strings.TrimSpace(id)
	if console == "" || !inventoryID.MatchString(organisationID) || !inventoryLoginKind(kind) || !inventoryID.MatchString(id) {
		return InventoryIdentity{}
	}
	return InventoryIdentity{
		Tenant: console + "\n" + inventoryOrganisation + "\n" + organisationID,
		Login:  console + "\n" + kind + "\n" + id,
	}
}

func inventoryLoginKind(kind string) bool {
	return kind == InventoryLoginUser || kind == InventoryLoginServiceAccount || kind == InventoryLoginAgent
}

// inventoryConsole is a Console as a tenant names it: the address it is
// served at, in one form. Scheme and host are lower case, with no default port
// or trailing dot. The path is the one the Console is served under, as the
// client that opens a session reads a host (agentapi.DeploymentPath), cleaned
// and with no trailing slash: two Consoles of one origin are two tenants. A
// query is dropped. "" if unknown.
func inventoryConsole(host string) string {
	parsed, err := url.Parse(strings.TrimSpace(host))
	if err != nil || parsed.Opaque != "" {
		return ""
	}
	origin := inventoryOrigin(parsed)
	if origin == "" {
		return ""
	}
	served := agentapi.DeploymentPath(parsed.Path)
	if served != "" {
		served = strings.TrimSuffix(path.Clean(served), "/")
	}
	// A path that still ends as the API's does is read two ways: no tenant.
	if agentapi.DeploymentPath(served) != served {
		return ""
	}
	console := origin + (&url.URL{Path: served}).EscapedPath()
	if len(console) > maxInventoryConsole {
		return ""
	}
	return console
}

// inventoryOrigin is scheme, host and port: lower case, with no default port
// or trailing dot. "" if unknown.
func inventoryOrigin(parsed *url.URL) string {
	scheme := strings.ToLower(parsed.Scheme)
	name := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if (scheme != "https" && scheme != "http") || name == "" || strings.ContainsAny(name, "\n\r\t ") {
		return ""
	}
	if raw := parsed.Port(); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
		if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
			return scheme + "://" + net.JoinHostPort(name, strconv.Itoa(port))
		}
	}
	if strings.Contains(name, ":") {
		name = "[" + name + "]"
	}
	return scheme + "://" + name
}

// Known reports an identity that names a tenant and a login in the canonical
// form. Anything else, the zero value included, belongs to nobody.
func (i InventoryIdentity) Known() bool {
	tenant, login := strings.Split(i.Tenant, "\n"), strings.Split(i.Login, "\n")
	if len(tenant) != 3 || len(login) != 3 || tenant[0] != login[0] || tenant[1] != inventoryOrganisation {
		return false
	}
	return inventoryConsole(tenant[0]) == tenant[0] && inventoryID.MatchString(tenant[2]) &&
		inventoryLoginKind(login[1]) && inventoryID.MatchString(login[2])
}

// SameTenant reports two known identities of one Console and organisation.
func (i InventoryIdentity) SameTenant(other InventoryIdentity) bool {
	return i.Known() && other.Known() && i.Tenant == other.Tenant
}

// Is reports two known identities that are the same login of the same tenant.
func (i InventoryIdentity) Is(other InventoryIdentity) bool {
	return i.SameTenant(other) && i.Login == other.Login
}
