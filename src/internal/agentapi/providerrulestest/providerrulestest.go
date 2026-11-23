// Package providerrulestest holds, for tests, the provider rules the Console's
// manifests send with each Connection (credentialEnvironment and secretGuard),
// in their wire form. They were extracted from the tables the CLI compiled in
// before the rules moved to the Console, and are what the Console's
// services/v1/<service>.json files carry.
package providerrulestest

import (
	"embed"
	"encoding/json"

	"github.com/phasehq/cli/internal/agentapi"
)

//go:embed *.json
var files embed.FS

// Raw returns the service's rules as a JSON object fragment of a Connection,
// or nil for a service that has none.
func Raw(serviceType string) []byte {
	data, err := files.ReadFile(serviceType + ".json")
	if err != nil {
		return nil
	}
	return data
}

// Apply decodes the service's rules into the Connection the way a session
// payload carries them, through the Connection's own JSON decoding. The data
// is embedded, so a decoding failure is a broken test file and panics.
func Apply(connection agentapi.Connection) agentapi.Connection {
	data := Raw(connection.ServiceType)
	if data == nil {
		return connection
	}
	if err := json.Unmarshal(data, &connection); err != nil {
		panic("decode " + connection.ServiceType + " provider rules: " + err.Error())
	}
	return connection
}

// CredentialEnvironment is the union of the services' credentialEnvironment.
func CredentialEnvironment(serviceTypes ...string) []string {
	var names []string
	for _, serviceType := range serviceTypes {
		names = append(names, Apply(agentapi.Connection{ServiceType: serviceType}).CredentialEnvironment...)
	}
	return names
}
