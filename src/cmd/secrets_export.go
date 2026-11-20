package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/spf13/cobra"
)

var secretsExportCmd = &cobra.Command{
	Use:   "export [keys...]",
	Short: "🥡 Export secrets in a specific format",
	RunE:  runSecretsExport,
}

func init() {
	secretsExportCmd.Flags().String("format", "dotenv", "Export format (dotenv, json, csv, yaml, xml, toml, hcl, ini, java_properties, kv)")
	secretsExportCmd.Flags().String("env", "", "Environment name")
	secretsExportCmd.Flags().String("app", "", "Application name")
	secretsExportCmd.Flags().String("app-id", "", "Application ID")
	secretsExportCmd.Flags().String("tags", "", "Filter by tags")
	secretsExportCmd.Flags().String("path", "/", "Path filter (default '/'. Pass empty string to export from all paths)")
	secretsExportCmd.Flags().String("generate-leases", "true", "Generate leases for dynamic secrets")
	secretsExportCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	secretsCmd.AddCommand(secretsExportCmd)
}

func runSecretsExport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	tags, _ := cmd.Flags().GetString("tags")
	path, _ := cmd.Flags().GetString("path")
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	// Uppercase requested keys for filtering
	var filterKeys []string
	for _, k := range args {
		filterKeys = append(filterKeys, strings.ToUpper(k))
	}

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewBackend()
	if err != nil {
		return err
	}
	if err := refuseAgentDynamicSecretFlags(cmd, p); err != nil {
		return err
	}

	opts := sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Tag:     tags,
		Path:    path,
		Dynamic: true,
		Lease:   util.ParseBoolFlag(generateLeases),
	}
	if cmd.Flags().Changed("lease-ttl") {
		opts.LeaseTTL = &leaseTTL
	}

	allSecrets, err := p.Get(opts)
	if err != nil {
		return err
	}

	// An Agent login exports real values, to be written to a file or piped to
	// a program. Other logins are masked by each secret's own type.
	exportValue := func(secret sdk.SecretResult) string {
		if !ai.AgentLogin() && ai.ShouldRedact(secret.Type) {
			return "[REDACTED]"
		}
		return secret.Value
	}

	// The last secret of each key is what a key filter exports.
	lastByKey := make(map[string]sdk.SecretResult)
	for _, secret := range allSecrets {
		lastByKey[secret.Key] = secret
	}

	var secretsList []util.KeyValue
	// What leaves with a real value is registered with leak protection first.
	var handedOut []sdk.SecretResult
	exportSecret := func(key string, secret sdk.SecretResult) {
		value := exportValue(secret)
		if value == secret.Value {
			handedOut = append(handedOut, secret)
		}
		secretsList = append(secretsList, util.KeyValue{Key: key, Value: value})
	}
	if len(filterKeys) > 0 {
		// Check for missing keys
		var missingKeys []string
		for _, key := range filterKeys {
			if _, ok := lastByKey[key]; !ok {
				missingKeys = append(missingKeys, key)
			}
		}
		if len(missingKeys) > 0 {
			missing := strings.Join(missingKeys, ", ")
			switch {
			case tags != "" && path != "":
				return fmt.Errorf("🥡 failed to export — the following secret(s) were not found at path %s with tag filter %s: %s. Adjust --tags, or pass --path \"\" to export from all paths", path, tags, missing)
			case tags != "":
				return fmt.Errorf("🥡 failed to export — the following secret(s) did not match tag filter %s: %s. Adjust or drop --tags", tags, missing)
			case path != "":
				return fmt.Errorf("🥡 failed to export — the following secret(s) were not found at path %s: %s. Secrets under other paths are not searched — pass --path \"\" to export from all paths", path, missing)
			default:
				return fmt.Errorf("🥡 failed to export — the following secret(s) do not exist: %s", missing)
			}
		}
		// Export only the requested keys (in the order they were specified)
		for _, key := range filterKeys {
			exportSecret(key, lastByKey[key])
		}
	} else {
		for _, secret := range allSecrets {
			exportSecret(secret.Key, secret)
		}
	}
	if err := protectSecrets(cmd.Context(), p, handedOut); err != nil {
		return err
	}

	// An export that produces nothing is otherwise silent; say why on stderr so
	// it can't be mistaken for a broken app or environment. stderr keeps the
	// exported document on stdout intact for piping.
	if len(secretsList) == 0 {
		fmt.Fprint(os.Stderr, emptyResultHint(path, tags, "export", false))
	}

	switch format {
	case "json":
		util.ExportJSON(secretsList)
	case "csv":
		util.ExportCSV(secretsList)
	case "yaml":
		util.ExportYAML(secretsList)
	case "xml":
		util.ExportXML(secretsList)
	case "toml":
		util.ExportTOML(secretsList)
	case "hcl":
		util.ExportHCL(secretsList)
	case "ini":
		util.ExportINI(secretsList)
	case "java_properties":
		util.ExportJavaProperties(secretsList)
	case "kv":
		util.ExportKV(secretsList)
	case "dotenv":
		util.ExportDotenv(secretsList)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s, using dotenv\n", format)
		util.ExportDotenv(secretsList)
	}

	return nil
}
