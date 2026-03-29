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

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
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

	// Build maps for key filtering and AI redaction
	allSecretsMap := make(map[string]string)
	allSecretsKeySet := make(map[string]bool)
	typeMap := make(map[string]string)
	for _, secret := range allSecrets {
		allSecretsMap[secret.Key] = secret.Value
		allSecretsKeySet[secret.Key] = true
		typeMap[secret.Key] = secret.Type
	}

	var secretsList []util.KeyValue
	if len(filterKeys) > 0 {
		// Check for missing keys
		var missingKeys []string
		for _, key := range filterKeys {
			if !allSecretsKeySet[key] {
				missingKeys = append(missingKeys, key)
			}
		}
		if len(missingKeys) > 0 {
			return fmt.Errorf("🥡 failed to export — the following secret(s) do not exist: %s", strings.Join(missingKeys, ", "))
		}
		// Export only the requested keys (in the order they were specified)
		for _, key := range filterKeys {
			value := allSecretsMap[key]
			if ai.ShouldRedact(typeMap[key]) {
				value = "[REDACTED]"
			}
			secretsList = append(secretsList, util.KeyValue{Key: key, Value: value})
		}
	} else {
		for _, secret := range allSecrets {
			value := secret.Value
			if ai.ShouldRedact(typeMap[secret.Key]) {
				value = "[REDACTED]"
			}
			secretsList = append(secretsList, util.KeyValue{Key: secret.Key, Value: value})
		}
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
