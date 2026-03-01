package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/spf13/cobra"
)

var secretsExportCmd = &cobra.Command{
	Use:   "export",
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

	// Resolve secret references and build ordered key-value slice
	var secretsList []util.KeyValue
	for _, secret := range allSecrets {
		if secret.Value == "" {
			continue
		}
		resolvedValue, err := sdk.ResolveAllSecrets(secret.Value, allSecrets, p, secret.Application, secret.Environment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			continue
		}
		secretsList = append(secretsList, util.KeyValue{Key: secret.Key, Value: resolvedValue})
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
