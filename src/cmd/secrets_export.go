package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"

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
	secretsExportCmd.Flags().String("path", "", "Path filter")
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

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	opts := phase.GetOptions{
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

	// Resolve secret references and build key-value map
	secretsDict := map[string]string{}
	for _, secret := range allSecrets {
		if secret.Value == "" {
			continue
		}
		resolvedValue := phase.ResolveAllSecrets(secret.Value, allSecrets, p, secret.Application, secret.Environment)
		secretsDict[secret.Key] = resolvedValue
	}

	switch format {
	case "json":
		util.ExportJSON(secretsDict)
	case "csv":
		util.ExportCSV(secretsDict)
	case "yaml":
		util.ExportYAML(secretsDict)
	case "xml":
		util.ExportXML(secretsDict)
	case "toml":
		util.ExportTOML(secretsDict)
	case "hcl":
		util.ExportHCL(secretsDict)
	case "ini":
		util.ExportINI(secretsDict)
	case "java_properties":
		util.ExportJavaProperties(secretsDict)
	case "kv":
		util.ExportKV(secretsDict)
	case "dotenv":
		util.ExportDotenv(secretsDict)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s, using dotenv\n", format)
		util.ExportDotenv(secretsDict)
	}

	return nil
}
