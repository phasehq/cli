package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var secretsUpdateCmd = &cobra.Command{
	Use:   "update <KEY>",
	Short: "📝 Update an existing secret",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSecretsUpdate,
}

func init() {
	secretsUpdateCmd.Flags().String("env", "", "Environment name")
	secretsUpdateCmd.Flags().String("app", "", "Application name")
	secretsUpdateCmd.Flags().String("app-id", "", "Application ID")
	secretsUpdateCmd.Flags().String("path", "", "Source path of the secret")
	secretsUpdateCmd.Flags().String("updated-path", "", "New path for the secret")
	secretsUpdateCmd.Flags().Bool("override", false, "Update override value")
	secretsUpdateCmd.Flags().Bool("toggle-override", false, "Toggle override state")
	secretsUpdateCmd.Flags().String("random", "", "Random type (hex, alphanumeric, key128, key256)")
	secretsUpdateCmd.Flags().Int("length", 32, "Length for random secret")
	secretsCmd.AddCommand(secretsUpdateCmd)
}

func runSecretsUpdate(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	sourcePath, _ := cmd.Flags().GetString("path")
	destPath, _ := cmd.Flags().GetString("updated-path")
	override, _ := cmd.Flags().GetBool("override")
	toggleOverride, _ := cmd.Flags().GetBool("toggle-override")
	randomType, _ := cmd.Flags().GetString("random")
	randomLength, _ := cmd.Flags().GetInt("length")

	var key string
	if len(args) > 0 {
		key = args[0]
	} else {
		fmt.Print("🗝️\u200A Please enter the key: ")
		fmt.Scanln(&key)
	}

	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ToUpper(key)

	var newValue string
	if toggleOverride {
		// No value needed for toggle
	} else if randomType != "" {
		if (randomType == "key128" || randomType == "key256") && randomLength != 32 {
			fmt.Fprintf(os.Stderr, "⚠️\u200A Warning: The length argument is ignored for '%s'. Using default lengths.\n", randomType)
		}
		var err error
		newValue, err = misc.GenerateRandomSecret(randomType, randomLength)
		if err != nil {
			return fmt.Errorf("failed to generate random secret: %w", err)
		}
	} else if override {
		fmt.Print("✨ Please enter the 🔏 override value (hidden): ")
		valueBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read value: %w", err)
		}
		fmt.Println()
		newValue = string(valueBytes)
	} else {
		if term.IsTerminal(int(syscall.Stdin)) {
			fmt.Printf("✨ Please enter the new value for %s (hidden): ", key)
			valueBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}
			fmt.Println()
			newValue = string(valueBytes)
		} else {
			buf := make([]byte, 1024*1024)
			n, _ := os.Stdin.Read(buf)
			newValue = strings.TrimSpace(string(buf[:n]))
		}
	}

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	result, err := p.Update(sdk.UpdateOptions{
		EnvName:         envName,
		AppName:         appName,
		AppID:           appID,
		Key:             key,
		Value:           newValue,
		SourcePath:      sourcePath,
		DestinationPath: destPath,
		Override:        override,
		ToggleOverride:  toggleOverride,
	})
	if err != nil {
		return fmt.Errorf("error updating secret: %w", err)
	}

	if result == "Success" {
		fmt.Println(util.BoldGreen("✅ Successfully updated the secret."))
		listPath := sourcePath
		if destPath != "" {
			listPath = destPath
		}
		if err := listSecrets(p, envName, appName, appID, "", listPath, false, false, false, nil); err != nil {
			return err
		}
	} else {
		fmt.Println(result)
	}
	return nil
}
