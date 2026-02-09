package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var secretsCreateCmd = &cobra.Command{
	Use:   "create [KEY]",
	Short: "💳 Create a new secret",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSecretsCreate,
}

func init() {
	secretsCreateCmd.Flags().String("env", "", "Environment name")
	secretsCreateCmd.Flags().String("app", "", "Application name")
	secretsCreateCmd.Flags().String("app-id", "", "Application ID")
	secretsCreateCmd.Flags().String("path", "/", "Path for the secret")
	secretsCreateCmd.Flags().Bool("override", false, "Create with override")
	secretsCreateCmd.Flags().String("random", "", "Random type (hex, alphanumeric, key128, key256)")
	secretsCreateCmd.Flags().Int("length", 32, "Length for random secret")
	secretsCmd.AddCommand(secretsCreateCmd)
}

func runSecretsCreate(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")
	override, _ := cmd.Flags().GetBool("override")
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

	var value string
	if override {
		value = ""
	} else if randomType != "" {
		if (randomType == "key128" || randomType == "key256") && randomLength != 32 {
			fmt.Fprintf(os.Stderr, "⚠️\u200A Warning: The length argument is ignored for '%s'. Using default lengths.\n", randomType)
		}
		var err error
		value, err = misc.GenerateRandomSecret(randomType, randomLength)
		if err != nil {
			return fmt.Errorf("failed to generate random secret: %w", err)
		}
	} else {
		if term.IsTerminal(int(syscall.Stdin)) {
			fmt.Print("✨ Please enter the value (hidden): ")
			valueBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}
			fmt.Println()
			value = string(valueBytes)
		} else {
			// Read from pipe
			buf := make([]byte, 1024*1024)
			n, _ := os.Stdin.Read(buf)
			value = strings.TrimSpace(string(buf[:n]))
		}
	}

	var overrideValue string
	if override {
		fmt.Print("✨ Please enter the 🔏 override value (hidden): ")
		ovBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read override value: %w", err)
		}
		fmt.Println()
		overrideValue = string(ovBytes)
	}

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	err = p.Create(phase.CreateOptions{
		KeyValuePairs: []phase.KeyValuePair{{Key: key, Value: value}},
		EnvName:       envName,
		AppName:       appName,
		AppID:         appID,
		Path:          path,
		OverrideValue: overrideValue,
	})
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	listSecrets(p, envName, appName, appID, "", path, false)
	return nil
}
