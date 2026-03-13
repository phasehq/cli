package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var usersKeyringCmd = &cobra.Command{
	Use:   "keyring",
	Short: "🔐 Display information about the Phase keyring",
	RunE:  runUsersKeyring,
}

func init() {
	usersCmd.AddCommand(usersKeyringCmd)
}

func runUsersKeyring(cmd *cobra.Command, args []string) error {
	switch runtime.GOOS {
	case "darwin":
		fmt.Println("Keyring backend: macOS Keychain")
	case "linux":
		fmt.Println("Keyring backend: GNOME Keyring / Secret Service")
	case "windows":
		fmt.Println("Keyring backend: Windows Credential Manager")
	default:
		fmt.Printf("Keyring backend: Unknown (%s)\n", runtime.GOOS)
	}
	return nil
}
