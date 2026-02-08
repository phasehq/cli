package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

func init() {
	if runtime.GOOS == "linux" {
		updateCmd := &cobra.Command{
			Use:   "update",
			Short: "🆙 Update the Phase CLI to the latest version",
			RunE:  runUpdate,
		}
		rootCmd.AddCommand(updateCmd)
	}
}

func runUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("Updating Phase CLI...")

	resp, err := http.Get("https://pkg.phase.dev/install.sh")
	if err != nil {
		return fmt.Errorf("failed to download install script: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download install script: HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "phase-install-*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write install script: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	cleanEnv := util.CleanSubprocessEnv()
	var envSlice []string
	for k, v := range cleanEnv {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	c := exec.Command(tmpPath)
	c.Env = envSlice
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin

	if err := c.Run(); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Println(util.BoldGreen("✅ Update completed successfully."))
	return nil
}
