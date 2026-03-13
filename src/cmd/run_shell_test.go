package cmd

import "testing"

func TestRunCommandRequiresAtLeastOneArg(t *testing.T) {
	if err := runCmd.Args(runCmd, []string{}); err == nil {
		t.Fatal("expected error when no command args are provided")
	}
	if err := runCmd.Args(runCmd, []string{"echo"}); err != nil {
		t.Fatalf("expected no error for one arg, got %v", err)
	}
}

func TestRunAndShellDefaultPathFlag(t *testing.T) {
	runPath, err := runCmd.Flags().GetString("path")
	if err != nil {
		t.Fatalf("read run --path flag: %v", err)
	}
	if runPath != "/" {
		t.Fatalf("unexpected run --path default: got %q want %q", runPath, "/")
	}

	shellPath, err := shellCmd.Flags().GetString("path")
	if err != nil {
		t.Fatalf("read shell --path flag: %v", err)
	}
	if shellPath != "/" {
		t.Fatalf("unexpected shell --path default: got %q want %q", shellPath, "/")
	}
}
