package aiproxy

import (
	"errors"
	"os"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestEventSpoolFolderExistsOnlyWhileEventsWait(t *testing.T) {
	base := t.TempDir()
	spool, err := openEventSpool(base, "session-cleanup", 0)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("opening a spool created %d entries", len(entries))
	}
	event := agentapi.Event{EventID: "event-1", ProxyDecision: "block", Outcome: "denied"}
	if err := spool.Persist(event); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool.directory); err != nil {
		t.Fatalf("spooled event has no folder: %v", err)
	}
	if err := spool.Acknowledge([]agentapi.Event{event}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drained spool folder remains: %v", err)
	}
	if events, err := spool.Load(); err != nil || len(events) != 0 {
		t.Fatalf("load of a removed spool = %v, %v", events, err)
	}
	// The sweep may remove the empty folder between events.
	if err := spool.Persist(agentapi.Event{EventID: "event-2", ProxyDecision: "block", Outcome: "denied"}); err != nil {
		t.Fatal(err)
	}
	if events, err := spool.Load(); err != nil || len(events) != 1 {
		t.Fatalf("event after the folder was removed = %v, %v", events, err)
	}
}
