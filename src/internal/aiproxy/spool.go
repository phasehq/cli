package aiproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/phasehq/cli/internal/agentapi"
)

const defaultEventSpoolBytes = int64(16 << 20)

type spoolEnvelope struct {
	SchemaVersion int            `json:"schemaVersion"`
	SessionUID    string         `json:"sessionUid"`
	Event         agentapi.Event `json:"event"`
}

type spoolRecord struct {
	path string
	size int64
}

type eventSpool struct {
	mu         sync.Mutex
	directory  string
	sessionUID string
	maxBytes   int64
	bytes      int64
	records    map[string]spoolRecord
}

func defaultEventSpoolDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve event spool home: %w", err)
	}
	return filepath.Join(home, ".phase", "ai", "event-spool"), nil
}

func openEventSpool(baseDirectory, sessionUID string, maxBytes int64) (*eventSpool, error) {
	if strings.TrimSpace(sessionUID) == "" {
		return nil, errors.New("Agent event spool requires a session UID")
	}
	if baseDirectory == "" {
		var err error
		baseDirectory, err = defaultEventSpoolDirectory()
		if err != nil {
			return nil, err
		}
	}
	if maxBytes <= 0 {
		maxBytes = defaultEventSpoolBytes
	}
	digest := sha256.Sum256([]byte(sessionUID))
	directory := filepath.Join(baseDirectory, hex.EncodeToString(digest[:16]))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create Agent event spool: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure Agent event spool: %w", err)
	}
	spool := &eventSpool{directory: directory, sessionUID: sessionUID, maxBytes: maxBytes, records: make(map[string]spoolRecord)}
	if _, err := spool.loadLocked(); err != nil {
		return nil, err
	}
	return spool, nil
}

func (s *eventSpool) Persist(event agentapi.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[event.EventID]; ok {
		return nil
	}
	payload, err := json.Marshal(spoolEnvelope{SchemaVersion: agentapi.SchemaVersion, SessionUID: s.sessionUID, Event: event})
	if err != nil {
		return fmt.Errorf("encode Agent audit event: %w", err)
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > s.maxBytes-s.bytes || len(s.records) >= maxBufferedEvents {
		return errors.New("Agent denial/error audit spool is full; proxy stopped to preserve audit guarantees")
	}
	nameDigest := sha256.Sum256([]byte(event.EventID))
	destination := filepath.Join(s.directory, hex.EncodeToString(nameDigest[:])+".json")
	temporary, err := os.CreateTemp(s.directory, ".event-*")
	if err != nil {
		return fmt.Errorf("create Agent audit spool file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(payload)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryName, destination)
	}
	if err == nil {
		err = os.Chmod(destination, 0o600)
	}
	if err == nil {
		err = syncDirectory(s.directory)
	}
	if err != nil {
		return fmt.Errorf("persist Agent denial/error audit event: %w", err)
	}
	s.records[event.EventID] = spoolRecord{path: destination, size: int64(len(payload))}
	s.bytes += int64(len(payload))
	return nil
}

func (s *eventSpool) Load() ([]agentapi.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *eventSpool) loadLocked() ([]agentapi.Event, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, fmt.Errorf("read Agent event spool: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	records := make(map[string]spoolRecord)
	events := make([]agentapi.Event, 0, len(entries))
	var total int64
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".event-") {
			// A crash before rename leaves only a temporary file with no committed
			// event. It is safe to remove after startup.
			_ = os.Remove(filepath.Join(s.directory, entry.Name()))
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Type()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("Agent event spool contains unexpected entry %q", entry.Name())
		}
		path := filepath.Join(s.directory, entry.Name())
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("inspect Agent event spool entry %q", entry.Name())
		}
		if info.Size() <= 0 || info.Size() > s.maxBytes-total {
			return nil, errors.New("Agent denial/error audit spool exceeds its bounded retention limit")
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read Agent event spool entry: %w", err)
		}
		var envelope spoolEnvelope
		if err := json.Unmarshal(payload, &envelope); err != nil || envelope.SchemaVersion != agentapi.SchemaVersion || envelope.SessionUID != s.sessionUID || envelope.Event.EventID == "" {
			return nil, fmt.Errorf("Agent event spool entry %q is invalid", entry.Name())
		}
		if _, duplicate := records[envelope.Event.EventID]; duplicate {
			return nil, errors.New("Agent event spool contains duplicate event IDs")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure Agent event spool entry: %w", err)
		}
		records[envelope.Event.EventID] = spoolRecord{path: path, size: info.Size()}
		total += info.Size()
		events = append(events, envelope.Event)
	}
	if len(records) > maxBufferedEvents {
		return nil, errors.New("Agent denial/error audit spool exceeds its event limit")
	}
	s.records = records
	s.bytes = total
	return events, nil
}

func (s *eventSpool) Acknowledge(events []agentapi.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, event := range events {
		record, ok := s.records[event.EventID]
		if !ok {
			continue
		}
		if err := os.Remove(record.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove delivered Agent audit event: %w", err)
		}
		delete(s.records, event.EventID)
		s.bytes -= record.size
		changed = true
	}
	if changed {
		return syncDirectory(s.directory)
	}
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
