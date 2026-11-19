package engine

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"time"
)

// ProxyStateVersion is the version of the proxy state this build writes and reads.
const ProxyStateVersion = 1

// ProxyState says where a running engine's proxy listens, with the capability its
// control API asks for. A command on this machine reads it to register a secret value
// with the proxy's leak protection, from a shell that carries nothing of Phase.
//
// The capability lets its holder use the proxy, so the file is its owner's alone. It
// is kept apart from the status, which holds no credential, and it is there only
// while the proxy serves a session.
type ProxyState struct {
	Version int       `json:"version"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	// ProxyURL is the proxy's loopback address with its capability, as a runtime
	// hands it out.
	ProxyURL string `json:"proxyUrl"`
}

// ProxyStatePath is where a running engine keeps its proxy state.
func ProxyStatePath(directory string) string { return filepath.Join(directory, "proxy.json") }

// ReadProxyState reads an engine's proxy state. It reads only a regular file that is
// its owner's alone and that this build understands; anything else is an error, and
// nothing of it is used. Whether the engine that wrote it still runs is the caller's
// to check.
func ReadProxyState(directory string) (ProxyState, error) {
	path := ProxyStatePath(directory)
	info, err := os.Lstat(path)
	if err != nil {
		return ProxyState{}, err
	}
	if !info.Mode().IsRegular() {
		return ProxyState{}, errors.New("the engine's proxy state must be a regular file, not a link")
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ProxyState{}, errors.New("the engine's proxy state must be its owner's alone")
	}
	file, err := os.Open(path)
	if err != nil {
		return ProxyState{}, err
	}
	defer file.Close()
	// The file that was opened is the one that was looked at.
	if opened, err := file.Stat(); err != nil || !os.SameFile(info, opened) {
		return ProxyState{}, errors.New("the engine's proxy state changed while it was read")
	}
	var state ProxyState
	if err := json.NewDecoder(io.LimitReader(file, 64<<10)).Decode(&state); err != nil {
		return ProxyState{}, err
	}
	if state.Version != ProxyStateVersion {
		return ProxyState{}, errors.New("the engine's proxy state is of a version this build doesn't read")
	}
	if state.PID <= 0 || state.ProxyURL == "" {
		return ProxyState{}, errors.New("the engine's proxy state is incomplete")
	}
	return state, nil
}

// publishProxy writes the proxy state for the session the proxy has just started to
// serve.
func (e *engine) publishProxy(proxyURL string) error {
	payload, err := json.Marshal(ProxyState{Version: ProxyStateVersion, PID: os.Getpid(), Started: e.started, ProxyURL: proxyURL})
	if err != nil {
		return err
	}
	return writeOwnerOnly(ProxyStatePath(e.cfg.StateDirectory), payload)
}

// withdrawProxy removes the proxy state: the proxy no longer serves a session.
func (e *engine) withdrawProxy() {
	_ = os.Remove(ProxyStatePath(e.cfg.StateDirectory))
}

// writeOwnerOnly replaces a file with one only its owner can read, whole or not at
// all.
func writeOwnerOnly(path string, payload []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".proxy-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
