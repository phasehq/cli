package aiproxy

import (
	"errors"
	"net/http"
	"sync"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// maxDecoyHistoryPerConnection bounds how many Agent-visible credential
// generations one proxy process remembers per Connection. Each backend session
// mints fresh decoys, so this is the number of session recycles a client may
// sleep through before it has to be re-bootstrapped.
const maxDecoyHistoryPerConnection = 512

// decoyHistory remembers every Agent-visible identifier and decoy set this
// proxy process has handed out, per Connection. The Console mints decoys per
// backend session, so a relay that outlives its sessions keeps serving clients
// whose environment still carries an older generation: the request is
// translated to the live credential of the same Connection at injection time.
//
// Decoys are placeholders, not secrets; the proxy capability authenticates the
// client. An older generation can therefore never select a different
// Connection, only the one it was issued for.
type decoyHistory struct {
	mu   sync.RWMutex
	sets map[string][]decoySet
}

type decoySet struct {
	identifiers map[string]string
	decoys      map[string]string
}

func newDecoyHistory() *decoyHistory {
	return &decoyHistory{sets: make(map[string][]decoySet)}
}

func (h *decoyHistory) remember(connections []agentapi.Connection) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, connection := range connections {
		if connection.ConnectionID == "" {
			continue
		}
		candidate := decoySet{identifiers: cloneStringMap(connection.Identifiers), decoys: cloneStringMap(connection.DecoyMaterial)}
		history := h.sets[connection.ConnectionID]
		duplicate := false
		for _, known := range history {
			if equalStringMap(known.identifiers, candidate.identifiers) && equalStringMap(known.decoys, candidate.decoys) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		history = append(history, candidate)
		if len(history) > maxDecoyHistoryPerConnection {
			history = history[len(history)-maxDecoyHistoryPerConnection:]
		}
		h.sets[connection.ConnectionID] = history
	}
}

// previous returns views of the live Connection whose Agent-visible material is
// an older generation, newest first. The views share the live secret material,
// so an injection performed through one of them swaps the old decoy for the
// current credential.
func (h *decoyHistory) previous(current agentapi.Connection) []agentapi.Connection {
	if h == nil || current.ConnectionID == "" {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	history := h.sets[current.ConnectionID]
	views := make([]agentapi.Connection, 0, len(history))
	for index := len(history) - 1; index >= 0; index-- {
		known := history[index]
		if equalStringMap(known.identifiers, current.Identifiers) && equalStringMap(known.decoys, current.DecoyMaterial) {
			continue
		}
		view := current
		view.Identifiers = cloneStringMap(known.identifiers)
		view.DecoyMaterial = cloneStringMap(known.decoys)
		views = append(views, view)
	}
	return views
}

// previousDecoyViews is the state-level accessor used by the HTTP and
// protocol adapters.
func (s *runtimeState) previousDecoyViews(connection agentapi.Connection) []agentapi.Connection {
	if s == nil {
		return nil
	}
	return s.decoys.previous(connection)
}

// staleDecoyInjectionFailure reports whether an injection failed only because
// the request presented a credential generation other than the live one.
func staleDecoyInjectionFailure(err error) bool {
	var typed *phaseproxy.InjectionError
	if !errors.As(err, &typed) {
		return false
	}
	switch typed.Code {
	case phaseproxy.InjectionSwapMiss:
		return true
	case phaseproxy.InjectionFinalizerFailed:
		return typed.AWSSigV4Failure == phaseproxy.AWSSigV4AccessKeyMismatch
	}
	return false
}

// applyHTTPInjectionWithHistory injects the live credential for a request that
// presents either the current or a previously issued decoy generation. Every
// injector validates before it mutates, so a failed attempt leaves the request
// untouched for the next generation.
func applyHTTPInjectionWithHistory(req *http.Request, connection agentapi.Connection, previous []agentapi.Connection) (phaseproxy.InjectionResult, error) {
	result, err := phaseproxy.ApplyHTTPInjection(req.Context(), req, connection)
	if err == nil || !staleDecoyInjectionFailure(err) {
		return result, err
	}
	for _, view := range previous {
		retried, retryErr := phaseproxy.ApplyHTTPInjection(req.Context(), req, view)
		if retryErr == nil {
			return retried, nil
		}
		if !staleDecoyInjectionFailure(retryErr) {
			return phaseproxy.InjectionResult{}, retryErr
		}
	}
	return result, err
}
