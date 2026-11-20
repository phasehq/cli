package aiproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
)

func (e *Engine) monitor(ctx context.Context, state *runtimeState) {
	interval := e.RefreshInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		expiresIn := time.Until(state.expiration())
		if expiresIn <= 0 {
			state.fail(fmt.Errorf("%w: reopen the foreground proxy with a new backend session and decoys", airuntime.ErrSessionExpired))
			return
		}
		expiryTimer := time.NewTimer(expiresIn)
		select {
		case <-ctx.Done():
			expiryTimer.Stop()
			return
		case <-expiryTimer.C:
			state.fail(fmt.Errorf("%w: reopen the foreground proxy with a new backend session and decoys", airuntime.ErrSessionExpired))
			return
		case <-ticker.C:
			expiryTimer.Stop()
			if refreshFromMonitor(ctx, state, true) {
				return
			}
		case <-state.refreshRequests:
			expiryTimer.Stop()
			if refreshFromMonitor(ctx, state, false) {
				return
			}
		}
	}
}

// refreshFromMonitor applies one config refresh and reports whether the
// monitor must stop. Only the periodic refresh decides session health on a
// transient failure: an extra refresh that cannot reach the Console leaves the
// session as the last periodic refresh found it.
func refreshFromMonitor(ctx context.Context, state *runtimeState, periodic bool) bool {
	_, err := state.refreshConfig(ctx)
	if err == nil {
		return false
	}
	rejected, terminal := errors.Is(err, errRefreshedConfigRejected), terminalSessionError(err)
	if periodic || rejected || terminal {
		state.setUnhealthy()
	}
	if rejected {
		state.fail(err)
		return true
	}
	if terminal {
		cause := errors.New("Agent session was revoked during refresh")
		var apiErr *agentapi.Error
		if errors.As(err, &apiErr) && apiErr.Code == "agent_session_expired" {
			cause = fmt.Errorf("%w: backend reported hard expiry", airuntime.ErrSessionExpired)
		}
		state.fail(cause)
		return true
	}
	return false
}

func terminalSessionError(err error) bool {
	var apiErr *agentapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.Code == "agent_session_revoked" || apiErr.Code == "agent_session_expired"
}
