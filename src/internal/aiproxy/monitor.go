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
			_, err := state.refreshConfig(ctx)
			if err != nil {
				state.setUnhealthy()
				if errors.Is(err, errRefreshedConfigRejected) {
					state.fail(err)
					return
				}
				if terminalSessionError(err) {
					cause := errors.New("Agent session was revoked during refresh")
					var apiErr *agentapi.Error
					if errors.As(err, &apiErr) && apiErr.Code == "agent_session_expired" {
						cause = fmt.Errorf("%w: backend reported hard expiry", airuntime.ErrSessionExpired)
					}
					state.fail(cause)
					return
				}
				continue
			}
		}
	}
}

func terminalSessionError(err error) bool {
	var apiErr *agentapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.Code == "agent_session_revoked" || apiErr.Code == "agent_session_expired"
}
