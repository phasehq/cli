package aiproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	// presetCacheLifetime is how long one read of the Console's preset list is
	// reused. Runtime API calls count against the plan rate limit.
	presetCacheLifetime = 5 * time.Minute
	// presetRetryInterval spaces out attempts after a failed read.
	presetRetryInterval = time.Minute
	presetFetchTimeout  = 10 * time.Second
)

// presetCache holds the Console's provider presets for one session, in memory
// only. A proxied request never waits for it: lookup answers from what is
// already held and at most starts a refresh in the background. Only the
// control routes an Agent calls on purpose read the list synchronously.
type presetCache struct {
	mu         sync.Mutex
	fetch      func(context.Context) ([]agentapi.Preset, error)
	now        func() time.Time
	presets    []agentapi.Preset
	loaded     bool
	fetchedAt  time.Time
	attemptAt  time.Time
	refreshing bool
}

func newPresetCache(client *agentapi.Client) *presetCache {
	return &presetCache{now: time.Now, fetch: func(ctx context.Context) ([]agentapi.Preset, error) {
		registry, err := client.Registry(ctx)
		if err != nil {
			return nil, err
		}
		return registry.Presets, nil
	}}
}

func (c *presetCache) fresh(now time.Time) bool {
	return c.loaded && now.Sub(c.fetchedAt) < presetCacheLifetime
}

// list returns the presets, reading them from the Console when the held copy
// is missing or old. A failed read falls back to the held copy if there is one.
func (c *presetCache) list(ctx context.Context) ([]agentapi.Preset, error) {
	c.mu.Lock()
	if c.fresh(c.now()) {
		presets := c.presets
		c.mu.Unlock()
		return presets, nil
	}
	c.mu.Unlock()
	presets, err := c.fetch(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attemptAt = c.now()
	if err != nil {
		if c.loaded {
			return c.presets, nil
		}
		return nil, err
	}
	c.presets, c.loaded, c.fetchedAt = presets, true, c.attemptAt
	return presets, nil
}

// lookup returns the preset a host belongs to from the held copy. It never
// waits: when the copy is missing or old it starts one background read, so a
// later call can answer better.
//
// held is false while no copy has been read yet: the caller then cannot tell
// a host without a preset from one whose preset it has not seen.
func (c *presetCache) lookup(host string, port int) (preset *agentapi.Preset, held bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	now := c.now()
	if !c.fresh(now) && !c.refreshing && (c.attemptAt.IsZero() || now.Sub(c.attemptAt) >= presetRetryInterval) {
		c.refreshing = true
		go c.refresh()
	}
	presets, held := c.presets, c.loaded
	c.mu.Unlock()
	return matchPreset(presets, host, port), held
}

func (c *presetCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), presetFetchTimeout)
	defer cancel()
	_, _ = c.list(ctx)
	c.mu.Lock()
	c.refreshing = false
	c.mu.Unlock()
}

// matchPreset finds the preset a host belongs to. The port is not compared:
// a request that reached the service on another port, or over plain HTTP, is
// still a request to that service.
func matchPreset(presets []agentapi.Preset, host string, _ int) *agentapi.Preset {
	for index := range presets {
		for _, rule := range presets[index].HostRules() {
			rule.Port = 0
			if phaseproxy.MatchHostOnly(rule, host, 443) {
				return &presets[index]
			}
		}
	}
	return nil
}

// presets serves GET /v1/presets: the provider presets a Connection can be
// asked for by ID. It is catalog data and carries no secret.
func (h *controlHandler) presets(w http.ResponseWriter, req *http.Request) {
	presets, err := h.state.presets.list(req.Context())
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	response := remoteapi.PresetsResponse{
		SchemaVersion: agentapi.SchemaVersion, Kind: "phase.ai.presets", Presets: make([]agentapi.Preset, 0, len(presets)),
	}
	for _, preset := range presets {
		if controlIdentifier.MatchString(preset.ID) {
			response.Presets = append(response.Presets, preset)
		}
	}
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, h.state.eventSecrets()) {
		writeControlError(w, http.StatusBadGateway, "unsafe_presets_response", "The preset list contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}
