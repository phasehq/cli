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
	fetch      func(context.Context) (*agentapi.RegistryResponse, error)
	now        func() time.Time
	presets    []agentapi.Preset
	services   []agentapi.RegistryService
	loaded     bool
	fetchedAt  time.Time
	attemptAt  time.Time
	refreshing bool
}

func newPresetCache(client *agentapi.Client) *presetCache {
	return &presetCache{now: time.Now, fetch: client.Registry}
}

func (c *presetCache) fresh(now time.Time) bool {
	return c.loaded && now.Sub(c.fetchedAt) < presetCacheLifetime
}

// list returns the presets, reading them from the Console when the held copy
// is missing or old. A failed read falls back to the held copy if there is one.
func (c *presetCache) list(ctx context.Context) ([]agentapi.Preset, error) {
	presets, _, err := c.registry(ctx)
	return presets, err
}

// registry is list with the packaged services the registry lists beside the
// presets; both are cached together.
func (c *presetCache) registry(ctx context.Context) ([]agentapi.Preset, []agentapi.RegistryService, error) {
	c.mu.Lock()
	if c.fresh(c.now()) {
		presets, services := c.presets, c.services
		c.mu.Unlock()
		return presets, services, nil
	}
	c.mu.Unlock()
	registry, err := c.fetch(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attemptAt = c.now()
	if err != nil {
		if c.loaded {
			return c.presets, c.services, nil
		}
		return nil, nil, err
	}
	c.presets, c.services, c.loaded, c.fetchedAt = registry.Presets, registry.ServiceList(), true, c.attemptAt
	return c.presets, c.services, nil
}

// lookup returns the preset a host belongs to from the held copy. It never
// waits: when the copy is missing or old it starts one background read, so a
// later call can answer better.
//
// held is false while no copy has been read yet: the caller then cannot tell
// a host without a preset from one whose preset it has not seen.
func (c *presetCache) lookup(host string, port int) (match hostMatch, held bool) {
	if c == nil {
		return hostMatch{}, false
	}
	c.mu.Lock()
	now := c.now()
	if !c.fresh(now) && !c.refreshing && (c.attemptAt.IsZero() || now.Sub(c.attemptAt) >= presetRetryInterval) {
		c.refreshing = true
		go c.refresh()
	}
	presets, services, held := c.presets, c.services, c.loaded
	c.mu.Unlock()
	return matchRegistry(presets, services, host, port), held
}

func (c *presetCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), presetFetchTimeout)
	defer cancel()
	_, _ = c.list(ctx)
	c.mu.Lock()
	c.refreshing = false
	c.mu.Unlock()
}

// hostMatch is what the registry knows about a host no Connection covers: a
// packaged service that owns it, else a preset, else nothing.
type hostMatch struct {
	service *agentapi.RegistryService
	preset  *agentapi.Preset
}

// matchRegistry prefers a packaged service over a preset. The aws service is
// never matched: its suffix rule is too broad to say what a host needs.
func matchRegistry(presets []agentapi.Preset, services []agentapi.RegistryService, host string, port int) hostMatch {
	for index := range services {
		service := &services[index]
		if service.ServiceType == "aws" || !controlIdentifier.MatchString(service.ServiceType) ||
			plainTitleText(service.DisplayName) == "" || len(service.CredentialProviders) == 0 ||
			!controlIdentifier.MatchString(service.CredentialProviders[0]) {
			continue
		}
		for _, rule := range service.Hosts {
			rule.Port = 0
			if phaseproxy.MatchHostOnly(rule, host, 443) {
				return hostMatch{service: service}
			}
		}
	}
	return hostMatch{preset: matchPreset(presets, host, port)}
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
	if err != nil || manifestPayloadContains(payload, h.state.readTripwireSecrets()) {
		writeControlError(w, http.StatusBadGateway, "unsafe_presets_response", "The preset list contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}
