package aiproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	maxBufferedEvents = 1000
	eventBatchSize    = 50
	// Console's limits for the request-derived fields. A denial that Console
	// refuses would block every later batch, so the fields are clamped here.
	maxEventMethodLength = 32
	maxEventHostLength   = 512
	maxEventPathLength   = 4096
)

// eventIdentifier mirrors Console's identifier rule for method and reason.
var eventIdentifier = regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)

var credentialShape = regexp.MustCompile(`(?i)(?:pss_(?:user|service|agent):v\d+:[^\s]+|psx_sess_[A-Za-z0-9_-]+|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-(?:proj-|admin-)?[A-Za-z0-9_-]{16,})`)

type eventBuffer struct {
	state    *runtimeState
	interval time.Duration
	input    chan agentapi.Event
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	spool    *eventSpool
	replay   []agentapi.Event
	stopErr  error
}

func newEventBuffer(state *runtimeState, interval time.Duration, spoolDirectory string, spoolMaxBytes int64) (*eventBuffer, error) {
	if interval <= 0 {
		interval = time.Second
	}
	spool, err := openEventSpool(spoolDirectory, state.sessionUID, spoolMaxBytes)
	if err != nil {
		return nil, err
	}
	buffer := &eventBuffer{
		state: state, interval: interval, input: make(chan agentapi.Event, 256),
		stop: make(chan struct{}), done: make(chan struct{}), spool: spool,
	}
	replay, err := spool.Load()
	if err != nil {
		return nil, err
	}
	for index := range replay {
		if !buffer.safe(&replay[index]) || !durableAuditEvent(replay[index]) {
			return nil, errors.New("Agent denial/error audit spool contains an unsafe event")
		}
	}
	buffer.replay = replay
	go buffer.loop()
	return buffer, nil
}

func (b *eventBuffer) Emit(event agentapi.Event) {
	redactRequestFields(&event, b.state.eventSecrets())
	durable := durableAuditEvent(event)
	if !b.safe(&event) {
		if durable {
			b.state.fail(errors.New("Agent denial/error audit event failed redaction validation"))
		}
		return
	}
	if durable {
		if err := b.spool.Persist(event); err != nil {
			b.state.fail(err)
			return
		}
	}
	select {
	case b.input <- event:
	default:
		// Ordinary allow events may shed under sustained pressure. Denials and
		// errors were fsync'd above and are discovered from the spool on the next
		// flush tick, so they cannot silently disappear here.
	}
}

func (b *eventBuffer) safe(event *agentapi.Event) bool {
	if event.Port < 0 || event.Port > 65535 {
		return false
	}
	fields := []string{event.EventID, event.GrantID, event.EventType, event.Protocol, event.Method,
		event.Host, event.Path, event.Provider, event.ProxyDecision, event.Outcome,
		event.CredentialAction, event.Reason}
	secrets := b.state.eventSecrets()
	for _, field := range fields {
		if credentialShape.MatchString(field) {
			return false
		}
		for _, secret := range secrets {
			if secret != "" && strings.Contains(field, secret) {
				return false
			}
		}
	}
	event.Detail = safeEventDetail(event.Detail, secrets)
	return true
}

// Request-derived fields are the only part of an event the Agent controls, and
// an unauthenticated client can put anything in them before it is refused. A
// denial still has to be recorded, so an unsafe value is replaced instead of
// treated as a redaction failure; every other field is written by the proxy,
// and an unsafe value there still fails closed in safe().
func redactRequestFields(event *agentapi.Event, secrets []string) {
	if event.Method == "" || len(event.Method) > maxEventMethodLength ||
		!eventIdentifier.MatchString(event.Method) || !safeEventText(event.Method, secrets) {
		event.Method = "UNKNOWN"
	}
	if event.Host == "" || len(event.Host) > maxEventHostLength ||
		containsControlCharacter(event.Host) || !safeEventText(event.Host, secrets) {
		event.Host = "redacted.invalid"
	}
	if len(event.Path) > maxEventPathLength || containsControlCharacter(event.Path) ||
		!safeEventText(event.Path, secrets) {
		event.Path = "/redacted"
	}
}

func containsControlCharacter(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}

// outcomeScrubbed marks a response the proxy passed on only after replacing
// credential material in it. It is kept like a denial: it must reach the
// Console.
const outcomeScrubbed = "scrubbed"

func durableAuditEvent(event agentapi.Event) bool {
	return event.Outcome == "denied" || event.Outcome == "error" || event.ProxyDecision == "block" ||
		event.ProxyDecision == "auth_deny" || event.Outcome == outcomeScrubbed
}

// eventDetailText and eventDetailNumbers are the only detail members an event
// may carry besides aws_sigv4_failure, path and rule: what the access policy
// or the secret guard decided, flat and bounded. An event never carries a
// request or response value, nor the request an ask offers.
var (
	eventDetailText    = []string{"connectionId", "connectionName", "class", "method", "operation"}
	eventDetailNumbers = []string{"scrubbedValues"}
)

// Console's limits for detail values.
const (
	maxEventDetailTextLength = 512
	maxEventRulePathLength   = 1024
)

func safeEventDetail(detail map[string]any, secrets []string) map[string]any {
	result := map[string]any{}
	if value, ok := detail["aws_sigv4_failure"].(string); ok && len(value) <= 64 &&
		controlIdentifier.MatchString(value) && safeEventText(value, secrets) {
		result["aws_sigv4_failure"] = value
	}
	for _, name := range eventDetailText {
		if value, ok := detail[name].(string); ok && value != "" && len(value) <= maxEventDetailTextLength &&
			!containsControlCharacter(value) && safeEventText(value, secrets) {
			result[name] = value
		}
	}
	if value, ok := detail["path"].(string); ok && value != "" && len(value) <= maxEventPathLength &&
		!containsControlCharacter(value) && safeEventText(value, secrets) {
		result["path"] = value
	}
	if rule, ok := safeEventRule(detail["rule"], secrets); ok {
		result["rule"] = rule
	}
	for _, name := range eventDetailNumbers {
		switch value := detail[name].(type) {
		case int:
			result[name] = value
		case float64:
			// A spooled event comes back from JSON with every number a float.
			if value >= 0 && value <= 1<<31 && value == float64(int(value)) {
				result[name] = int(value)
			}
		}
	}
	return result
}

// safeEventRule accepts the rule a policy answer names: "default",
// "secret_guard", or one rule object with a class or a match and an effect.
// It returns the rule rebuilt from its known members only, so nothing else
// rides along. A spooled event comes back from JSON with generic values, so
// both forms are read.
func safeEventRule(value any, secrets []string) (any, bool) {
	text := func(raw any, limit int) (string, bool) {
		value, ok := raw.(string)
		return value, ok && value != "" && len(value) <= limit && !containsControlCharacter(value) && safeEventText(value, secrets)
	}
	switch rule := value.(type) {
	case string:
		return rule, rule == "default" || rule == phaseproxy.SecretGuardRule
	case agentapi.PolicyRule:
		encoded := map[string]any{"effect": rule.Effect}
		if rule.Match != nil {
			match := map[string]any{}
			if len(rule.Match.Methods) > 0 {
				methods := make([]any, 0, len(rule.Match.Methods))
				for _, method := range rule.Match.Methods {
					methods = append(methods, method)
				}
				match["methods"] = methods
			}
			if rule.Match.Path != "" {
				match["path"] = rule.Match.Path
			}
			encoded["match"] = match
		} else {
			encoded["class"] = rule.Class
		}
		return safeEventRule(encoded, secrets)
	case map[string]any:
		effect, ok := text(rule["effect"], 16)
		if !ok {
			return nil, false
		}
		result := map[string]any{"effect": effect}
		rawMatch, hasMatch := rule["match"].(map[string]any)
		class, hasClass := text(rule["class"], 32)
		if hasMatch == hasClass {
			return nil, false
		}
		if hasClass {
			result["class"] = class
			return result, true
		}
		match := map[string]any{}
		if rawMethods, present := rawMatch["methods"]; present {
			list, ok := rawMethods.([]any)
			if !ok || len(list) == 0 || len(list) > 9 {
				return nil, false
			}
			methods := make([]string, 0, len(list))
			for _, raw := range list {
				method, ok := text(raw, maxEventMethodLength)
				if !ok {
					return nil, false
				}
				methods = append(methods, method)
			}
			match["methods"] = methods
		}
		if rawPath, present := rawMatch["path"]; present {
			path, ok := text(rawPath, maxEventRulePathLength)
			if !ok {
				return nil, false
			}
			match["path"] = path
		}
		if len(match) == 0 {
			return nil, false
		}
		result["match"] = match
		return result, true
	default:
		return nil, false
	}
}

func safeEventText(value string, secrets []string) bool {
	if credentialShape.MatchString(value) || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			return false
		}
	}
	return true
}

func (b *eventBuffer) loop() {
	defer close(b.done)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	pending := append(make([]agentapi.Event, 0, eventBatchSize+len(b.replay)), b.replay...)
	b.replay = nil
	for {
		select {
		case event := <-b.input:
			if len(pending) < maxBufferedEvents {
				pending = append(pending, event)
			}
			if len(pending) >= eventBatchSize {
				pending = b.flush(pending)
			}
		case <-ticker.C:
			pending = b.mergeSpooled(pending)
			pending = b.flush(pending)
		case <-b.stop:
			for {
				select {
				case event := <-b.input:
					if len(pending) < maxBufferedEvents {
						pending = append(pending, event)
					}
				default:
					pending = b.mergeSpooled(pending)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if !b.flushAllWithContext(ctx, pending) {
						b.stopErr = errors.New("flush Agent audit events before closing the session")
					}
					cancel()
					return
				}
			}
		}
	}
}

func (b *eventBuffer) mergeSpooled(pending []agentapi.Event) []agentapi.Event {
	spooled, err := b.spool.Load()
	if err != nil {
		b.state.fail(err)
		return pending
	}
	known := make(map[string]struct{}, len(pending))
	for _, event := range pending {
		known[event.EventID] = struct{}{}
	}
	for index := range spooled {
		if _, exists := known[spooled[index].EventID]; exists {
			continue
		}
		if !b.safe(&spooled[index]) || !durableAuditEvent(spooled[index]) {
			b.state.fail(errors.New("Agent denial/error audit spool contains an unsafe event"))
			continue
		}
		pending = append(pending, spooled[index])
		known[spooled[index].EventID] = struct{}{}
	}
	return pending
}

func (b *eventBuffer) flush(pending []agentapi.Event) []agentapi.Event {
	if len(pending) == 0 {
		return pending
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for len(pending) > 0 {
		count := eventBatchSize
		if len(pending) < count {
			count = len(pending)
		}
		if !b.flushWithContext(ctx, pending[:count]) {
			return pending
		}
		pending = pending[count:]
	}
	return nil
}

func (b *eventBuffer) flushWithContext(ctx context.Context, pending []agentapi.Event) bool {
	if len(pending) == 0 {
		return true
	}
	_, err := b.state.client.ShipEvents(ctx, b.state.sessionUID, agentapi.EventBatchRequest{
		SchemaVersion: agentapi.SchemaVersion,
		BatchID:       randomEventID("batch-"),
		Events:        pending,
	}, b.state.currentBackendCredential())
	if err != nil {
		return false
	}
	if err := b.spool.Acknowledge(pending); err != nil {
		b.state.fail(fmt.Errorf("acknowledge durable Agent audit events: %w", err))
		return false
	}
	return true
}

func (b *eventBuffer) flushAllWithContext(ctx context.Context, pending []agentapi.Event) bool {
	for len(pending) > 0 {
		count := eventBatchSize
		if len(pending) < count {
			count = len(pending)
		}
		if !b.flushWithContext(ctx, pending[:count]) {
			return false
		}
		pending = pending[count:]
	}
	return true
}

func (b *eventBuffer) Stop() error {
	b.once.Do(func() { close(b.stop) })
	<-b.done
	return b.stopErr
}

func randomEventID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return prefix + "00000000000000000000000000000000"
	}
	return prefix + hex.EncodeToString(value)
}

func newRequestEvent(binding *binding, method, host string, port int, requestPath string, decision, outcome, reason string, status int, latency time.Duration, action string) agentapi.Event {
	grantID, provider := "", "proxy"
	if binding != nil {
		grantID = binding.connection.GrantID
		provider = binding.connection.ServiceType
	}
	return agentapi.Event{
		EventID: randomEventID("event-"), CreatedAt: time.Now().UTC(), GrantID: grantID,
		EventType: "request", Protocol: "http", Method: method, Host: host, Port: port, Path: requestPath,
		Provider: provider, StatusCode: status, ProxyDecision: decision, Outcome: outcome,
		LatencyMS: latency.Milliseconds(), CredentialAction: action, Reason: reason, Detail: map[string]any{},
	}
}
