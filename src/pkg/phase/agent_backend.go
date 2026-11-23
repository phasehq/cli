package phase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/offline"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

// AgentBackend serves the secrets commands for an Agent token. It never holds
// an environment key and never writes anything to disk: every call goes to
// the Console, which checks the Workflow's app Connections each time.
type AgentBackend struct {
	client *agentapi.Client
	// userData is the app access listing in the SDK's shape, read once per
	// process and kept in memory only.
	userData *misc.AppKeyResponse
	// expired are the app grants whose time limit passed, from the same read.
	expired []agentapi.ExpiredAppConnection
	// secretIDs maps what Get returned to each secret's Phase id, for leak
	// protection's placeholders.
	idMu      sync.Mutex
	secretIDs map[string]string
}

func secretIDKey(result sdk.SecretResult) string {
	return result.Application + "\x00" + result.Environment + "\x00" + result.Path + "\x00" + result.Key
}

// SecretID is the Phase id of a secret this backend returned, or "".
func (b *AgentBackend) SecretID(result sdk.SecretResult) string {
	b.idMu.Lock()
	defer b.idMu.Unlock()
	return b.secretIDs[secretIDKey(result)]
}

// agentTarget is the environment a call addresses, with the names to show.
type agentTarget struct {
	appID, env         string
	appLabel, envLabel string
}

// agentCallTimeout bounds one secrets command; the transport bounds each call.
const agentCallTimeout = 2 * time.Minute

func newAgentBackend() (*AgentBackend, error) {
	if offline.IsOffline() {
		return nil, ErrAgentOffline
	}
	token, err := keyring.GetCredentials()
	if err != nil {
		return nil, err
	}
	account := keyring.LastAccount()
	host, err := config.GetDefaultUserHost()
	if err != nil {
		return nil, err
	}
	ConfigureUserAgent()
	client, err := agentapi.NewClient(host, token, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid Agent token: %w", err)
	}
	if client.TokenType() != agentapi.TokenAgent {
		return nil, errors.New("invalid Agent token")
	}
	ai.SetAgentLogin(true)
	backend := &AgentBackend{client: client}
	rememberLogin(backend, account)
	return backend, nil
}

func agentContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), agentCallTimeout)
}

// UserData converts what the Workflow can use now into the SDK's app list, so
// apps list, init and app and environment selection work as they do for other
// logins. Several app Connections may cover one app; their environments merge.
func (b *AgentBackend) UserData() (*misc.AppKeyResponse, error) {
	if b.userData != nil {
		return b.userData, nil
	}
	ctx, cancel := agentContext()
	defer cancel()
	access, err := b.client.AppAccess(ctx)
	if err != nil {
		return nil, agentError(err)
	}
	data := &misc.AppKeyResponse{Apps: []misc.App{}}
	b.expired = access.Expired
	appIndex := map[string]int{}
	for _, connection := range access.Apps {
		index, known := appIndex[connection.App.ID]
		if !known {
			index = len(data.Apps)
			appIndex[connection.App.ID] = index
			data.Apps = append(data.Apps, misc.App{ID: connection.App.ID, Name: connection.App.Name, Encryption: "SSE"})
		}
		for _, environment := range connection.Environments {
			duplicate := false
			for _, existing := range data.Apps[index].EnvironmentKeys {
				duplicate = duplicate || existing.Environment.ID == environment.ID
			}
			if duplicate {
				continue
			}
			data.Apps[index].EnvironmentKeys = append(data.Apps[index].EnvironmentKeys, misc.EnvironmentKey{
				ID: environment.ID,
				Environment: misc.Environment{
					ID: environment.ID, Name: environment.Name, EnvType: strings.ToUpper(environment.EnvType),
				},
			})
		}
	}
	b.userData = data
	return data, nil
}

// target resolves the selectors against what the Workflow can use: an app by
// exact ID, or app and environment names matched exactly, ignoring case. A
// substring match is never used, as it can land a write or delete on another
// app or environment the Agent happens to hold. An app ID or an environment
// that is not listed is still sent, so the Console's refusal and its
// ready-to-send request is what the Agent sees. Only an app named by a name
// nothing matches cannot be sent, as the API takes app IDs; that refusal
// carries a request by app name instead.
func (b *AgentBackend) target(appName, envName, appID, access string) (agentTarget, error) {
	if envName == "" {
		envName = "Development"
	}
	if appID == "" && appName == "" {
		return agentTarget{}, errors.New("no application context provided")
	}
	data, err := b.UserData()
	if err != nil {
		return agentTarget{}, err
	}
	var app *misc.App
	for index := range data.Apps {
		candidate := &data.Apps[index]
		switch {
		case appID != "":
			if candidate.ID == appID {
				app = candidate
			}
		case app == nil && nameMatches(candidate.Name, appName):
			app = candidate
		}
	}
	if app == nil {
		if appID != "" {
			return agentTarget{appID: appID, env: envName, appLabel: appID, envLabel: envName}, nil
		}
		// An expired grant is still addressed by its app ID, so the Agent gets
		// the Console's refusal and its renew request.
		if expired, ok := b.expiredApp(appName); ok {
			return agentTarget{appID: expired.App.ID, env: envName, appLabel: expired.App.Name, envLabel: envName}, nil
		}
		return agentTarget{}, &AgentRefusal{&agentapi.AppSecretsError{
			Code: "agent_grant_missing",
			Message: fmt.Sprintf("No app named %q is available to this Agent's Workflow (%s). The request below asks for the app by name, "+
				"which must be the app's exact name; the Console answers when the request is filed and may still refuse it, "+
				"for example when there is no such app or the app does not use server-side encryption.", appName, availableApps(data)),
			Request: appAccessRequest(appName, envName, access),
		}}
	}
	target := agentTarget{appID: app.ID, env: envName, appLabel: app.Name, envLabel: envName}
	for _, key := range app.EnvironmentKeys {
		if nameMatches(key.Environment.Name, envName) {
			target.env, target.envLabel = key.Environment.Name, key.Environment.Name
			break
		}
	}
	return target, nil
}

// nameMatches is an exact name match that ignores case.
func nameMatches(name, wanted string) bool {
	return strings.EqualFold(name, wanted)
}

// availableApps names the apps this Agent can use, for a local refusal.
func availableApps(data *misc.AppKeyResponse) string {
	if len(data.Apps) == 0 {
		return "it can use no apps yet"
	}
	names := make([]string, 0, len(data.Apps))
	for _, app := range data.Apps {
		names = append(names, fmt.Sprintf("%q", app.Name))
	}
	return "apps it can use: " + strings.Join(names, ", ")
}

// expiredApp finds an expired grant by app name, matched as granted apps are.
func (b *AgentBackend) expiredApp(appName string) (agentapi.ExpiredAppConnection, bool) {
	for _, candidate := range b.expired {
		if nameMatches(candidate.App.Name, appName) {
			return candidate, true
		}
	}
	return agentapi.ExpiredAppConnection{}, false
}

// ExpiredApps describes, for apps list, each app whose access has ended, with
// the request that asks a member to renew it.
func (b *AgentBackend) ExpiredApps() ([]string, error) {
	if _, err := b.UserData(); err != nil {
		return nil, err
	}
	descriptions := make([]string, 0, len(b.expired))
	for _, expired := range b.expired {
		refusal := &AgentRefusal{&agentapi.AppSecretsError{
			Code: "agent_grant_expired",
			Message: fmt.Sprintf("Access to %s (%s) through %s expired at %s.", expired.App.Name, expired.App.ID,
				expired.ConnectionName, expired.ExpiredAt.UTC().Format(time.RFC3339)),
			Request: renewRequest(expired.ConnectionID, expired.ConnectionName),
		}}
		descriptions = append(descriptions, refusal.Error())
	}
	return descriptions, nil
}

// renewRequest is the request that asks a member to renew an ended grant, in
// the shape the Console sends with its own refusals.
func renewRequest(connectionID, connectionName string) json.RawMessage {
	title := "Renew access to " + connectionName
	if len([]rune(title)) > 120 {
		title = string([]rune(title)[:120])
	}
	payload, err := json.Marshal(map[string]any{
		"kind":  "access_change",
		"title": title,
		"action": map[string]any{
			"type": "agent_grant.renew", "version": 1, "connectionId": connectionID,
		},
	})
	if err != nil {
		return nil
	}
	return payload
}

// NoAppAccessMessage is what apps list says when an Agent has no app access.
const NoAppAccessMessage = "This Agent has no app access yet; access to an app is asked for with a request a member approves (run `phase ai guide app-secrets`)."

// appAccessRequest is the request an Agent sends to ask for an app by name.
func appAccessRequest(appName, envName, access string) json.RawMessage {
	verb := "Read"
	if access == "read_write" {
		verb = "Read and write"
	}
	title := fmt.Sprintf("%s secrets in %s (%s)", verb, appName, envName)
	if len([]rune(title)) > 120 {
		title = string([]rune(title)[:120])
	}
	payload, err := json.Marshal(map[string]any{
		"kind":  "setup",
		"title": title,
		"action": map[string]any{
			"type": "agent_connection.app_access", "version": 1,
			"appName": appName, "environments": []string{envName}, "access": access,
		},
	})
	if err != nil {
		return nil
	}
	return payload
}

func (b *AgentBackend) Get(opts sdk.GetOptions) ([]sdk.SecretResult, error) {
	if opts.LeaseTTL != nil {
		return nil, ErrAgentDynamicSecrets
	}
	target, err := b.target(opts.AppName, opts.EnvName, opts.AppID, "read")
	if err != nil {
		return nil, err
	}
	query := agentapi.AppSecretsQuery{AppID: target.appID, Env: target.env, Path: opts.Path, Raw: opts.Raw}
	if len(opts.Keys) == 1 {
		query.Key = opts.Keys[0]
	}
	ctx, cancel := agentContext()
	defer cancel()
	secrets, err := b.client.ListAppSecrets(ctx, query)
	if err != nil {
		return nil, agentError(err)
	}
	wanted := make(map[string]bool, len(opts.Keys))
	for _, key := range opts.Keys {
		wanted[key] = true
	}
	results := make([]sdk.SecretResult, 0, len(secrets))
	for _, secret := range secrets {
		// Tags and keys are filtered here, as the SDK does, so both logins
		// match the same secrets.
		tags := secret.Tags
		if tags == nil {
			tags = []string{}
		}
		if opts.Tag != "" && !misc.TagMatches(tags, opts.Tag) {
			continue
		}
		if len(wanted) > 0 && !wanted[secret.Key] {
			continue
		}
		result := sdk.SecretResult{
			Key: secret.Key, Value: secret.Value, Comment: secret.Comment, Path: secret.Path, Tags: tags,
			Type: secret.Type, Lifecycle: secret.Lifecycle, Application: target.appLabel, Environment: target.envLabel,
		}
		if result.Path == "" {
			result.Path = "/"
		}
		if result.Type == "" || result.Type == "static" {
			result.Type = sdk.SecretTypeSecret
		}
		if result.Lifecycle == "" {
			result.Lifecycle = sdk.SecretLifecycleStatic
		}
		if secret.ID != "" {
			b.idMu.Lock()
			if b.secretIDs == nil {
				b.secretIDs = map[string]string{}
			}
			b.secretIDs[secretIDKey(result)] = secret.ID
			b.idMu.Unlock()
		}
		results = append(results, result)
	}
	return results, nil
}

func (b *AgentBackend) Create(opts sdk.CreateOptions) error {
	if opts.OverrideValue != "" {
		return ErrAgentOverride
	}
	target, err := b.target(opts.AppName, opts.EnvName, opts.AppID, "read_write")
	if err != nil {
		return err
	}
	path := opts.Path
	if path == "" {
		path = "/"
	}
	writes := make([]agentapi.AppSecretWrite, 0, len(opts.KeyValuePairs))
	for _, pair := range opts.KeyValuePairs {
		value := pair.Value
		secretType := pair.Type
		if secretType == "" {
			secretType = opts.Type
		}
		writes = append(writes, agentapi.AppSecretWrite{Key: pair.Key, Value: &value, Path: path, Type: secretType})
	}
	ctx, cancel := agentContext()
	defer cancel()
	return agentError(b.client.CreateAppSecrets(ctx, target.appID, target.env, writes))
}

// Update finds the secret's ID by key first, as the API names secrets by ID.
func (b *AgentBackend) Update(opts sdk.UpdateOptions) error {
	if opts.Override || opts.ToggleOverride {
		return ErrAgentOverride
	}
	target, err := b.target(opts.AppName, opts.EnvName, opts.AppID, "read_write")
	if err != nil {
		return err
	}
	ctx, cancel := agentContext()
	defer cancel()
	secrets, err := b.client.ListAppSecrets(ctx, agentapi.AppSecretsQuery{
		AppID: target.appID, Env: target.env, Path: opts.SourcePath, Key: opts.Key, Raw: true,
	})
	if err != nil {
		return agentError(err)
	}
	var id string
	for _, secret := range secrets {
		if secret.Key == opts.Key && (opts.SourcePath == "" || secret.Path == opts.SourcePath) {
			id = secret.ID
			break
		}
	}
	if id == "" {
		return &sdk.ErrSecretNotFound{Key: opts.Key, Path: opts.SourcePath}
	}
	write := agentapi.AppSecretWrite{ID: id, Path: opts.DestinationPath, Type: opts.Type}
	if opts.Value != "" {
		value := opts.Value
		write.Value = &value
	}
	return agentError(b.client.UpdateAppSecrets(ctx, target.appID, target.env, []agentapi.AppSecretWrite{write}))
}

// Delete finds each key's ID first and reports the keys it did not find, as
// the SDK does.
func (b *AgentBackend) Delete(opts sdk.DeleteOptions) ([]string, error) {
	target, err := b.target(opts.AppName, opts.EnvName, opts.AppID, "read_write")
	if err != nil {
		return nil, err
	}
	ctx, cancel := agentContext()
	defer cancel()
	secrets, err := b.client.ListAppSecrets(ctx, agentapi.AppSecretsQuery{
		AppID: target.appID, Env: target.env, Path: opts.Path, Raw: true,
	})
	if err != nil {
		return nil, agentError(err)
	}
	var ids, notFound []string
	for _, key := range opts.KeysToDelete {
		found := false
		for _, secret := range secrets {
			if secret.Key == key && (opts.Path == "" || secret.Path == opts.Path) {
				ids, found = append(ids, secret.ID), true
				break
			}
		}
		if !found {
			notFound = append(notFound, key)
		}
	}
	if len(ids) > 0 {
		if err := b.client.DeleteAppSecrets(ctx, target.appID, target.env, ids); err != nil {
			return nil, agentError(err)
		}
	}
	return notFound, nil
}

// resolveNames is ResolveNames for an Agent: the listing it already holds,
// never a cache on disk.
func (b *AgentBackend) resolveNames(appName, envName, appID string) (string, string) {
	if envName == "" {
		envName = "Development"
	}
	target, err := b.target(appName, envName, appID, "read")
	if err != nil {
		return fallbackNames(appName, envName, appID)
	}
	return target.appLabel, target.envLabel
}

// AgentRefusal is a refusal from the Console, printed for the Agent: the
// sentence, and when the Console sent a ready-to-send request, that request
// and how to send it.
type AgentRefusal struct {
	*agentapi.AppSecretsError
}

func (r *AgentRefusal) Unwrap() error { return r.AppSecretsError }

func (r *AgentRefusal) Error() string {
	var out strings.Builder
	out.WriteString(r.Message)
	switch {
	case r.Code == "agent_access_blocked":
		out.WriteString(" A blocked call cannot be requested; tell the human if the task needs it.")
	case r.StatusCode == 429 && r.RetryAfter > 0:
		fmt.Fprintf(&out, " Retry after %d seconds.", int(r.RetryAfter.Round(time.Second)/time.Second))
	}
	if len(r.Request) == 0 {
		return out.String()
	}
	requestsURL := phaseproxy.ControlURL + "/v1/requests"
	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		out.WriteString("\nTo ask a member for it, send this JSON unchanged to POST " + requestsURL +
			", show the human the approvalUrl, and run the command again once the request is approved:\n")
	} else {
		out.WriteString("\nA member can grant it through a request, which is filed from inside a Phase AI session " +
			"(phase ai run, phase ai exec, or a harness set up with phase ai enable). From there, send this JSON unchanged to POST " +
			requestsURL + ":\n")
	}
	out.Write(r.Request)
	return out.String()
}

// agentError presents a Console refusal for the Agent and passes anything
// else through.
func agentError(err error) error {
	var refusal *agentapi.AppSecretsError
	if errors.As(err, &refusal) {
		return &AgentRefusal{refusal}
	}
	return err
}
