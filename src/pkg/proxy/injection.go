package proxy

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

const maximumInjectionCredentialBytes = 1 << 20

type InjectionErrorCode string

const (
	InjectionInvalidTemplate InjectionErrorCode = "invalid_template"
	InjectionSwapMiss        InjectionErrorCode = "swap_miss"
	InjectionMissingMaterial InjectionErrorCode = "missing_material"
	InjectionUnsafeValue     InjectionErrorCode = "unsafe_value"
	InjectionFinalizerFailed InjectionErrorCode = "finalizer_failed"
)

type InjectionError struct {
	Code            InjectionErrorCode
	AWSSigV4Failure AWSSigV4Failure
}

func (e *InjectionError) Error() string {
	switch e.Code {
	case InjectionInvalidTemplate:
		return "credential injection template is invalid"
	case InjectionSwapMiss:
		return "credential decoy was not presented at the configured injection point"
	case InjectionMissingMaterial:
		return "proxy-only credential material is unavailable"
	case InjectionUnsafeValue:
		return "credential injection value is unsafe"
	default:
		return "credential injection finalizer failed"
	}
}

type InjectionResult struct {
	Action     string
	AWSService string
	AWSRegion  string
}

func ApplyHTTPInjection(ctx context.Context, req *http.Request, connection agentapi.Connection) (InjectionResult, error) {
	if req == nil || req.URL == nil {
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	injection := connection.Injection
	if injection.Action == "aws_sigv4" {
		return applyAWSSigV4(ctx, req, connection)
	}
	if injection.Action == "remove_header" {
		if !safeHeaderName(injection.Name) || injection.ValueFrom.Source != "none" {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
		req.Header.Del(injection.Name)
		return InjectionResult{Action: injection.Action}, nil
	}
	if injection.ValueFrom.Source != "credential" || injection.ValueFrom.Field == "" {
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	live, ok := connection.SecretMaterial.Get(injection.ValueFrom.Field)
	if !ok || live == "" {
		return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
	}
	presented, status := agentapi.ResolveMaterial(connection.DecoyMaterial, injection.ValueFrom.Field)
	if status == agentapi.MaterialAmbiguous {
		return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
	}
	if status == agentapi.MaterialMissing {
		presented, status = agentapi.ResolveMaterial(connection.Identifiers, injection.ValueFrom.Field)
	}
	if status != agentapi.MaterialFound || presented == "" {
		return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
	}
	expected, err := formatCredentialValue(injection.ValueFormat, presented)
	if err != nil {
		return InjectionResult{}, err
	}
	replacement, err := formatCredentialValue(injection.ValueFormat, live)
	if err != nil || containsHeaderBreak(replacement) {
		return InjectionResult{}, &InjectionError{Code: InjectionUnsafeValue}
	}

	switch injection.Action {
	case "set_header", "replace_header":
		if !safeHeaderName(injection.Name) {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
		values := req.Header.Values(injection.Name)
		if len(values) != 1 || values[0] != expected {
			return InjectionResult{}, &InjectionError{Code: InjectionSwapMiss}
		}
		req.Header.Set(injection.Name, replacement)
	case "set_param":
		if injection.Name == "" || strings.ContainsAny(injection.Name, "&=\x00") {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
		query := req.URL.Query()
		values, exists := query[injection.Name]
		if !exists || len(values) != 1 || values[0] != expected {
			return InjectionResult{}, &InjectionError{Code: InjectionSwapMiss}
		}
		query.Set(injection.Name, replacement)
		req.URL.RawQuery = query.Encode()
	case "set_path":
		if req.URL.Path != expected || !strings.HasPrefix(replacement, "/") {
			return InjectionResult{}, &InjectionError{Code: InjectionSwapMiss}
		}
		req.URL.Path, req.URL.RawPath = replacement, ""
	case "replace_path_regex":
		if injection.Pattern == "" || injection.Replacement == "" || !strings.Contains(injection.Replacement, "{value}") {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
		pattern, compileErr := regexp.Compile(injection.Pattern)
		if compileErr != nil || len(pattern.FindAllStringIndex(req.URL.Path, 2)) != 1 || !strings.Contains(req.URL.Path, expected) {
			return InjectionResult{}, &InjectionError{Code: InjectionSwapMiss}
		}
		literalReplacement := strings.Replace(injection.Replacement, "{value}", replacement, 1)
		if containsHeaderBreak(literalReplacement) {
			return InjectionResult{}, &InjectionError{Code: InjectionUnsafeValue}
		}
		req.URL.Path = pattern.ReplaceAllStringFunc(req.URL.Path, func(string) string { return literalReplacement })
		req.URL.RawPath = ""
	default:
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	return InjectionResult{Action: injection.Action}, nil
}

func applyAWSSigV4(ctx context.Context, req *http.Request, connection agentapi.Connection) (InjectionResult, error) {
	fields := connection.Injection.ValueFrom.Fields
	accessField, accessStatus := roleField(fields, "accessKeyId", "access_key_id")
	secretField, secretStatus := roleField(fields, "secretAccessKey", "secret_access_key")
	if accessStatus != agentapi.MaterialFound || secretStatus != agentapi.MaterialFound ||
		accessField == "" || secretField == "" || connection.Injection.ValueFrom.Source != "credential" {
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	expectedAccessKey, ok := agentapi.LookupMaterial(connection.Identifiers, accessField)
	if !ok || expectedAccessKey == "" {
		return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
	}
	liveAccessKey, accessOK := connection.SecretMaterial.Get(accessField)
	liveSecret, secretOK := connection.SecretMaterial.Get(secretField)
	if !accessOK || !secretOK {
		return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
	}
	sessionToken := ""
	tokenField, tokenFieldStatus := roleField(fields, "sessionToken", "session_token")
	if tokenFieldStatus == agentapi.MaterialAmbiguous {
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	if tokenFieldStatus == agentapi.MaterialFound {
		if tokenField == "" {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
		var tokenStatus agentapi.MaterialLookupStatus
		sessionToken, tokenStatus = connection.SecretMaterial.Resolve(tokenField)
		if tokenStatus == agentapi.MaterialAmbiguous {
			return InjectionResult{}, &InjectionError{Code: InjectionMissingMaterial}
		}
		if tokenStatus == agentapi.MaterialFound && !validOptionalAWSSessionToken(sessionToken) {
			return InjectionResult{}, &InjectionError{Code: InjectionUnsafeValue}
		}
		// A configured session-token role is optional in live AWS material.
		// Long-lived access keys omit it even though the agent always signs with
		// the decoy token supplied in its environment. Re-signing with an empty
		// live token removes that decoy header and signed-header entry.
		if tokenStatus == agentapi.MaterialMissing {
			sessionToken = ""
		}
	}
	options := AWSSigV4Options{ExpectedAccessKeyID: expectedAccessKey}
	if connection.Injection.ServiceFrom == "config" {
		options.ExpectedService, _ = stringConfig(connection.ConnectionConfig, "service")
		if options.ExpectedService == "" {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
	}
	if connection.Injection.RegionFrom == "config" {
		options.ExpectedRegion, _ = stringConfig(connection.ConnectionConfig, "region")
		if options.ExpectedRegion == "" {
			return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
		}
	}
	result, err := ResignAWSSigV4(ctx, req, AWSCredentials{
		AccessKeyID: liveAccessKey, SecretAccessKey: liveSecret, SessionToken: sessionToken,
	}, options)
	if err != nil {
		injectionErr := &InjectionError{Code: InjectionFinalizerFailed}
		var sigV4Err *AWSSigV4Error
		if errors.As(err, &sigV4Err) {
			injectionErr.AWSSigV4Failure = sigV4Err.Failure
		}
		return InjectionResult{}, injectionErr
	}
	return InjectionResult{Action: "aws_sigv4", AWSService: result.Service, AWSRegion: result.Region}, nil
}

// SanitizeAWSSigV4Response derives safe replacements from the same credential
// mapping used for request injection, then prevents every proxy-only live value
// from crossing back into the Agent process.
func SanitizeAWSSigV4Response(response *http.Response, connection agentapi.Connection) error {
	if connection.Injection.Action != "aws_sigv4" || connection.Injection.ValueFrom.Source != "credential" {
		return &InjectionError{Code: InjectionInvalidTemplate}
	}
	accessField, status := roleField(connection.Injection.ValueFrom.Fields, "accessKeyId", "access_key_id")
	if status != agentapi.MaterialFound || accessField == "" {
		return &InjectionError{Code: InjectionInvalidTemplate}
	}
	agentAccessKeyID, agentStatus := agentapi.ResolveMaterial(connection.Identifiers, accessField)
	liveAccessKeyID, liveStatus := connection.SecretMaterial.Resolve(accessField)
	if agentStatus != agentapi.MaterialFound || liveStatus != agentapi.MaterialFound ||
		agentAccessKeyID == "" || liveAccessKeyID == "" {
		return &InjectionError{Code: InjectionMissingMaterial}
	}
	unsafeValues := agentapi.ProxyOnlyCredentialValues([]agentapi.Connection{connection})
	unsafe := make(map[string]struct{}, len(unsafeValues))
	for _, value := range unsafeValues {
		unsafe[value] = struct{}{}
	}
	const redacted = "PHASE_REDACTED_CREDENTIAL"
	replacementIsSafe := func(value string) bool {
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
		for _, live := range unsafeValues {
			if strings.Contains(value, live) {
				return false
			}
		}
		return true
	}
	redactionsByLive := make(map[string]string, len(unsafeValues))
	for field, live := range connection.SecretMaterial.Clone() {
		if _, proxyOnly := unsafe[live]; !proxyOnly {
			continue
		}
		replacement := ""
		if live == liveAccessKeyID {
			replacement = agentAccessKeyID
		} else if candidate, status := agentapi.ResolveMaterial(connection.DecoyMaterial, field); status == agentapi.MaterialFound {
			replacement = candidate
		} else if candidate, status := agentapi.ResolveMaterial(connection.Identifiers, field); status == agentapi.MaterialFound {
			replacement = candidate
		}
		if !replacementIsSafe(replacement) {
			replacement = redacted
		}
		if !replacementIsSafe(replacement) {
			return &InjectionError{Code: InjectionUnsafeValue}
		}
		if existing, found := redactionsByLive[live]; found && existing != replacement {
			redactionsByLive[live] = redacted
		} else {
			redactionsByLive[live] = replacement
		}
	}
	redactions := make([]CredentialRedaction, 0, len(unsafeValues))
	for _, live := range unsafeValues {
		replacement, found := redactionsByLive[live]
		if !found {
			replacement = redacted
		}
		if !replacementIsSafe(replacement) {
			return &InjectionError{Code: InjectionUnsafeValue}
		}
		redactions = append(redactions, CredentialRedaction{Live: live, AgentVisible: replacement})
	}
	if err := RedactAWSSigV4Response(response, redactions); err != nil {
		return &InjectionError{Code: InjectionUnsafeValue}
	}
	return nil
}

func validOptionalAWSSessionToken(value string) bool {
	if len(value) > maximumInjectionCredentialBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < ' ' || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func roleField(fields map[string]string, names ...string) (string, agentapi.MaterialLookupStatus) {
	for _, name := range names {
		value, status := agentapi.ResolveMaterial(fields, name)
		if status != agentapi.MaterialMissing {
			return value, status
		}
	}
	return "", agentapi.MaterialMissing
}

func stringConfig(values map[string]any, key string) (string, bool) {
	value, ok := values[key].(string)
	return value, ok
}

func formatCredentialValue(format, value string) (string, error) {
	if strings.Count(format, "{value}") != 1 {
		return "", &InjectionError{Code: InjectionInvalidTemplate}
	}
	result := strings.Replace(format, "{value}", value, 1)
	if strings.ContainsRune(result, '\x00') {
		return "", &InjectionError{Code: InjectionUnsafeValue}
	}
	return result, nil
}

func safeHeaderName(name string) bool {
	if name == "" || strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") ||
		strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Connection") {
		return false
	}
	for _, character := range name {
		if character <= 32 || character >= 127 || strings.ContainsRune("()<>@,;:\\[]?={}\t", character) {
			return false
		}
	}
	return true
}

func containsHeaderBreak(value string) bool { return strings.ContainsAny(value, "\r\n\x00") }
