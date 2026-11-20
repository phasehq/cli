package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
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
	InjectionPlainHTTP       InjectionErrorCode = "plain_http"
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
	case InjectionPlainHTTP:
		return "Phase sends this Connection's credential only over HTTPS. Use the https:// endpoint."
	default:
		return "credential injection finalizer failed"
	}
}

type InjectionResult struct {
	Action     string
	AWSService string
	AWSRegion  string
}

// ApplyHTTPInjection rewrites an outgoing request with the Connection's live
// credential. Every injection of the Connection is checked first and the
// request is changed only if all of them pass, so it is never half-rewritten.
func ApplyHTTPInjection(ctx context.Context, req *http.Request, connection agentapi.Connection) (InjectionResult, error) {
	return ApplyHTTPInjectionPresenting(ctx, req, connection, connection)
}

// ApplyHTTPInjectionPresenting is ApplyHTTPInjection for a request that
// presents the Agent-visible identifiers and decoys of an earlier generation
// of the same Connection. What the request must carry is read from presented;
// what it is rewritten to always comes from live.
func ApplyHTTPInjectionPresenting(ctx context.Context, req *http.Request, live, presented agentapi.Connection) (InjectionResult, error) {
	if req == nil || req.URL == nil {
		return InjectionResult{}, &InjectionError{Code: InjectionInvalidTemplate}
	}
	injections := live.EffectiveInjections()
	if len(live.Injections) == 0 && injections[0].Action == "aws_sigv4" {
		return applyAWSSigV4(ctx, req, presented)
	}
	// A header-style credential is neither swapped in nor attached on a
	// request that would carry it in the clear, unless the Connection says
	// so. That holds for every HTTP Connection, custom or packaged: the
	// rule follows the payload (an injection that is not request signing),
	// not the service type. AWS request signing keeps its own handling above.
	if !live.AllowPlainHTTP && !strings.EqualFold(req.URL.Scheme, "https") {
		return InjectionResult{}, &InjectionError{Code: InjectionPlainHTTP}
	}
	claimed := make(map[string]struct{}, len(injections))
	rewrites := make([]func(), 0, len(injections))
	for _, injection := range injections {
		rewrite, err := planHTTPInjection(req, injection, live, presented, claimed)
		if err != nil {
			return InjectionResult{}, err
		}
		rewrites = append(rewrites, rewrite)
	}
	for _, rewrite := range rewrites {
		rewrite()
	}
	return InjectionResult{Action: injections[0].Action}, nil
}

// planHTTPInjection checks one injection against the request without touching
// it and returns the rewrite to run once every injection has passed. At its
// injection point a request that carries exactly the decoy form is swapped, a
// request that carries nothing is attached to when the injection allows it,
// and anything else is a swap miss.
// maximumValueFormats bounds the alternate forms of one injection.
const maximumValueFormats = 4

func planHTTPInjection(req *http.Request, injection agentapi.Injection, live, presented agentapi.Connection, claimed map[string]struct{}) (func(), error) {
	invalid := &InjectionError{Code: InjectionInvalidTemplate}
	swapMiss := &InjectionError{Code: InjectionSwapMiss}
	attach := false
	switch injection.WhenAbsent {
	case "", agentapi.WhenAbsentBlock:
	case agentapi.WhenAbsentAttach:
		attach = true
	default:
		return nil, invalid
	}
	// Two injections writing the same place would make the outcome depend on
	// their order.
	claim := func(target string) bool {
		if _, taken := claimed[target]; taken {
			return false
		}
		claimed[target] = struct{}{}
		return true
	}
	switch injection.Action {
	case "remove_header":
		if attach || !safeHeaderName(injection.Name) || injection.ValueFrom.Source != "none" ||
			!claim("header:"+strings.ToLower(injection.Name)) {
			return nil, invalid
		}
		return func() { req.Header.Del(injection.Name) }, nil
	case "basic_auth":
		return planBasicAuth(req, injection, live, presented, attach, claim)
	}
	if injection.ValueFrom.Source != "credential" || injection.ValueFrom.Field == "" {
		return nil, invalid
	}
	liveValue, ok := live.SecretMaterial.Get(injection.ValueFrom.Field)
	if !ok || liveValue == "" {
		return nil, &InjectionError{Code: InjectionMissingMaterial}
	}
	presentedValue, status := agentapi.ResolveMaterial(presented.DecoyMaterial, injection.ValueFrom.Field)
	if status == agentapi.MaterialAmbiguous {
		return nil, &InjectionError{Code: InjectionMissingMaterial}
	}
	if status == agentapi.MaterialMissing {
		presentedValue, status = agentapi.ResolveMaterial(presented.Identifiers, injection.ValueFrom.Field)
	}
	if status != agentapi.MaterialFound || presentedValue == "" {
		return nil, &InjectionError{Code: InjectionMissingMaterial}
	}
	expected, err := formatCredentialValue(injection.ValueFormat, presentedValue)
	if err != nil {
		return nil, err
	}
	replacement, err := formatCredentialValue(injection.ValueFormat, liveValue)
	if err != nil || containsHeaderBreak(replacement) || len(replacement) > maximumInjectionCredentialBytes {
		return nil, &InjectionError{Code: InjectionUnsafeValue}
	}
	// Alternate forms are checked like the primary one, whatever the action,
	// so a malformed one never goes unnoticed. Index 0 is the primary form.
	if len(injection.ValueFormats) > maximumValueFormats {
		return nil, invalid
	}
	expectedForms := []string{expected}
	replacementForms := []string{replacement}
	for _, format := range injection.ValueFormats {
		alternateExpected, formatErr := formatCredentialValue(format, presentedValue)
		if formatErr != nil {
			return nil, formatErr
		}
		alternateReplacement, formatErr := formatCredentialValue(format, liveValue)
		if formatErr != nil || containsHeaderBreak(alternateReplacement) || len(alternateReplacement) > maximumInjectionCredentialBytes {
			return nil, &InjectionError{Code: InjectionUnsafeValue}
		}
		expectedForms = append(expectedForms, alternateExpected)
		replacementForms = append(replacementForms, alternateReplacement)
	}
	// matchedForm returns the index of the form a presented value is in.
	matchedForm := func(presentedForm string) int {
		for index, form := range expectedForms {
			if presentedForm == form {
				return index
			}
		}
		return -1
	}

	switch injection.Action {
	case "set_header", "replace_header":
		if !safeHeaderName(injection.Name) || (attach && !attachableHeaderName(injection.Name)) ||
			!claim("header:"+strings.ToLower(injection.Name)) {
			return nil, invalid
		}
		values := req.Header.Values(injection.Name)
		form := -1
		if len(values) == 1 {
			form = matchedForm(values[0])
		}
		if form < 0 && !(attach && len(values) == 0) {
			return nil, swapMiss
		}
		// A swap is written in the form it was presented in; attaching uses
		// the primary form.
		chosen := replacementForms[max(form, 0)]
		return func() { req.Header.Set(injection.Name, chosen) }, nil
	case "set_param":
		if injection.Name == "" || strings.ContainsAny(injection.Name, "&=\x00") || !claim("param:"+injection.Name) {
			return nil, invalid
		}
		query, parseErr := url.ParseQuery(req.URL.RawQuery)
		values, exists := query[injection.Name]
		form := -1
		if exists && len(values) == 1 {
			form = matchedForm(values[0])
		}
		// A query the proxy cannot fully parse may hide a value for this
		// parameter, so it never counts as carrying nothing.
		if form < 0 && !(attach && !exists && parseErr == nil) {
			return nil, swapMiss
		}
		chosen := replacementForms[max(form, 0)]
		return func() {
			rewritten := req.URL.Query()
			rewritten.Set(injection.Name, chosen)
			req.URL.RawQuery = rewritten.Encode()
		}, nil
	case "set_path":
		if attach || !claim("path") {
			return nil, invalid
		}
		if req.URL.Path != expected || !strings.HasPrefix(replacement, "/") {
			return nil, swapMiss
		}
		return func() { req.URL.Path, req.URL.RawPath = replacement, "" }, nil
	case "replace_path_regex":
		if attach || injection.Pattern == "" || injection.Replacement == "" || !strings.Contains(injection.Replacement, "{value}") ||
			!claim("path") {
			return nil, invalid
		}
		pattern, compileErr := regexp.Compile(injection.Pattern)
		if compileErr != nil || len(pattern.FindAllStringIndex(req.URL.Path, 2)) != 1 || !strings.Contains(req.URL.Path, expected) {
			return nil, swapMiss
		}
		literalReplacement := strings.Replace(injection.Replacement, "{value}", replacement, 1)
		if containsHeaderBreak(literalReplacement) {
			return nil, &InjectionError{Code: InjectionUnsafeValue}
		}
		rewritten := pattern.ReplaceAllStringFunc(req.URL.Path, func(string) string { return literalReplacement })
		return func() { req.URL.Path, req.URL.RawPath = rewritten, "" }, nil
	default:
		return nil, invalid
	}
}

// planBasicAuth handles HTTP Basic authentication. The username is an
// Agent-visible identifier and only the password is secret: the request must
// present username:decoy, and it is rewritten to the live username and
// password. Attaching builds the same header from the identifier and the live
// password.
func planBasicAuth(req *http.Request, injection agentapi.Injection, live, presented agentapi.Connection, attach bool, claim func(string) bool) (func(), error) {
	invalid := &InjectionError{Code: InjectionInvalidTemplate}
	missing := &InjectionError{Code: InjectionMissingMaterial}
	name := injection.Name
	if name == "" {
		name = "Authorization"
	}
	usernameField, usernameStatus := agentapi.ResolveMaterial(injection.ValueFrom.Fields, "username")
	passwordField, passwordStatus := agentapi.ResolveMaterial(injection.ValueFrom.Fields, "password")
	if injection.ValueFrom.Source != "credential" || usernameStatus != agentapi.MaterialFound || passwordStatus != agentapi.MaterialFound ||
		usernameField == "" || passwordField == "" {
		return nil, invalid
	}
	livePassword, ok := live.SecretMaterial.Get(passwordField)
	if !ok || livePassword == "" {
		return nil, missing
	}
	liveUsername, liveStatus := agentapi.ResolveMaterial(live.Identifiers, usernameField)
	presentedUsername, presentedStatus := agentapi.ResolveMaterial(presented.Identifiers, usernameField)
	decoy, decoyStatus := agentapi.ResolveMaterial(presented.DecoyMaterial, passwordField)
	if liveStatus != agentapi.MaterialFound || presentedStatus != agentapi.MaterialFound || decoyStatus != agentapi.MaterialFound ||
		liveUsername == "" || presentedUsername == "" || decoy == "" {
		return nil, missing
	}
	// A colon would move the boundary between username and password.
	if strings.ContainsAny(liveUsername, ":\r\n\x00") || strings.ContainsAny(presentedUsername, ":\r\n\x00") {
		return nil, &InjectionError{Code: InjectionUnsafeValue}
	}
	replacement := "Basic " + base64.StdEncoding.EncodeToString([]byte(liveUsername+":"+livePassword))
	if len(replacement) > maximumInjectionCredentialBytes {
		return nil, &InjectionError{Code: InjectionUnsafeValue}
	}
	if !safeHeaderName(name) || (attach && !attachableHeaderName(name)) || !claim("header:"+strings.ToLower(name)) {
		return nil, invalid
	}
	values := req.Header.Values(name)
	swap := false
	if len(values) == 1 {
		scheme, encoded, found := strings.Cut(values[0], " ")
		if found && strings.EqualFold(scheme, "Basic") {
			decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
			swap = decodeErr == nil && string(decoded) == presentedUsername+":"+decoy
		}
	}
	if !swap && !(attach && len(values) == 0) {
		return nil, &InjectionError{Code: InjectionSwapMiss}
	}
	return func() { req.Header.Set(name, replacement) }, nil
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

// attachableHeaderName refuses the framing and hop-by-hop headers the proxy
// strips from every forwarded request. A decoy can never be presented in one,
// so a swap already misses there; a credential must not be attached to one
// either.
func attachableHeaderName(name string) bool {
	for _, reserved := range []string{"Transfer-Encoding", "Proxy-Connection", "Upgrade", "TE", "Trailer", "Keep-Alive", "Proxy-Authenticate"} {
		if strings.EqualFold(name, reserved) {
			return false
		}
	}
	return true
}

func containsHeaderBreak(value string) bool { return strings.ContainsAny(value, "\r\n\x00") }
