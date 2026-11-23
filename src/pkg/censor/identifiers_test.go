package censor

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"regexp"
	"strings"
	"testing"
)

const (
	base64URL    = alnum + "-_"
	base64Std    = alnum + "+/"
	lowerHex     = "0123456789abcdef"
	mixedHex     = "0123456789abcdefABCDEF"
	upperDigits  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowerDigits  = "abcdefghijklmnopqrstuvwxyz0123456789"
	asciiLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	decimal      = "0123456789"
)

// fresh builds a made-up token, again if chance put an ignore-list word such
// as "dummy" in it. Every token in these tests is random and built from pieces
// at run time, so no file holds anything shaped like a live credential.
func fresh(t testing.TB, build func() string) string {
	t.Helper()
	for {
		if token := build(); !DefaultRules().ignored([]byte(token), false) {
			return token
		}
	}
}

func checksummed(t testing.TB, prefix string) string {
	return fresh(t, func() string {
		body := randomString(t, alnum, 30)
		return prefix + body + base62(crc32.ChecksumIEEE([]byte(body)), 6)
	})
}

// pypiMacaroonToken is shaped as PyPI makes them: a version 2 macaroon for
// pypi.org with an identifier, one caveat and a signature, in base64url.
func pypiMacaroonToken(t testing.TB) string {
	return fresh(t, func() string {
		raw := []byte(pypiMacaroonHeader)
		identifier := randomString(t, lowerHex, 36)
		raw = append(append(raw, 2, byte(len(identifier))), identifier...)
		caveat := `{"permissions": "user", "version": 1}`
		raw = append(append(append(raw, 0, 2, byte(len(caveat))), caveat...), 0, 0)
		signature := make([]byte, 32)
		if _, err := rand.Read(signature); err != nil {
			t.Fatal(err)
		}
		raw = append(append(raw, 6, byte(len(signature))), signature...)
		return "pypi-" + base64.RawURLEncoding.EncodeToString(raw)
	})
}

func installationToken(t testing.TB) string {
	segment := func(value any) string {
		encoded, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	return fresh(t, func() string {
		return "ghs_" + randomString(t, decimal, 7) + "_" + segment(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
			segment(map[string]any{"iss": "github", "installation_id": 48213377, "exp": 1798761600}) + "." + randomString(t, base64URL, 342)
	})
}

type formatSample struct {
	text   string // what is scanned
	secret string // the part of it that must be replaced
	score  int    // when the text earns another score than the case's, as after a keyword
}

// formatCase is what one rule must do: replace its positives, and leave its
// near-misses and its documentation or test-mode values exactly as they were.
// A rule that only alerts reports its positives and leaves them as they were.
type formatCase struct {
	rule, label string
	score       int  // of every positive
	alert       bool // the rule never replaces
	positives   []formatSample
	nearMisses  map[string]string
	examples    map[string]string
}

func inText(token string) formatSample {
	return formatSample{text: "the value is " + token + " here", secret: token}
}

func after(name, token string) formatSample {
	return formatSample{text: name + token, secret: token}
}

func formatCases(t testing.TB) []formatCase {
	random := func(alphabet string, n int) string { return randomString(t, alphabet, n) }
	token := func(build func() string) string { return fresh(t, build) }
	x := func(n int) string { return strings.Repeat("x", n) }
	zeros := func(n int) string { return strings.Repeat("0", n) }
	plain := func(text string) string { return "the value is " + text + " here" }

	anthropic := func(kind string) string {
		return token(func() string { return "sk-" + "ant-" + kind + "-" + random(base64URL, 93) + "AA" })
	}
	const marker = "T3Blbk" + "FJ"
	openai := func(kind string, n int) string {
		return token(func() string { return "sk-" + kind + "-" + random(base64URL, n) + marker + random(base64URL, n) })
	}
	legacyOpenAI := token(func() string { return "sk-" + random(alnum, 20) + marker + random(alnum, 20) })
	openrouter := token(func() string { return "sk-" + "or-v1-" + random(lowerHex, 64) })
	google := token(func() string { return "AI" + "za" + random(base64URL, 35) })
	gitlab := token(func() string { return "glpat" + "-" + random(base64URL, 20) })
	routable := token(func() string { return "glpat" + "-" + random(base64URL, 40) + "." + random(lowerDigits, 9) })
	huggingface := token(func() string { return "hf" + "_" + random(asciiLetters, 34) })
	slackApp := token(func() string {
		return "xapp" + "-1-A" + random(upperDigits, 10) + "-" + random(decimal, 13) + "-" + random(lowerHex, 64)
	})
	hookPath := token(func() string {
		return "T" + random(upperDigits, 10) + "/B" + random(upperDigits, 10) + "/" + random(alnum, 24)
	})
	const hooks = "https://hooks.slack.com/services/"
	sendgrid := token(func() string { return "SG" + "." + random(base64URL, 22) + "." + random(base64URL, 43) })
	telegram := token(func() string { return random("123456789", 1) + random(decimal, 9) + ":AA" + random(base64URL, 33) })
	webhookSecret := token(func() string { return "whsec" + "_" + random(alnum, 32) })
	restricted := token(func() string { return "rk_" + "live_" + random(alnum, 32) })
	databricks := token(func() string { return "dapi" + random(lowerHex, 32) })
	linear := token(func() string { return "lin_" + "api_" + random(alnum, 40) })
	supabase := token(func() string { return "sbp" + "_" + random(lowerHex, 40) })
	postman := token(func() string { return "PMAK" + "-" + random(lowerHex, 24) + "-" + random(lowerHex, 34) })
	sentryUser := token(func() string { return "sntryu" + "_" + random(lowerHex, 64) })
	sentryPayload := base64.StdEncoding.EncodeToString([]byte(`{"iat":1763548800.123456,"url":"https://sentry.io","region_url":"https://us.sentry.io","org":"orders"}`))
	sentryOrg := token(func() string { return "sntrys" + "_" + sentryPayload + "_" + random(base64Std, 43) })
	azure := token(func() string { return random(base64Std, 86) + "==" })
	// The storage emulator's account key, which every Azure developer has seen.
	emulatorKey := "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50u" + "SRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	secretWords := token(func() string { return random(asciiLetters, 12) + "-" + random(asciiLetters, 12) })
	imageTagText := "2024.11." + random("123456789", 1) + random(decimal, 1) + "-build." + random(decimal, 4)
	awsID := token(func() string { return "AKIA" + random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) })
	npmrc := checksummed(t, "npm_")

	cases := []formatCase{
		{
			rule: "aws-access-key-id", label: "aws_access_key_id", score: 80,
			positives:  []formatSample{inText(awsID)},
			nearMisses: map[string]string{"15 characters": plain("AKIA" + random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 15)), "17 characters": plain(awsID + "Q")},
			examples:   map[string]string{"AWS's documented key id": plain("AKIAIOSFODNN7" + "EXAMPLE")},
		},
		{
			rule: "anthropic-api-key", label: "anthropic_api_key", score: 60,
			positives: []formatSample{inText(anthropic("api03")), inText(anthropic("admin01"))},
			nearMisses: map[string]string{
				"92 characters":   plain("sk-" + "ant-api03-" + random(base64URL, 92) + "AA"),
				"no AA at an end": plain("sk-" + "ant-api03-" + random(base64URL, 93) + "AB"),
				"no kind":         plain("sk-" + "ant-" + random(base64URL, 93) + "AA"),
			},
			examples: map[string]string{"placeholder": plain("sk-" + "ant-api03-" + x(93) + "AA")},
		},
		{
			rule: "openai-api-key", label: "openai_api_key", score: 60,
			positives: []formatSample{inText(openai("proj", 74)), inText(openai("svcacct", 58)), inText(openai("admin", 74)), inText(openai("proj", 20)), inText(openai("svcacct", 43))},
			nearMisses: map[string]string{
				"no marker":        plain("sk-" + "proj-" + random(base64URL, 156)),
				"19 after marker":  plain("sk-" + "proj-" + random(base64URL, 74) + marker + random(base64URL, 19)),
				"75 after marker":  plain("sk-" + "proj-" + random(base64URL, 74) + marker + random(base64URL, 75)),
				"19 before marker": plain("sk-" + "proj-" + random(alnum, 19) + marker + random(base64URL, 74)),
				"another kind":     plain("sk-" + "team-" + random(alnum, 74) + marker + random(alnum, 74)),
			},
			examples: map[string]string{"placeholder": plain("sk-" + "proj-" + x(74) + marker + x(74))},
		},
		{
			rule: "openai-legacy-api-key", label: "openai_api_key", score: 60,
			positives: []formatSample{inText(legacyOpenAI)},
			nearMisses: map[string]string{
				"19 before marker": plain("sk-" + random(alnum, 19) + marker + random(alnum, 20)),
				"21 after marker":  plain(legacyOpenAI + "Q"),
				"no marker":        plain("sk-" + random(alnum, 48)),
				"a CSS class":      ".sk-" + random("abcdefghijklmnopqrstuvwxyz", 20) + marker + "{color:red}",
			},
			examples: map[string]string{"placeholder": plain("sk-" + x(20) + marker + x(20))},
		},
		{
			rule: "openrouter-api-key", label: "openrouter_api_key", score: 60,
			positives:  []formatSample{inText(openrouter)},
			nearMisses: map[string]string{"63 characters": plain(openrouter[:len(openrouter)-1]), "65 characters": plain(openrouter + "0"), "not hex": plain("sk-" + "or-v1-" + random(lowerHex, 63) + "g")},
			examples:   map[string]string{"one repeated character": plain("sk-" + "or-v1-" + zeros(64))},
		},
		{
			// Replaced under a name that says Gemini or Google AI, and only there:
			// TestGoogleKeysAreReportedUnlessTheNameSaysGemini has the other names.
			rule: "google-api-key", label: "google_api_key", score: 70,
			positives: []formatSample{
				after("GEMINI_API_KEY=", google),
				{text: `export GOOGLE_API_KEY="` + google + `"`, secret: google},
				{text: `curl -H "x-goog-api-key: ` + google + `" https://example.com/v1beta/models`, secret: google},
				{text: `genai.configure(api_key="` + google + `")`, secret: google},
			},
			nearMisses: map[string]string{"34 characters": plain(google[:len(google)-1]), "36 characters": plain(google + "Q"), "inside a word": plain("x" + google)},
			examples:   map[string]string{"placeholder": plain("AI" + "za" + strings.Repeat("X", 35))},
		},
		{
			rule: "github-classic-token", label: "github_token", score: 80,
			positives: []formatSample{inText(checksummed(t, "gho_")), inText(checksummed(t, "ghu_")), inText(checksummed(t, "ghs_")), inText(checksummed(t, "ghr_")), inText(checksummed(t, "ghp_"))},
			nearMisses: map[string]string{
				"35 characters":      plain("gho_" + random(alnum, 35)),
				"37 characters":      plain("ghu_" + random(alnum, 37)),
				"another prefix":     plain("ghx_" + random(alnum, 36)),
				"an underscore in":   plain("ghs_" + random(alnum, 20) + "_" + random(alnum, 15)),
				"inside an identity": plain("x" + checksummed(t, "ghp_")),
			},
			examples: map[string]string{
				"the documentation's token": plain("ghu_" + "16C7e42F292c69" + "12E7710c838347Ae178B4a"),
				"placeholder":               plain("ghp_" + x(36)),
				"one repeated character":    plain("gho_" + strings.Repeat("A", 36)),
			},
		},
		{
			rule: "github-installation-token", label: "github_token", score: 60,
			positives: []formatSample{inText(installationToken(t))},
			nearMisses: map[string]string{
				"no signature": plain("ghs_" + random(decimal, 7) + "_eyJ" + random(base64URL, 30) + ".eyJ" + random(base64URL, 80)),
				"no app id":    plain("ghs__eyJ" + random(base64URL, 30) + ".eyJ" + random(base64URL, 80) + "." + random(base64URL, 86)),
			},
			examples: map[string]string{"the documentation's shape": plain("ghs_APPID_JWT"), "placeholder": plain("ghs_0000000_eyJ" + x(30) + ".eyJ" + x(80) + "." + x(86))},
		},
		{
			rule: "gitlab-token", label: "gitlab_token", score: 60,
			positives:  []formatSample{inText(gitlab), {text: "git clone https://deploy:" + gitlab + "@gitlab.com/acme/orders.git", secret: gitlab}},
			nearMisses: map[string]string{"19 characters": plain(gitlab[:len(gitlab)-1]), "25 characters": plain(gitlab + random(alnum, 5))},
			examples:   map[string]string{"placeholder": plain("glpat" + "-" + x(20))},
		},
		{
			rule: "gitlab-routable-token", label: "gitlab_token", score: 60,
			positives:  []formatSample{inText(routable)},
			nearMisses: map[string]string{"8 after the dot": plain(routable[:len(routable)-1]), "26 before the dot": plain("glpat" + "-" + random(alnum, 26) + "." + random(lowerDigits, 9))},
			examples:   map[string]string{"placeholder": plain("glpat" + "-" + x(40) + "." + x(9))},
		},
		{
			rule: "npm-token", label: "npm_token", score: 80,
			positives:  []formatSample{inText(checksummed(t, "npm_")), {text: "//registry.npmjs.org/:_authToken=" + npmrc, secret: npmrc, score: 110}},
			nearMisses: map[string]string{"35 characters": plain("npm_" + random(alnum, 35)), "37 characters": plain("npm_" + random(alnum, 37)), "an npm variable": "npm_config_user_agent=npm/10.8.2 node/v22.4.1 npm_package_json=/repo/package.json"},
			examples:   map[string]string{"placeholder": plain("npm_" + x(36))},
		},
		{
			rule: "pypi-token", label: "pypi_token", score: 80,
			positives:  []formatSample{inText(pypiMacaroonToken(t))},
			nearMisses: map[string]string{"49 after the header": plain("pypi-" + "AgEIcHlwaS5vcmc" + random(alnum, 49)), "another index": plain("pypi-" + "AgEIdGVzdC5weXBp" + random(alnum, 120))},
			examples:   map[string]string{"placeholder": plain("pypi-" + "AgEIcHlwaS5vcmc" + x(80))},
		},
		{
			rule: "huggingface-token", label: "huggingface_token", score: 60,
			positives:  []formatSample{inText(huggingface)},
			nearMisses: map[string]string{"33 letters": plain(huggingface[:len(huggingface)-1]), "35 letters": plain(huggingface + "q"), "a digit in it": plain("hf_" + random(asciiLetters, 20) + "7" + random(asciiLetters, 13)), "a function name": "path = hf_hub_download(repo_id=model, filename=name)"},
			examples:   map[string]string{"placeholder": plain("hf_" + x(34))},
		},
		{
			rule: "slack-app-token", label: "slack_app_token", score: 60,
			positives:  []formatSample{inText(slackApp)},
			nearMisses: map[string]string{"31 at the end": plain("xapp" + "-1-A" + random(upperDigits, 10) + "-" + random(decimal, 13) + "-" + random(lowerHex, 31)), "no app id": plain("xapp" + "-1-" + random(decimal, 13) + "-" + random(lowerHex, 64))},
			examples:   map[string]string{"placeholder": plain("xapp" + "-1-A0000000000-0000000000000-" + x(64))},
		},
		{
			rule: "slack-webhook", label: "slack_webhook", score: 60,
			positives: []formatSample{{text: "curl -X POST " + hooks + hookPath + " -d '{}'", secret: hookPath}, {text: "webhook: hooks.slack.com/services/" + hookPath, secret: hookPath}},
			nearMisses: map[string]string{
				"23 at the end":  plain(hooks + hookPath[:len(hookPath)-1]),
				"25 at the end":  plain(hooks + hookPath + "Q"),
				"another host":   plain("https://hooks.example.com/services/" + hookPath),
				"a workflow URL": plain("https://hooks.slack.com/workflows/" + hookPath),
			},
			examples: map[string]string{"Slack's documented URL": plain(hooks + "T00000000/B00000000/" + strings.Repeat("X", 24))},
		},
		{
			rule: "sendgrid-api-key", label: "sendgrid_api_key", score: 60,
			positives:  []formatSample{inText(sendgrid)},
			nearMisses: map[string]string{"42 at the end": plain(sendgrid[:len(sendgrid)-1]), "44 at the end": plain(sendgrid + "Q"), "21 in the middle": plain("SG" + "." + random(alnum, 21) + "." + random(alnum, 43)), "a method call": "logger.info(MSG.format(name, value)); SG.send(message, callback)"},
			examples:   map[string]string{"placeholder": plain("SG" + "." + x(22) + "." + x(43))},
		},
		{
			rule: "telegram-bot-token", label: "telegram_bot_token", score: 70,
			positives:  []formatSample{after("TELEGRAM_BOT_TOKEN=", telegram), after(`bot = telebot.TeleBot(token="`, telegram)},
			nearMisses: map[string]string{"no keyword": plain(telegram), "no keyword, in a log": "bot " + telegram + " started polling"},
			examples:   map[string]string{"the documentation's token": "TELEGRAM_BOT_TOKEN=123456:" + "ABC-DEF1234ghIkl-zyx57W2v1u123ew11"},
		},
		{
			rule: "telegram-bot-url", label: "telegram_bot_token", score: 60,
			positives:  []formatSample{{text: "curl https://api.telegram.org/bot" + telegram + "/getMe", secret: telegram}, {text: "https://api.telegram.org/file/bot" + telegram + "/photos/file_1.jpg", secret: telegram}},
			nearMisses: map[string]string{"34 characters": plain("https://api.telegram.org/bot" + telegram[:len(telegram)-1] + "/getMe"), "a short id": plain("https://api.telegram.org/bot1234567:AA" + random(alnum, 33) + "/getMe"), "another host": plain("https://api.example.org/bot" + telegram + "/getMe")},
			examples:   map[string]string{"the documentation's URL": plain("https://api.telegram.org/bot123456:" + "ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe")},
		},
		{
			rule: "stripe-live-key", label: "stripe_key", score: 60,
			positives:  []formatSample{inText(restricted)},
			nearMisses: map[string]string{"19 characters": plain("rk_" + "live_" + random(alnum, 19) + ".")},
			examples: map[string]string{
				"test secret key":      "STRIPE_SECRET_KEY=sk_" + "test_" + random(alnum, 24),
				"Stripe's own test":    "stripe.api_key = \"sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc\"",
				"test restricted key":  "STRIPE_API_KEY=rk_" + "test_" + random(alnum, 24),
				"publishable key":      "stripe_api_key: pk_" + "live_" + random(alnum, 24),
				"test publishable key": "STRIPE_API_KEY=pk_" + "test_" + random(alnum, 24),
			},
		},
		{
			rule: "stripe-webhook-secret", label: "stripe_webhook_secret", score: 60,
			positives:  []formatSample{inText(webhookSecret)},
			nearMisses: map[string]string{"31 characters": plain(webhookSecret[:len(webhookSecret)-1]), "65 characters": plain("whsec" + "_" + random(alnum, 65))},
			examples:   map[string]string{"placeholder": plain("whsec" + "_" + x(32))},
		},
		{
			rule: "digitalocean-token", label: "digitalocean_token", score: 60,
			positives:  []formatSample{inText(token(func() string { return "dop" + "_v1_" + random(lowerHex, 64) })), inText(token(func() string { return "doo" + "_v1_" + random(lowerHex, 64) })), inText(token(func() string { return "dor" + "_v1_" + random(lowerHex, 64) }))},
			nearMisses: map[string]string{"63 characters": plain("dop" + "_v1_" + random(lowerHex, 63)), "65 characters": plain("dop" + "_v1_" + random(lowerHex, 65)), "another kind": plain("dox" + "_v1_" + random(lowerHex, 64))},
			examples:   map[string]string{"one repeated character": plain("dop" + "_v1_" + zeros(64))},
		},
		{
			rule: "shopify-token", label: "shopify_token", score: 60,
			positives:  []formatSample{inText(token(func() string { return "shpat" + "_" + random(mixedHex, 32) })), inText(token(func() string { return "shpss" + "_" + random(lowerHex, 32) })), inText(token(func() string { return "shpca" + "_" + random(lowerHex, 32) })), inText(token(func() string { return "shppa" + "_" + random(lowerHex, 32) }))},
			nearMisses: map[string]string{"31 characters": plain("shpat" + "_" + random(lowerHex, 31)), "33 characters": plain("shpat" + "_" + random(lowerHex, 33)), "another kind": plain("shpxx" + "_" + random(lowerHex, 32))},
			examples:   map[string]string{"one repeated character": plain("shpat" + "_" + zeros(32))},
		},
		{
			rule: "databricks-token", label: "databricks_token", score: 60,
			positives:  []formatSample{inText(databricks), inText(databricks + "-2")},
			nearMisses: map[string]string{"31 characters": plain(databricks[:len(databricks)-1]), "33 characters": plain(databricks + "0"), "inside a word": plain("vdapi" + random(lowerHex, 32))},
			examples:   map[string]string{"one repeated character": plain("dapi" + zeros(32))},
		},
		{
			rule: "linear-api-key", label: "linear_api_key", score: 60,
			positives:  []formatSample{inText(linear)},
			nearMisses: map[string]string{"39 characters": plain(linear[:len(linear)-1]), "41 characters": plain(linear + "Q")},
			examples:   map[string]string{"placeholder": plain("lin_" + "api_" + x(40))},
		},
		{
			rule: "supabase-token", label: "supabase_token", score: 60,
			positives:  []formatSample{inText(supabase)},
			nearMisses: map[string]string{"39 characters": plain(supabase[:len(supabase)-1]), "41 characters": plain(supabase + "0")},
			examples:   map[string]string{"one repeated character": plain("sbp" + "_" + zeros(40)), "placeholder": plain("sbp" + "_" + x(40))},
		},
		{
			rule: "vault-token", label: "vault_token", score: 60,
			positives:  []formatSample{inText(token(func() string { return "hvs" + "." + random(base64URL, 95) })), inText(token(func() string { return "hvb" + "." + random(base64URL, 140) }))},
			nearMisses: map[string]string{"89 characters": plain("hvs" + "." + random(alnum, 89)), "137 characters of a batch token": plain("hvb" + "." + random(alnum, 137)), "inside a word": plain("x" + "hvs" + "." + random(alnum, 95))},
			examples:   map[string]string{"placeholder": plain("hvs" + "." + x(95))},
		},
		{
			rule: "postman-api-key", label: "postman_api_key", score: 60,
			positives:  []formatSample{inText(postman)},
			nearMisses: map[string]string{"33 at the end": plain(postman[:len(postman)-1]), "23 in the middle": plain("PMAK" + "-" + random(lowerHex, 23) + "-" + random(lowerHex, 34))},
			examples:   map[string]string{"one repeated character": plain("PMAK" + "-" + zeros(24) + "-" + zeros(34))},
		},
		{
			rule: "sentry-user-token", label: "sentry_token", score: 60,
			positives:  []formatSample{inText(sentryUser)},
			nearMisses: map[string]string{"63 characters": plain(sentryUser[:len(sentryUser)-1]), "65 characters": plain(sentryUser + "0")},
			examples:   map[string]string{"one repeated character": plain("sntryu" + "_" + zeros(64))},
		},
		{
			rule: "sentry-org-token", label: "sentry_token", score: 60,
			positives:  []formatSample{inText(sentryOrg)},
			nearMisses: map[string]string{"42 at the end": plain(sentryOrg[:len(sentryOrg)-1]), "44 at the end": plain(sentryOrg + "Q"), "no payload": plain("sntrys" + "_" + random(alnum, 43))},
			examples:   map[string]string{"placeholder": plain("sntrys" + "_eyJ" + x(60) + "_" + x(43))},
		},
		{
			rule: "doppler-token", label: "doppler_token", score: 60,
			positives: []formatSample{
				inText(token(func() string { return "dp" + ".pt." + random(alnum, 43) })),
				inText(token(func() string { return "dp" + ".st.prd." + random(alnum, 43) })),
				inText(token(func() string { return "dp" + ".st." + random(alnum, 40) })),
				inText(token(func() string { return "dp" + ".ct." + random(alnum, 43) })),
			},
			nearMisses: map[string]string{"39 characters": plain("dp" + ".pt." + random(alnum, 39)), "45 characters": plain("dp" + ".pt." + random(alnum, 45)), "another kind": plain("dp" + ".xx." + random(alnum, 43)), "CSS classes": ".dp.pt.selected{margin:0}.dp.st.active{color:red}"},
			examples:   map[string]string{"placeholder": plain("dp" + ".pt." + x(43))},
		},
		{
			rule: "azure-storage-key", label: "azure_storage_key", score: 60,
			positives: []formatSample{
				{text: "DefaultEndpointsProtocol=https;AccountName=ordersprod;AccountKey=" + azure + ";EndpointSuffix=core.windows.net", secret: azure},
				after("AZURE_STORAGE_KEY=", azure),
				{text: `account_key: "` + azure + `"`, secret: azure},
				{text: `{"storageAccountKey" : '` + azure + `'}`, secret: azure},
				// The az CLI's own flag, and a .NET config file's attribute pair.
				{text: "az storage blob list --account-name ordersprod --account-key " + azure + " -c backups", secret: azure},
				{text: `az storage container list --account-key "` + azure + `"`, secret: azure},
				{text: `<add key="StorageAccountKey" value="` + azure + `" />`, secret: azure},
				{text: `<add key='AccountKey' value = '` + azure + `'/>`, secret: azure},
			},
			nearMisses: map[string]string{
				"no name before it":         plain(azure),
				"a space after a name":      "AccountKey " + azure,
				"another flag":              "az storage blob list --account-name " + azure,
				"another attribute between": `<add key="AccountKey" name="x" value="` + azure + `" />`,
				"85 characters":             "AccountKey=" + random(alnum, 85) + "==;",
				"87 characters":             "AccountKey=" + random(alnum, 87) + "==;",
				"one = at the end":          "AccountKey=" + random(alnum, 87) + "=;",
				"a name far before":         "AccountKey is rotated monthly, the current blob is " + azure,
			},
			examples: map[string]string{"the storage emulator's key": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=" + emulatorKey + ";BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"},
		},
		{
			// In JSON the name is the key, and the value is all the rules read.
			rule: "azure-storage-key-value", label: "azure_storage_key", score: 50,
			positives: []formatSample{
				{text: `{"messages":[{"role":"user","content":{"AccountKey":"` + azure + `"}}]}`, secret: azure},
				{text: `{"messages":[{"role":"user","content":{"storageAccountKey":"` + azure + `"}}]}`, secret: azure},
				{text: `{"input":[{"output":{"account_key":"` + azure + `"}}]}`, secret: azure},
			},
			nearMisses: map[string]string{
				"a key that names nothing":      `{"messages":[{"role":"user","content":{"checksum":"` + azure + `"}}]}`,
				"85 characters":                 `{"messages":[{"role":"user","content":{"AccountKey":"` + random(alnum, 85) + `=="}}]}`,
				"more than the key":             `{"messages":[{"role":"user","content":{"AccountKey":"` + azure + ` rotated"}}]}`,
				"a key of the request's own":    `{"metadata":{"AccountKey":"` + azure + `"},"messages":[]}`,
				"a name that says it is public": `{"messages":[{"role":"user","content":{"AccountKeyName":"key1"}}]}`,
			},
			examples: map[string]string{"the storage emulator's key": `{"messages":[{"role":"user","content":{"AccountKey":"` + emulatorKey + `"}}]}`},
		},
		{
			// It only reports. The value in these has no digit or is an image's
			// tag, so the keyword rule does not replace it either; a random value
			// after the scheme is the keyword rule's, in TestRulesThatOnlyRelabelAreGone.
			rule: "secret-token-uri", label: "secret_token", score: 90, alert: true,
			positives: []formatSample{
				{text: "the hook sends secret-token:" + secretWords + " as its password", secret: secretWords},
				{text: "    image: ghcr.io/acme/secret-token:" + imageTagText + "\n", secret: imageTagText},
			},
			nearMisses: map[string]string{"15 characters": "use secret-token:" + random(lowerHex, 15) + " for now", "an image tag": "image: registry.example.com/tools/secret-token:v1.2.3"},
			examples:   map[string]string{"the RFC's own": "Authorization: Bearer secret-token:" + "E92FB7EB-D882-47A4-A265-A0B6135DC842%20foo"},
		},
	}
	return cases
}

func randomUUIDText(t testing.TB) string {
	h := randomHex(t, 16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// rulesBeforeIdentifiers are the rules the first version shipped, which have
// their own tests. Every rule added since needs a formatCase.
var rulesBeforeIdentifiers = map[string]bool{
	"phase-user-token": true, "phase-service-token": true, "phase-agent-token": true, "aws-secret-access-key": true,
	"github-fine-grained-token": true, "private-key-block": true, "private-key-header": true, "slack-token": true,
	"jwt": true, "keyword-high-entropy": true,
}

// TestTokenFormats holds every format rule to three things: a token is
// replaced, by that rule and with its label; a near-miss is not; and neither
// is the format's documentation example or test-mode value.
func TestTokenFormats(t *testing.T) {
	cases := formatCases(t)
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
		if len(tc.positives) == 0 || len(tc.nearMisses) == 0 || len(tc.examples) == 0 {
			t.Errorf("%s needs a positive, a near-miss and an example", tc.rule)
		}
		t.Run(tc.rule, func(t *testing.T) {
			for i, sample := range tc.positives {
				ix := build(t)
				result := apply(ix, []byte(sample.text))
				if len(result.Rules) != 1 {
					t.Fatalf("positive %d: %d findings, want one: %+v in %q", i, len(result.Rules), result.Rules, sample.text)
				}
				hit, score := result.Rules[0], tc.score
				if sample.score != 0 {
					score = sample.score
				}
				if tc.alert {
					if hit.Rule != tc.rule || hit.Label != tc.label || hit.Action != actionAlert || hit.Placeholder != "" || hit.Score != score || string(result.Out) != sample.text {
						t.Fatalf("positive %d: %+v and %q, want an alert of rule %s, score %d, and nothing changed", i, hit, result.Out, tc.rule, score)
					}
					continue
				}
				if hit.Rule != tc.rule || hit.Label != tc.label || hit.Action != actionRedact || hit.Placeholder != "ph:"+tc.label+":1" || hit.Score != score {
					t.Fatalf("positive %d: %+v, want rule %s label %s score %d", i, hit, tc.rule, tc.label, score)
				}
				if want := strings.Replace(sample.text, sample.secret, hit.Placeholder, 1); string(result.Out) != want {
					t.Fatalf("positive %d:\n got %q\nwant %q", i, result.Out, want)
				}
			}
			for name, text := range tc.nearMisses {
				ix := build(t)
				if result := apply(ix, []byte(text)); string(result.Out) != text || len(result.Rules) != 0 {
					t.Errorf("near-miss %q was taken: %+v\n%q", name, result.Rules, result.Out)
				}
			}
			for name, text := range tc.examples {
				ix := build(t)
				if result := apply(ix, []byte(text)); string(result.Out) != text || len(result.Rules) != 0 {
					t.Errorf("example %q was taken: %+v\n%q", name, result.Rules, result.Out)
				}
			}
		})
	}
	for _, rule := range append(append([]*Rule(nil), DefaultRules().list...), DefaultRules().keywordRules...) {
		if !covered[rule.ID] && !rulesBeforeIdentifiers[rule.ID] {
			t.Errorf("rule %s has no format case", rule.ID)
		}
	}
}

// Each format also has to be found where agents meet it: as a JSON value in a
// request, next to other tokens, and the same token under the same placeholder.
func TestTokenFormatsInARequest(t *testing.T) {
	var lines, secrets []string
	distinct := map[string]bool{}
	for _, tc := range formatCases(t) {
		if tc.alert {
			continue
		}
		for _, sample := range tc.positives {
			lines = append(lines, sample.text)
			secrets = append(secrets, sample.secret)
			distinct[tc.label+" "+sample.secret] = true
		}
	}
	ix := build(t)
	text := strings.Join(lines, "\n")
	result := apply(ix, modelRequest(text, text))
	if !json.Valid(result.Out) {
		t.Fatal("the rewritten body is not JSON")
	}
	for i, secret := range secrets {
		escaped := jsonEscape(secret)
		if strings.Contains(string(result.Out), secret) || strings.Contains(string(result.Out), escaped) {
			t.Errorf("%q survived in a request", lines[i])
		}
	}
	if len(result.Rules) != 2*len(secrets) {
		t.Errorf("%d findings for %d tokens sent twice", len(result.Rules), len(secrets))
	}
	placeholder := regexp.MustCompile(`^ph:[a-z][a-z0-9_]*:[0-9]+$`)
	seen := map[string]bool{}
	for _, hit := range result.Rules {
		if hit.Action != actionRedact || !placeholder.MatchString(hit.Placeholder) {
			t.Errorf("finding %+v", hit)
		}
		seen[hit.Placeholder] = true
	}
	// The same token is the same placeholder wherever it turns up.
	if len(seen) != len(distinct) {
		t.Errorf("%d placeholders for %d distinct tokens", len(seen), len(distinct))
	}
}

// A keyword rule with a shape still needs its keyword, and a value of another
// shape after the same keyword is left to the general keyword rule.
func TestShapedKeywordRules(t *testing.T) {
	ix := build(t)
	bot := fresh(t, func() string {
		return randomString(t, "123456789", 1) + randomString(t, decimal, 9) + ":AA" + randomString(t, base64URL, 33)
	})
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]string{"botToken": bot, "note": bot}}}})
	result := apply(ix, body)
	if len(result.Rules) != 1 || result.Rules[0].Rule != "telegram-bot-token" || result.Rules[0].Path != "/messages/0/content/botToken" || strings.Count(string(result.Out), bot) != 1 {
		t.Fatalf("as a JSON value under a keyword: %+v %s", result.Rules, result.Out)
	}
	hit, out, ok := ruleHit(t, ix, "TELEGRAM_BOT_TOKEN=12345:"+"AA9f8e7d6c5b4a39281706f5e4d3c2b1a")
	if !ok || hit.Label != "keyword_secret" || hit.Action != actionRedact || !strings.HasPrefix(out, "TELEGRAM_BOT_TOKEN=ph:keyword_secret:") {
		t.Fatalf("a value of another shape after the keyword: %+v %s", hit, out)
	}
	// With several keywords before one value it is still one finding.
	hit, out, _ = ruleHit(t, ix, "auth token secret: "+bot)
	if hit.Rule != "telegram-bot-token" || out != "auth token secret: "+hit.Placeholder {
		t.Fatalf("%+v %s", hit, out)
	}
}

// What is publicly known about the GitHub and npm checksum: GitHub's own
// description names CRC32, Base62 and zero padding to six characters. That the
// sum covers the 30 characters before it, in the alphabet 0-9A-Za-z with the
// most significant digit first, comes from documents and code that follow it.
// The vectors here are theirs, not made with this package's encoder:
//
//   - the example token in the README of the base62-token.js library, which
//     makes and checks tokens "GitHub-style";
//   - the test vectors of the Apache Software Foundation's draft token standard,
//     which takes its checksum from GitHub's: CRC-32 of the entropy characters,
//     base62, six characters.
//
// None is a token GitHub or npm issued, and no such token was used to write
// this. The npm vector is the same body under npm's prefix: npm documents the
// construction and gives no example.
func TestChecksumVectors(t *testing.T) {
	if got := base62(0xFFFFFFFF, 6); got != "4gfFC3" {
		t.Fatalf("0xFFFFFFFF in base62 is %s, the draft standard says 4gfFC3", got)
	}
	for entropy, checksum := range map[string]string{
		strings.Repeat("0", 27):       "2MvMGi",
		strings.Repeat("z", 27):       "13hv5A",
		"mXBgIOwUcV44oJElFX4LCMhWkEs": "2gaLe2",
		"63Uo76APFVkmVyTpHpi3W7zlmxJ": "1dGuWP",
		"PfCdJHSP5C8vM4hkQRMImIzAFm9": "0LW1gM",
	} {
		if !crc32Base62([]byte(entropy), []byte(checksum)) {
			t.Errorf("the draft standard's vector %s %s does not verify", entropy, checksum)
		}
	}
	const body, checksum = "zQWBuTSOoRi4A9" + "spHcVY5ncnsDkxkJ", "0mL" + "q17"
	github, npm, pypi, aws := validators["github_crc32"], validators["npm_crc32"], validators["pypi_macaroon"], validators["aws_key_id"]
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		if !github([]byte(prefix + body + checksum)) {
			t.Errorf("the library's example does not verify under %s", prefix)
		}
	}
	if !npm([]byte("npm_" + body + checksum)) {
		t.Error("the same body does not verify as an npm token")
	}
	for name, token := range map[string]string{
		"a changed character":          "ghp_" + "a" + body[1:] + checksum,
		"a changed checksum":           "ghp_" + body + "0mLq18",
		"the checksum's bytes swapped": "ghp_" + body + "20oiHi",
		"the prefix in the sum":        "ghp_" + body + base62(crc32.ChecksumIEEE([]byte("ghp_"+body)), 6),
		"no underscore":                "ghpx" + body + checksum,
		"a longer token":               "ghs_" + body + "Q" + checksum,
		"the longer installation form": installationToken(t),
		"an npm token":                 "npm_" + body + checksum,
	} {
		if github([]byte(token)) {
			t.Errorf("%s verified as a GitHub token", name)
		}
	}
	if npm([]byte("ghp_"+body+checksum)) || npm([]byte("npm_"+body+"0mLq18")) || npm([]byte("npm_"+body)) {
		t.Error("the npm checksum took what it should not")
	}

	if !pypi([]byte(pypiMacaroonToken(t))) {
		t.Error("a pypi.org macaroon does not verify")
	}
	macaroon := func(raw string) string { return "pypi-" + base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	for name, token := range map[string]string{
		"another location":       macaroon("\x02\x01\x0atest.pypi.org\x02\x04abcd\x00\x00\x06\x04sign"),
		"version 1":              macaroon("\x01\x01\x08pypi.org\x02\x04abcd\x00\x00\x06\x04sign"),
		"no identifier":          macaroon("\x02\x01\x08pypi.org\x00\x00\x06\x04sign"),
		"an identifier too long": macaroon("\x02\x01\x08pypi.org\x02\x40abcd"),
		"not base64url":          "pypi-" + "AgEIcHlwaS5vcmcC" + strings.Repeat("+", 40),
		"a length base64 cannot": "pypi-" + "AgEIcHlwaS5vcmcCJGFi" + "Y",
		"no prefix":              base64.RawURLEncoding.EncodeToString([]byte(pypiMacaroonHeader + "\x02\x04abcd")),
		"too long to be a token": macaroon(pypiMacaroonHeader + "\x02\x04abcd" + strings.Repeat("a", 800)),
	} {
		if pypi([]byte(token)) {
			t.Errorf("%s verified as a PyPI token", name)
		}
	}

	if !aws([]byte("AKIA"+"ABCDEFGHIJKLMNOP")) || !aws([]byte("ASIA"+"234567ABCDEFGHIJ")) || !validators["aws-key-id"]([]byte("AKIA"+"ABCDEFGHIJKLMNOP")) {
		t.Error("a base32 key id does not verify")
	}
	for _, id := range []string{"AKIA" + "ABCDEFGHIJKLMNO1", "AKIA" + "ABCDEFGHIJKLMNO", "AKIA" + "ABCDEFGHIJKLMNOPQ", "AKIA" + "abcdefghijklmnop", "AKIA" + "ABCDEFGH=JKLMNOP"} {
		if aws([]byte(id)) {
			t.Errorf("%s verified as an AWS key id", id)
		}
	}
}

// A checksum only ever adds to a score. A token whose checksum does not verify
// has its format's prefix, length and alphabet all the same, and is replaced as
// a rule with no validator would replace it.
func TestAFailedChecksumNeverSavesAToken(t *testing.T) {
	valid := map[string]string{
		"github-classic-token": checksummed(t, "ghs_"),
		"npm-token":            checksummed(t, "npm_"),
		"pypi-token":           pypiMacaroonToken(t),
		"aws-access-key-id":    fresh(t, func() string { return "ASIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16) }),
	}
	// The same shapes with a checksum or structure that does not verify.
	broken := map[string]string{
		"github-classic-token": fresh(t, func() string { return "ghs_" + randomString(t, alnum, 30) + "zzzzzz" }),
		"npm-token":            fresh(t, func() string { return "npm_" + randomString(t, alnum, 30) + "zzzzzz" }),
		"pypi-token":           fresh(t, func() string { return "pypi-" + "AgEIcHlwaS5vcmc" + "A" + randomString(t, base64URL, 90) }),
		"aws-access-key-id":    fresh(t, func() string { return "ASIA" + randomString(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 15) + "0" }),
	}
	rules := DefaultRules()
	for id := range valid {
		var rule *Rule
		for _, candidate := range rules.list {
			if candidate.ID == id {
				rule = candidate
			}
		}
		if rule == nil || rule.validate == nil {
			t.Fatalf("%s has no validator", id)
		}
		if !rule.validate([]byte(valid[id])) || rule.validate([]byte(broken[id])) {
			t.Fatalf("%s: the test's tokens are not what it says they are", id)
		}
		ix := build(t)
		passed, _, _ := ruleHit(t, ix, "found "+valid[id]+" in the log")
		failed, out, ok := ruleHit(t, ix, "found "+broken[id]+" in the log")
		if passed.Rule != id || passed.Score != rule.base+rules.scoring.ValidatorBonus || passed.Action != actionRedact {
			t.Errorf("%s with a passing validator: %+v", id, passed)
		}
		if !ok || failed.Rule != id || failed.Score != rule.base || failed.Action != actionRedact || strings.Contains(out, broken[id]) {
			t.Errorf("%s with a failing validator: %+v %s", id, failed, out)
		}
		if failed.Score < rule.redactAt {
			t.Errorf("%s: a failed validator leaves the score at %d, under redact_at", id, failed.Score)
		}
	}
}

// Labels become placeholders the model reads and repeats, so they keep to one
// plain form.
func TestShippedRulesAreWellFormed(t *testing.T) {
	rules := DefaultRules()
	if skipped := rules.Skipped(); len(skipped) != 0 {
		t.Fatalf("shipped rules were skipped: %+v", skipped)
	}
	label := regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	for _, rule := range append(append([]*Rule(nil), rules.list...), rules.keywordRules...) {
		if !label.MatchString(rule.Label) {
			t.Errorf("%s: label %q is not lowercase snake case", rule.ID, rule.Label)
		}
		if rule.Description == "" {
			t.Errorf("%s has no description", rule.ID)
		}
	}
	// Every rule is either tried only where its own literal begins or only at a
	// keyword. None runs a regex over all the text it is given.
	if len(rules.unanchored) != 0 {
		t.Errorf("%d shipped rules scan the whole text, the first %s", len(rules.unanchored), rules.unanchored[0].ID)
	}
	for _, rule := range rules.list {
		for _, start := range rule.starts {
			if len(start.text) < 3 {
				t.Errorf("%s begins with only %q", rule.ID, start.text)
			}
		}
	}
}
