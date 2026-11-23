package aiproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

// This file is the probe program behind testdata/leak_parity_base.txt, and
// builds unchanged in the commit the stored inventory was built on. The
// recorded file is what it wrote there:
//
//	git archive b256f28 src | tar -x -C <dir>
//	cp internal/aiproxy/leak_parity_probe_test.go <dir>/src/internal/aiproxy/
//	cd <dir>/src && go test ./internal/aiproxy/ -run TestRecordLeakParity -args -leak-parity-record=<file>
//
// It registers fixed values with a proxy as a command does and writes, for
// each probe, a hash of what every kind of scan made of it and of the scan's
// report, then what the provider received for a few requests, the events and
// the counts. The file holds hashes, counts and placeholders, and no probe.
//
// Left out, because the proxy now differs from that commit on purpose there:
// one value registered under two ids, a value that is a host or a path of
// the model's own requests, and ph:<type> written with no id.
var leakParityRecord = flag.String("leak-parity-record", "", "write the leak parity probes' output to this file")

// TestRecordLeakParity writes the probes' output for a proxy with no store.
func TestRecordLeakParity(t *testing.T) {
	if *leakParityRecord == "" {
		t.Skip("no file to record to")
	}
	rig := newLeakRig(t, leakModeCensor)
	lines := leakParityProbe(t, rig, func(values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse {
		return registerThroughControl(t, rig.proxy, values, kinds)
	}, -1)
	if err := os.WriteFile(*leakParityRecord, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// leakParityProbe registers the fixed values through register and returns a
// line for everything the proxy then did with the probes. events is how many
// events were recorded, to wait for, or below zero while recording.
func leakParityProbe(t *testing.T, rig *leakRig, register func(values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse, events int) []string {
	t.Helper()
	rng := rand.New(rand.NewSource(20261120))
	const alnum, hexDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "0123456789abcdef"
	str := func(alphabet string, n int) string {
		out := make([]byte, n)
		for i := range out {
			out[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(out)
	}
	pemBlock := func(kind string, n int) string {
		raw := make([]byte, n)
		rng.Read(raw)
		body := base64.StdEncoding.EncodeToString(raw)
		var lines []string
		for len(body) > 64 {
			lines, body = append(lines, body[:64]), body[64:]
		}
		return "-----BEGIN " + kind + "-----\n" + strings.Join(append(lines, body), "\n") + "\n-----END " + kind + "-----\n"
	}
	b64 := func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }

	// The values, and the units of each a scan may find on their own.
	token := str(alnum, 40)
	hex32, hex40, hex64 := str(hexDigits, 32), str(hexDigits, 40), str(hexDigits, 64)
	hexLineOne, hexLineTwo := str(hexDigits, 64), str(hexDigits, 64)
	hexLines := hexLineOne + "\n" + hexLineTwo
	privateKey := pemBlock("PRIVATE KEY", 300)
	kubeKey, kubeCert, kubeToken, kubePassword := b64(pemBlock("EC PRIVATE KEY", 120)), b64(pemBlock("CERTIFICATE", 400)), str(alnum, 44), str(alnum+"!$", 18)
	kube := "apiVersion: v1\nkind: Config\n# the cluster\nclusters:\n- cluster:\n    certificate-authority-data: " + kubeCert + "\n    server: https://10.0.0.1:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    client-key-data: " + kubeKey +
		"\n    token: " + kubeToken + "\n    password: \"" + kubePassword + "\"\n"
	envPassword, envKey, envToken, envURLPassword := str(alnum, 24), str(alnum, 32), str(alnum, 28), str(alnum, 20)
	envURL := "postgres://orders_app:" + envURLPassword + "@orders-db.internal.example.com:5432/orders"
	env := "# production\nDB_PASSWORD=" + envPassword + "\nAPI_KEY=\"" + envKey + "\"\nexport TOKEN='" + envToken + "'\nDATABASE_URL=" + envURL + "\nDEBUG=false\nEMPTY=\nPORT=8080\n" + str(alnum, 36) + "\n"
	iniID, iniSecret := str(alnum, 30), str(alnum+"+/", 40)
	ini := "[default]\naws_access_key_id = " + iniID + "\naws_secret_access_key = " + iniSecret + "\nregion = eu-west-1\n; comment\n[profile other]\noutput=json\n"
	urlPassword := str(alnum, 24)
	dbURL := "postgres://billing_app:" + urlPassword + "@billing-db.internal.example.com:5432/billing?sslmode=require"
	escapedPassword := str(alnum, 10) + "@" + str(alnum, 8) + "!" + str(alnum, 6)
	escapedURL := "mysql://svc:" + url.QueryEscape(escapedPassword) + "@db.example.org/app"
	userToken := str(alnum, 40)
	gitURL := "https://" + userToken + "@github.example.com/acme/orders.git"
	lineOne, lineTwo, lineThree := str(alnum+"+/", 64), str(alnum+"+/", 64), str(alnum+"+/", 44)
	lines := lineOne + "\n" + lineTwo + "\n" + lineThree
	// A service account: its key id is 40 hex digits in a JSON leaf.
	accountKeyID, accountSecret, accountKey := str(hexDigits, 40), str(alnum, 35), pemBlock("RSA PRIVATE KEY", 200)
	accountWith := func(keyID string) string {
		document, _ := json.Marshal(map[string]any{"type": "service_account", "project_id": "orders-prod", "private_key_id": keyID, "private_key": accountKey,
			"client_email": "orders@orders-prod.iam.gserviceaccount.com", "client_secret": accountSecret, "token_uri": "https://oauth2.example.com/token",
			"nested": map[string]any{"list": []any{"short", 7}, "n": 123456789012345}})
		return string(document)
	}
	account := accountWith(accountKeyID)
	numbers := "[" + strings.Repeat("1234567890123,", 3) + "98765432109876,5566778899001122,31415926535897,1,2,3,4,5,6,7,8,9,10,11,12]"
	short, tiny, plain := str(alnum, 12), str(alnum, 8), strings.Repeat("ab", 12)
	signed := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Orders","iat":1516239022}`)) + "." + str(alnum+"-_", 43)
	prefixed := "sk_" + "live_" + str(alnum, 32)
	accented := "pässwörd-" + str(alnum, 20) + "-ключ"
	registryAuth := b64("robot:" + str(alnum, 30))
	registry := `{"auths":{"registry.example.com":{"auth":"` + registryAuth + `"}}}`
	yamlPassword, yamlCache, yamlKeyOne, yamlKeyTwo := str(alnum, 22), str(alnum, 26), str(alnum, 33), str(alnum, 31)
	yaml := "db:\n  host: db.internal\n  password: " + yamlPassword + "\ncache:\n  url: redis://:" + yamlCache + "@cache.internal:6379/0\n  tls: true\nkeys:\n  - " + yamlKeyOne + "\n  - " + yamlKeyTwo + "\n"

	values := []leakguard.Value{
		{Type: "secret", ID: "token", Value: token}, {Type: "secret", ID: "hex32", Value: hex32}, {Type: "secret", ID: "hex40", Value: hex40},
		{Type: "secret", ID: "hex64", Value: hex64}, {Type: "secret", ID: "hexlines", Value: hexLines}, {Type: "sealed", ID: "pem", Value: privateKey},
		{Type: "secret", ID: "kube", Value: kube}, {Type: "secret", ID: "ENV_FILE", KeyName: true, Value: env}, {Type: "secret", ID: "ini", Value: ini},
		{Type: "dynamic", ID: "dburl", Value: dbURL}, {Type: "secret", ID: "escaped", Value: escapedURL}, {Type: "secret", ID: "GIT_URL", KeyName: true, Value: gitURL},
		{Type: "secret", ID: "lines", Value: lines}, {Type: "secret", ID: "account", Value: account}, {Type: "secret", ID: "numbers", Value: numbers},
		{Type: "secret", ID: "short", Value: short}, {Type: "secret", ID: "tiny", Value: tiny}, {Type: "secret", ID: "plain", Value: plain},
		{Type: "secret", ID: "signed", Value: signed}, {Type: "secret", ID: "prefixed", Value: prefixed}, {Type: "secret", ID: "accented", Value: accented},
		{Type: "secret", ID: "registry", Value: registry}, {Type: "secret", ID: "yaml", Value: yaml},
	}
	kinds := make([]string, len(values))
	for i, value := range values {
		kinds[i] = remoteapi.InventoryIDPhase
		if value.KeyName {
			kinds[i] = remoteapi.InventoryIDKeyName
		}
	}
	var out []string
	note := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	answered := func(what string, answer *remoteapi.InventoryResponse) {
		if answer == nil {
			t.Fatalf("%s was refused", what)
		}
		note("%s: added %d, unprotected %d", what, answer.Added, answer.Unprotected)
	}
	answered("registered", register(values, kinds))
	// Registered again, as every command does.
	answered("registered again", register(values[:6], kinds[:6]))

	var probes []string
	units := []string{token, hex32, hex40, hex64, hexLines, hexLineOne, hexLineTwo, privateKey, kube, env, ini, dbURL, escapedURL, gitURL, lines, account, numbers, short, tiny, plain,
		signed, prefixed, accented, registry, yaml, kubeKey, kubeCert, kubeToken, kubePassword, envPassword, envKey, envToken, envURL, envURLPassword, iniID, iniSecret, urlPassword,
		escapedPassword, url.QueryEscape(escapedPassword), userToken, lineOne, lineTwo, lineThree, accountKeyID, accountSecret, accountKey, registryAuth,
		yamlPassword, yamlCache, yamlKeyOne, yamlKeyTwo}
	for _, unit := range units {
		escaped, _ := json.Marshal(unit)
		probes = append(probes, unit, hex.EncodeToString([]byte(unit)), strings.ToUpper(hex.EncodeToString([]byte(unit))), b64(unit),
			base64.RawURLEncoding.EncodeToString([]byte(unit)), b64("u:"+unit), b64("user:"+unit+"\n"), url.QueryEscape(unit), string(escaped),
			strings.ReplaceAll(unit, "\n", `\n`), b64(b64(unit)))
		if len(unit) > 4 {
			probes = append(probes, unit[:len(unit)-1], unit[1:], unit[len(unit)/4:3*len(unit)/4], unit[:len(unit)/2], unit[len(unit)/2:])
		}
		for at := 0; at+23 <= len(unit) && at < 100; at += 11 {
			probes = append(probes, unit[at:at+23], unit[at:min(len(unit), at+47)])
		}
		for _, line := range strings.Split(unit, "\n") {
			if len(line) >= 12 && line != unit {
				probes = append(probes, line, strings.TrimSpace(line))
			}
		}
	}
	// Runs of hex digits cut to every length from 23 to 46, and a little
	// past, from the start of the value and from inside it.
	for _, digits := range []string{hex32, hex40, hex64, hexLineOne, hexLineTwo, accountKeyID} {
		for length := 23; length <= 48; length++ {
			for _, at := range []int{0, 1, 13} {
				if at+length <= len(digits) {
					probes = append(probes, digits[at:at+length])
				}
			}
		}
		probes = append(probes, strings.ToUpper(digits[1:]), "0x"+digits[:len(digits)-1], digits[:16]+" "+digits[16:], b64(digits[1:]), b64(digits)[3:])
	}
	// The key id less a character, where it stands in its document.
	probes = append(probes, accountWith(accountKeyID[:39]), accountWith(accountKeyID[1:]), `"private_key_id": "`+accountKeyID[:39]+`"`, `{"private_key_id":"`+accountKeyID[1:]+`"}`,
		hexLineOne[:63]+"\n"+hexLineTwo, hexLineOne+"\n"+hexLineTwo[1:], hexLineOne[20:]+"\n"+hexLineTwo[:40])
	hub, cloud := "gh"+"p_"+str(alnum, 36), "AKIA"+str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	probes = append(probes,
		token+":"+hub, "curl -u "+short+":"+cloud+" https://x.example", "password="+str(alnum, 24), "Authorization: Bearer "+token, hub, cloud,
		"ph:secret:token and ph:sealed:pem then "+token, "see ph:secret:ENV_FILE", "secret: "+str(alnum, 30), kube+"\n"+env+"\n"+account, strings.Repeat(token+" ", 50),
		hex64+hex40, hex40+" "+hex32+" "+hex64[7:39], "sha256:"+hex64, "commit "+hex40[:39], "id="+hex32[:23]+"&next=1")

	digest := func(parts ...any) string {
		sum := sha256.New()
		for _, part := range parts {
			switch part := part.(type) {
			case []byte:
				sum.Write(part)
			case error:
				fmt.Fprint(sum, part)
			default:
				encoded, err := json.Marshal(part)
				if err != nil {
					t.Fatal(err)
				}
				sum.Write(encoded)
			}
			sum.Write([]byte{0})
		}
		return hex.EncodeToString(sum.Sum(nil))[:8]
	}
	message := func(payload []byte) []byte {
		return append(binary.AppendUvarint([]byte{0x08, 0x07, 0x12}, uint64(len(payload))), payload...)
	}
	index := rig.guard.index
	for i, probe := range probes {
		text := []byte("lead " + probe + " trail")
		redacted, report := index.Redact(text)
		var written []string
		for _, finding := range report.Findings {
			if finding.Placeholder != "" && !strings.Contains(","+strings.Join(written, ",")+",", ","+finding.Placeholder+",") {
				written = append(written, finding.Placeholder)
			}
		}
		rewritten, jsonReport, err := index.RewriteJSON(anthropicBody(string(text)), censor.ScanOptions{})
		framed, framedReport := index.RewriteBinary(message(text), censor.ScanOptions{})
		raw, rawReport := index.RewriteBinary(text, censor.ScanOptions{})
		limited, limitedReport := index.RedactWith(text, censor.ScanOptions{Rules: rig.guard.limitedRules})
		// As text, in a JSON body, in a binary message, as bytes, where Find
		// says, and under the rules for Phase's own tokens alone; then how
		// many values and rule matches the text held, and what was written.
		note("%d: %s %s %s %s %s %s; %d %d %d %s", i, digest(redacted, report), digest(rewritten, jsonReport, fmt.Sprint(err)),
			digest(framed, framedReport), digest(raw, rawReport), digest(index.Find(text)), digest(limited, limitedReport),
			report.Inventory, report.Redacted, report.Alerts, strings.Join(written, ","))
	}

	// Through the proxy itself.
	client := rig.client(rig.phaseRoots)
	for _, request := range []struct{ name, query, content, encoding string }{
		{"documents", "", "cat ~/.kube/config\n" + kube + "\ncat .env\n" + env + "\n" + account + "\n" + privateKey, ""},
		{"pieces", "", token[3:33] + " " + kubeToken[:43] + " " + lineTwo + " " + urlPassword[1:] + " " + hex.EncodeToString([]byte(envKey)) + " " + dbURL, ""},
		{"hex pieces", "", hex32[1:] + " " + hex32[:23] + " " + hex40[1:] + " " + hex40[10:] + " " + hex64[14:50] + " " + hexLineTwo[:31] + " " + accountKeyID[:39], ""},
		{"a hex key less a character in its document", "", accountWith(accountKeyID[:39]), ""},
		{"gzip", "", yaml + " " + signed + " " + prefixed + " " + hex64[3:40], "gzip"},
		{"a value in the URL", "?key=" + url.QueryEscape(token), "nothing", ""},
		{"a piece in the URL", "?key=" + token[:30], "nothing", ""},
		{"hex digits in the URL", "?key=" + hex40, "nothing", ""},
		{"a piece of hex digits in the URL", "?key=" + hex40[1:], "nothing", ""},
		{"a password in the URL", "?p=" + urlPassword, "nothing", ""},
		{"nothing", "", "nothing at all", ""},
	} {
		before := rig.receivedCount()
		body := anthropicBody(request.content)
		if request.encoding == "gzip" {
			body = gzipBytes(t, body)
		}
		response := postMessages(t, client, "https://api.anthropic.com/v1/messages"+request.query, body, request.encoding)
		line := fmt.Sprintf("request %s: status %d", request.name, response.StatusCode)
		if rig.receivedCount() > before {
			received := rig.lastReceived()
			sent := received.body
			if request.encoding == "gzip" {
				sent = gunzipBytes(t, sent)
			}
			line += ", received " + digest(received.path, received.rawQuery, sent)
		}
		out = append(out, line)
	}
	// The events, in any order, once as many as were recorded have come and
	// no more do.
	var shipped []agentapi.Event
	for settled, deadline := 0, time.Now().Add(15*time.Second); (settled < 3 || len(shipped) < events) && time.Now().Before(deadline); {
		now := rig.leakEventsNow()
		if settled++; len(now) != len(shipped) {
			settled = 0
		}
		shipped = now
	}
	var details []string
	for _, event := range shipped {
		detail, _ := json.Marshal(event.Detail)
		details = append(details, "event: "+string(detail))
	}
	sort.Strings(details)
	out = append(out, details...)
	status := rig.guard.status()
	note("status: %d known, %d unprotected, mode %s", status.SecretsKnown, status.Unprotected, status.Mode)
	if bytes.Contains([]byte(strings.Join(out, "\n")), []byte(token)) {
		t.Fatal("the output holds a probe")
	}
	return out
}
