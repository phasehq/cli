package util

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var sampleSecrets = []KeyValue{
	{Key: "AWS_SECRET_ACCESS_KEY", Value: "abc/xyz"},
	{Key: "AWS_ACCESS_KEY_ID", Value: "AKIA123"},
	{Key: "JWT_SECRET", Value: "token.value"},
	{Key: "DB_PASSWORD", Value: "pass%word"},
}

// sampleSecretsMap is a convenience lookup for assertions.
var sampleSecretsMap = map[string]string{
	"AWS_SECRET_ACCESS_KEY": "abc/xyz",
	"AWS_ACCESS_KEY_ID":     "AKIA123",
	"JWT_SECRET":            "token.value",
	"DB_PASSWORD":           "pass%word",
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = original

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	return buf.String()
}

func parseKeyValueLines(t *testing.T, out string) map[string]string {
	t.Helper()
	parsed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid key-value line: %q", line)
		}
		parsed[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return parsed
}

func TestExportJSON(t *testing.T) {
	out := captureStdout(t, func() { ExportJSON(sampleSecrets) })

	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal json output: %v", err)
	}
	if len(got) != len(sampleSecretsMap) {
		t.Fatalf("unexpected key count: got %d want %d", len(got), len(sampleSecretsMap))
	}
	for k, v := range sampleSecretsMap {
		if got[k] != v {
			t.Fatalf("mismatch for %s: got %q want %q", k, got[k], v)
		}
	}
}

func TestExportCSV(t *testing.T) {
	out := captureStdout(t, func() { ExportCSV(sampleSecrets) })

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(records) < 1 || len(records[0]) != 2 || records[0][0] != "Key" || records[0][1] != "Value" {
		t.Fatalf("unexpected csv header: %#v", records)
	}

	got := map[string]string{}
	for _, row := range records[1:] {
		if len(row) != 2 {
			t.Fatalf("unexpected csv row width: %#v", row)
		}
		got[row[0]] = row[1]
	}
	for k, v := range sampleSecretsMap {
		if got[k] != v {
			t.Fatalf("mismatch for %s: got %q want %q", k, got[k], v)
		}
	}
}

func TestExportYAML(t *testing.T) {
	out := captureStdout(t, func() { ExportYAML(sampleSecrets) })

	var got map[string]string
	if err := yaml.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal yaml output: %v", err)
	}
	for k, v := range sampleSecretsMap {
		if got[k] != v {
			t.Fatalf("mismatch for %s: got %q want %q", k, got[k], v)
		}
	}
}

type xmlSecrets struct {
	Entries []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"secret"`
}

func TestExportXML(t *testing.T) {
	out := captureStdout(t, func() { ExportXML(sampleSecrets) })

	var parsed xmlSecrets
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal xml output: %v", err)
	}
	got := map[string]string{}
	for _, e := range parsed.Entries {
		got[e.Name] = e.Value
	}
	for k, v := range sampleSecretsMap {
		if got[k] != v {
			t.Fatalf("mismatch for %s: got %q want %q", k, got[k], v)
		}
	}
}

func TestExportDotenvAndKVLikeFormats(t *testing.T) {
	dotenvOut := captureStdout(t, func() { ExportDotenv(sampleSecrets) })
	dotenv := parseKeyValueLines(t, dotenvOut)
	for k, v := range sampleSecretsMap {
		if dotenv[k] != `"`+v+`"` {
			t.Fatalf("dotenv mismatch for %s: got %q want %q", k, dotenv[k], `"`+v+`"`)
		}
	}

	kvOut := captureStdout(t, func() { ExportKV(sampleSecrets) })
	kv := parseKeyValueLines(t, kvOut)
	for k, v := range sampleSecretsMap {
		if kv[k] != v {
			t.Fatalf("kv mismatch for %s: got %q want %q", k, kv[k], v)
		}
	}

	javaOut := captureStdout(t, func() { ExportJavaProperties(sampleSecrets) })
	javaProps := parseKeyValueLines(t, javaOut)
	for k, v := range sampleSecretsMap {
		if javaProps[k] != v {
			t.Fatalf("java properties mismatch for %s: got %q want %q", k, javaProps[k], v)
		}
	}
}

func TestExportINI_EscapesPercent(t *testing.T) {
	out := captureStdout(t, func() { ExportINI(sampleSecrets) })
	if !strings.HasPrefix(out, "[DEFAULT]\n") {
		t.Fatalf("expected ini [DEFAULT] header, got %q", out)
	}
	if !strings.Contains(out, "DB_PASSWORD = pass%%word") {
		t.Fatalf("expected escaped percent in ini output, got %q", out)
	}
}
