package util

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// KeyValue preserves insertion order for deterministic export output.
type KeyValue struct {
	Key   string
	Value string
}

// EscapeForFormat returns value as the format writes it, so leak protection
// can know a value in that form too. Formats that write values as they are
// return value unchanged.
func EscapeForFormat(format, value string) string {
	switch format {
	case "dotenv":
		// Single quotes keep a shell that sources or evals the export from
		// expanding $(...), backticks or variables in a value.
		return strings.ReplaceAll(value, "'", `'\''`)
	case "csv":
		return strings.ReplaceAll(value, `"`, `""`)
	case "xml":
		var escaped strings.Builder
		xml.EscapeText(&escaped, []byte(value))
		return escaped.String()
	case "hcl":
		return strings.ReplaceAll(value, `"`, `\"`)
	case "ini":
		return strings.ReplaceAll(value, "%", "%%")
	default:
		return value
	}
}

func ExportDotenv(secrets []KeyValue) {
	for _, kv := range secrets {
		fmt.Printf("%s='%s'\n", kv.Key, EscapeForFormat("dotenv", kv.Value))
	}
}

func ExportJSON(secrets []KeyValue) {
	// Use json.Encoder to produce an ordered JSON object
	ordered := make([]struct {
		Key   string
		Value string
	}, len(secrets))
	for i, kv := range secrets {
		ordered[i].Key = kv.Key
		ordered[i].Value = kv.Value
	}
	// Build a manually ordered JSON object to preserve key order
	fmt.Print("{\n")
	for i, kv := range secrets {
		keyJSON, _ := json.Marshal(kv.Key)
		valJSON, _ := json.Marshal(kv.Value)
		fmt.Printf("    %s: %s", string(keyJSON), string(valJSON))
		if i < len(secrets)-1 {
			fmt.Print(",")
		}
		fmt.Println()
	}
	fmt.Println("}")
}

func ExportCSV(secrets []KeyValue) {
	w := csv.NewWriter(os.Stdout)
	w.Write([]string{"Key", "Value"})
	for _, kv := range secrets {
		w.Write([]string{kv.Key, kv.Value})
	}
	w.Flush()
}

func ExportYAML(secrets []KeyValue) {
	// Build ordered YAML manually to preserve key order
	node := &yaml.Node{
		Kind: yaml.MappingNode,
	}
	for _, kv := range secrets {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: kv.Key},
			&yaml.Node{Kind: yaml.ScalarNode, Value: kv.Value},
		)
	}
	doc := &yaml.Node{
		Kind:    yaml.DocumentNode,
		Content: []*yaml.Node{node},
	}
	enc := yaml.NewEncoder(os.Stdout)
	enc.Encode(doc)
	enc.Close()
}

func ExportXML(secrets []KeyValue) {
	fmt.Println("<Secrets>")
	for _, kv := range secrets {
		fmt.Printf("  <secret name=\"%s\">%s</secret>\n", kv.Key, EscapeForFormat("xml", kv.Value))
	}
	fmt.Println("</Secrets>")
}

func ExportTOML(secrets []KeyValue) {
	for _, kv := range secrets {
		fmt.Printf("%s = \"%s\"\n", kv.Key, kv.Value)
	}
}

func ExportHCL(secrets []KeyValue) {
	for _, kv := range secrets {
		escaped := EscapeForFormat("hcl", kv.Value)
		fmt.Printf("variable \"%s\" {\n", kv.Key)
		fmt.Printf("  default = \"%s\"\n", escaped)
		fmt.Println("}")
		fmt.Println()
	}
}

func ExportINI(secrets []KeyValue) {
	fmt.Println("[DEFAULT]")
	for _, kv := range secrets {
		fmt.Printf("%s = %s\n", kv.Key, EscapeForFormat("ini", kv.Value))
	}
}

func ExportJavaProperties(secrets []KeyValue) {
	for _, kv := range secrets {
		fmt.Printf("%s=%s\n", kv.Key, kv.Value)
	}
}

func ExportKV(secrets []KeyValue) {
	for _, kv := range secrets {
		fmt.Printf("%s=%s\n", kv.Key, kv.Value)
	}
}
