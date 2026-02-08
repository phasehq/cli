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

func ExportDotenv(secrets map[string]string) {
	for key, value := range secrets {
		fmt.Printf("%s=\"%s\"\n", key, value)
	}
}

func ExportJSON(secrets map[string]string) {
	data, _ := json.MarshalIndent(secrets, "", "    ")
	fmt.Println(string(data))
}

func ExportCSV(secrets map[string]string) {
	w := csv.NewWriter(os.Stdout)
	w.Write([]string{"Key", "Value"})
	for key, value := range secrets {
		w.Write([]string{key, value})
	}
	w.Flush()
}

func ExportYAML(secrets map[string]string) {
	data, _ := yaml.Marshal(secrets)
	fmt.Print(string(data))
}

func ExportXML(secrets map[string]string) {
	fmt.Println("<Secrets>")
	for key, value := range secrets {
		var escaped strings.Builder
		xml.EscapeText(&escaped, []byte(value))
		fmt.Printf("  <secret name=\"%s\">%s</secret>\n", key, escaped.String())
	}
	fmt.Println("</Secrets>")
}

func ExportTOML(secrets map[string]string) {
	for key, value := range secrets {
		fmt.Printf("%s = \"%s\"\n", key, value)
	}
}

func ExportHCL(secrets map[string]string) {
	for key, value := range secrets {
		escaped := strings.ReplaceAll(value, "\"", "\\\"")
		fmt.Printf("variable \"%s\" {\n", key)
		fmt.Printf("  default = \"%s\"\n", escaped)
		fmt.Println("}")
		fmt.Println()
	}
}

func ExportINI(secrets map[string]string) {
	fmt.Println("[DEFAULT]")
	for key, value := range secrets {
		escaped := strings.ReplaceAll(value, "%", "%%")
		fmt.Printf("%s = %s\n", key, escaped)
	}
}

func ExportJavaProperties(secrets map[string]string) {
	for key, value := range secrets {
		fmt.Printf("%s=%s\n", key, value)
	}
}

func ExportKV(secrets map[string]string) {
	for key, value := range secrets {
		fmt.Printf("%s=%s\n", key, value)
	}
}
