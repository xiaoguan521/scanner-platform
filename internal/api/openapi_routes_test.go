package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every /api/v1 route registered in this package must have an operation in
// docs/api/openapi.yaml, so new endpoints cannot ship undocumented.
func TestOpenAPIDocumentsEveryRoute(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(spec)
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	route := regexp.MustCompile(`HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^"]*)"`)
	checked := 0
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range route.FindAllStringSubmatch(string(data), -1) {
			method, path := strings.ToLower(match[1]), match[2]
			checked++
			start := strings.Index(doc, "\n  \""+path+"\":\n")
			if start < 0 {
				t.Errorf("%s %s (%s) is not in openapi.yaml", match[1], path, source)
				continue
			}
			block := doc[start+1:]
			if next := regexp.MustCompile(`\n  ["/]`).FindStringIndex(block[1:]); next != nil {
				block = block[:next[0]+1]
			}
			if !strings.Contains(block, "\n    "+method+":") {
				t.Errorf("%s %s (%s) has no %s operation in openapi.yaml", match[1], path, source, method)
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d routes found; the route pattern no longer matches the handlers", checked)
	}
}
