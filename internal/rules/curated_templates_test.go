package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddCuratedTemplatesMergesValidJSON(t *testing.T) {
	dir := t.TempDir()
	good := `{"id":"cve-2021-test","info":{"name":"x","severity":"high"},"http":[{"method":"GET","path":["{{BaseURL}}/actuator/env"],"matchers":[{"type":"status","status":[200]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "cve-2021-test.json"), []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	files := BaselineTemplates()
	before := len(files)
	if err := addCuratedTemplates(files, dir); err != nil {
		t.Fatal(err)
	}
	if len(files) != before+1 {
		t.Fatalf("curated template not merged: %d -> %d", before, len(files))
	}
	if _, ok := files["nuclei/templates/cve-2021-test.json"]; !ok {
		t.Fatal("curated template missing expected manifest path")
	}
}

func TestAddCuratedTemplatesRejectsBadInputs(t *testing.T) {
	cases := map[string]string{
		"bad-id.json":   `{"id":"Bad ID","info":{"name":"x"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]}]}`,
		"not-json.json": `{not json`,
		"two-http.json": `{"id":"two","info":{"name":"x"},"http":[{},{}]}`,
	}
	for name, body := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := addCuratedTemplates(BaselineTemplates(), dir); err == nil {
			t.Errorf("expected rejection for %s", name)
		}
	}
}
