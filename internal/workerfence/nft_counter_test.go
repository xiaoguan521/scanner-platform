//go:build linux

package workerfence

import "testing"

func TestParseDropCounterJSON(t *testing.T) {
	raw := []byte(`{"nftables":[{"rule":{"expr":[{"counter":{"packets":4,"bytes":100}},{"drop":null}]}},{"rule":{"expr":[{"counter":{"packets":3,"bytes":80}},{"drop":null}]}},{"rule":{"expr":[{"counter":{"packets":100}},{"accept":null}]}}]}`)
	got, err := parseDropCounterJSON(raw, "egress")
	if err != nil || got != 7 {
		t.Fatalf("drop count=%d err=%v", got, err)
	}
}

func TestParseDropCounterJSONRequiresDropRule(t *testing.T) {
	raw := []byte(`{"nftables":[{"rule":{"expr":[{"counter":{"packets":4}},{"accept":null}]}}]}`)
	if _, err := parseDropCounterJSON(raw, "forward"); err == nil {
		t.Fatal("accept rule was treated as drop counter")
	}
}
