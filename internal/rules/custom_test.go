package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompileCustomRuleRestrictsRequestToReadOnlyRootGet(t *testing.T) {
	rule, err := CompileCustomRule(CustomRule{ID: "legacy-console", Name: "Legacy console marker", Severity: "medium", MatchType: "word", Part: "body", Values: []string{"Welcome to legacy console"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal([]byte(rule.Template), &template); err != nil {
		t.Fatal(err)
	}
	http := template["http"].([]any)[0].(map[string]any)
	if http["method"] != "GET" || http["path"].([]any)[0] != "{{BaseURL}}/" {
		t.Fatalf("custom rule escaped the safe request profile: %#v", http)
	}
	if strings.Contains(rule.Template, "POST") || strings.Contains(rule.Template, "payload") || strings.Contains(rule.Template, "interactsh") {
		t.Fatalf("compiled rule contains a disallowed capability: %s", rule.Template)
	}
}

func TestCompileCustomRuleRejectsInvalidDefinitions(t *testing.T) {
	tests := []CustomRule{
		{ID: "../outside", Name: "x", Severity: "high", MatchType: "word", Part: "body", Values: []string{"x"}},
		{ID: "bad-regex", Name: "x", Severity: "high", MatchType: "regex", Part: "body", Values: []string{"("}},
		{ID: "bad-status", Name: "x", Severity: "high", MatchType: "status", StatusCodes: []int{99}},
		{ID: "too-long", Name: "x", Severity: "high", MatchType: "word", Part: "body", Values: []string{strings.Repeat("x", 257)}},
		{ID: "bad-method", Name: "x", Severity: "high", MatchType: "post", Values: []string{"x"}},
	}
	for _, input := range tests {
		if _, err := CompileCustomRule(input); err == nil {
			t.Errorf("invalid custom rule accepted: %+v", input)
		}
	}
}
