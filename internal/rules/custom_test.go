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

func TestCompileCustomRuleSupportsSameOriginGetPath(t *testing.T) {
	rule, err := CompileCustomRule(CustomRule{ID: "internal-debug-open", Name: "Internal debug endpoint reachable", Severity: "high", MatchType: "status", StatusCodes: []int{200}, Path: "/internal/debug", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal([]byte(rule.Template), &template); err != nil {
		t.Fatal(err)
	}
	http := template["http"].([]any)[0].(map[string]any)
	if http["method"] != "GET" || http["path"].([]any)[0] != "{{BaseURL}}/internal/debug" {
		t.Fatalf("custom rule path was not applied: %#v", http)
	}
}

func TestCompileCustomRuleRejectsUnsafePaths(t *testing.T) {
	base := func(p string) CustomRule {
		return CustomRule{ID: "p", Name: "x", Severity: "high", MatchType: "status", StatusCodes: []int{200}, Path: p}
	}
	for _, p := range []string{"no-leading-slash", "/has space", "/inject{{interactsh-url}}", "/back\\slash", "/" + strings.Repeat("a", 300)} {
		if _, err := CompileCustomRule(base(p)); err == nil {
			t.Errorf("unsafe custom rule path accepted: %q", p)
		}
	}
}
