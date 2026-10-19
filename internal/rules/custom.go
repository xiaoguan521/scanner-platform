package rules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// CustomRule is a constrained, read-only HTTP signature owned by the platform.
// It intentionally has no user-provided request method, path, payload, or engine
// arguments.
type CustomRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	MatchType   string   `json:"matchType"`
	Part        string   `json:"part,omitempty"`
	Values      []string `json:"values,omitempty"`
	StatusCodes []int    `json:"statusCodes,omitempty"`
	Enabled     bool     `json:"enabled"`
	Template    string   `json:"template,omitempty"`
}

var customRuleID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,99}$`)

// CompileCustomRule turns a simple UI definition into the only Nuclei profile
// accepted by the Worker: one GET to the explicitly scoped root URL and local
// response matchers. It never accepts arbitrary YAML or Nuclei syntax.
func CompileCustomRule(rule CustomRule) (CustomRule, error) {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Description = strings.TrimSpace(rule.Description)
	if !customRuleID.MatchString(rule.ID) || len(rule.Name) < 1 || len(rule.Name) > 120 || len(rule.Description) > 2000 {
		return CustomRule{}, fmt.Errorf("invalid custom rule identity or description")
	}
	switch rule.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return CustomRule{}, fmt.Errorf("invalid custom rule severity")
	}
	matcher := map[string]any{"type": rule.MatchType}
	switch rule.MatchType {
	case "word", "regex":
		if rule.Part != "body" && rule.Part != "header" || len(rule.Values) == 0 || len(rule.Values) > 8 || len(rule.StatusCodes) != 0 {
			return CustomRule{}, fmt.Errorf("word and regex rules require a response part and 1 to 8 values")
		}
		values := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
				return CustomRule{}, fmt.Errorf("invalid custom rule matcher value")
			}
			if rule.MatchType == "regex" {
				if _, err := regexp.Compile(value); err != nil {
					return CustomRule{}, fmt.Errorf("invalid custom rule regular expression: %w", err)
				}
			}
			values = append(values, value)
		}
		if rule.MatchType == "word" {
			matcher["words"] = values
		} else {
			matcher["regex"] = values
		}
		matcher["part"] = rule.Part
		matcher["condition"] = "or"
	case "status":
		if rule.Part != "" || len(rule.Values) != 0 || len(rule.StatusCodes) == 0 || len(rule.StatusCodes) > 10 {
			return CustomRule{}, fmt.Errorf("status rules require 1 to 10 status codes")
		}
		seen := map[int]bool{}
		for _, status := range rule.StatusCodes {
			if status < 100 || status > 599 || seen[status] {
				return CustomRule{}, fmt.Errorf("invalid custom rule HTTP status")
			}
			seen[status] = true
		}
		matcher["status"] = rule.StatusCodes
	default:
		return CustomRule{}, fmt.Errorf("unsupported custom rule matcher")
	}
	document := map[string]any{
		"id":   rule.ID,
		"info": map[string]any{"name": rule.Name, "author": "scanner-platform custom rule", "severity": rule.Severity, "description": rule.Description, "tags": "custom,read-only"},
		"http": []any{map[string]any{"method": "GET", "path": []string{"{{BaseURL}}/"}, "matchers-condition": "or", "matchers": []any{matcher}}},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return CustomRule{}, fmt.Errorf("encode custom rule: %w", err)
	}
	rule.Template = string(encoded)
	return rule, nil
}
