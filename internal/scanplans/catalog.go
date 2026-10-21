// Package scanplans exposes the product-level scan plan catalog. Plans only
// describe safe, read-only policy defaults; engine command-line flags remain
// internal to the Worker.
package scanplans

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

var ErrInvalid = errors.New("invalid scan plan")

type Defaults struct {
	PortPreset     string   `json:"portPreset"`
	Intensity      string   `json:"intensity"`
	PortRanges     string   `json:"portRanges"`
	PortExclusions string   `json:"portExclusions"`
	CustomRuleIDs  []string `json:"customRuleIds"`
}

type Plan struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Summary   string   `json:"summary"`
	Detail    string   `json:"detail"`
	Kind      string   `json:"kind"`
	ReadOnly  bool     `json:"readOnly"`
	Defaults  Defaults `json:"defaults"`
	SourceID  string   `json:"sourceId,omitempty"`
	CreatedBy string   `json:"createdBy,omitempty"`
	CreatedAt string   `json:"createdAt,omitempty"`
	UpdatedAt string   `json:"updatedAt,omitempty"`
}

// Input is the product-level editable portion of a custom plan. It deliberately
// contains no engine command-line flags or executable paths.
type Input struct {
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Detail   string   `json:"detail"`
	Defaults Defaults `json:"defaults"`
	SourceID string   `json:"sourceId,omitempty"`
}

const (
	MaxPlans        = 100
	MaxTitleBytes   = 160
	MaxSummaryBytes = 400
	MaxDetailBytes  = 1200
)

func Catalog() []Plan {
	return []Plan{
		{
			ID: "quick", Title: "快速检测", Summary: "常见端口、温和速率、只读 HTTP 基线",
			Detail: "适合首次确认资产暴露面，连接数和目标负载较低。", Kind: "PRESET", ReadOnly: true,
			Defaults: Defaults{PortPreset: "common", Intensity: "gentle", CustomRuleIDs: []string{}},
		},
		{
			ID: "standard", Title: "标准检测", Summary: "常见端口加可选自定义范围、标准速率",
			Detail: "适合日常例检；仍只处理本次明确授权的端口。", Kind: "PRESET", ReadOnly: true,
			Defaults: Defaults{PortPreset: "common-and-custom", Intensity: "standard", CustomRuleIDs: []string{}},
		},
	}
}

func (d Defaults) normalized() Defaults {
	if d.PortPreset == "" {
		d.PortPreset = "common"
	}
	if d.Intensity == "" {
		d.Intensity = "gentle"
	}
	d.PortRanges = strings.TrimSpace(d.PortRanges)
	d.PortExclusions = strings.TrimSpace(d.PortExclusions)
	if d.CustomRuleIDs == nil {
		d.CustomRuleIDs = []string{}
	} else {
		for i := range d.CustomRuleIDs {
			d.CustomRuleIDs[i] = strings.TrimSpace(d.CustomRuleIDs[i])
		}
	}
	return d
}

func (in Input) NormalizeAndValidate() (Input, error) {
	in.Title = strings.TrimSpace(in.Title)
	in.Summary = strings.TrimSpace(in.Summary)
	in.Detail = strings.TrimSpace(in.Detail)
	in.SourceID = strings.TrimSpace(in.SourceID)
	if err := validateText(in.Title, "title", MaxTitleBytes); err != nil {
		return in, err
	}
	if err := validateText(in.Summary, "summary", MaxSummaryBytes); err != nil {
		return in, err
	}
	if err := validateText(in.Detail, "detail", MaxDetailBytes); err != nil {
		return in, err
	}
	in.Defaults = in.Defaults.normalized()
	if err := validateDefaults(in.Defaults); err != nil {
		return in, err
	}
	if in.SourceID != "" && (in.SourceID != "quick" && in.SourceID != "standard") {
		return in, fmt.Errorf("%w: sourceId must reference a built-in preset", ErrInvalid)
	}
	return in, nil
}

func validateText(value, field string, maxBytes int) error {
	if value == "" || len([]byte(value)) > maxBytes {
		return fmt.Errorf("%w: %s is required and must be at most %d bytes", ErrInvalid, field, maxBytes)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, field)
		}
	}
	return nil
}

func validateDefaults(d Defaults) error {
	switch d.PortPreset {
	case "common", "custom", "common-and-custom", "registered", "full":
	default:
		return fmt.Errorf("%w: unsupported port preset", ErrInvalid)
	}
	switch d.Intensity {
	case "gentle", "standard", "aggressive":
	default:
		return fmt.Errorf("%w: unsupported intensity", ErrInvalid)
	}
	if d.PortPreset != "custom" && d.PortPreset != "common-and-custom" && strings.TrimSpace(d.PortRanges) != "" {
		return fmt.Errorf("%w: port ranges are only valid for custom presets", ErrInvalid)
	}
	if _, err := parseRanges(d.PortRanges, d.PortPreset == "custom" || d.PortPreset == "common-and-custom"); err != nil {
		return err
	}
	if _, err := parseRanges(d.PortExclusions, false); err != nil {
		return err
	}
	if len(d.CustomRuleIDs) > 20 {
		return fmt.Errorf("%w: at most 20 custom rules may be selected", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(d.CustomRuleIDs))
	for _, id := range d.CustomRuleIDs {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\r\n\x00") {
			return fmt.Errorf("%w: invalid custom rule id", ErrInvalid)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: duplicate custom rule id", ErrInvalid)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func parseRanges(text string, required bool) ([][2]int, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		if required {
			return nil, fmt.Errorf("%w: custom port ranges are required for this preset", ErrInvalid)
		}
		return nil, nil
	}
	parts := strings.Split(text, ",")
	if len(parts) > 128 {
		return nil, fmt.Errorf("%w: too many port ranges", ErrInvalid)
	}
	out := make([][2]int, 0, len(parts))
	for _, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "" {
			return nil, fmt.Errorf("%w: empty port range", ErrInvalid)
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("%w: malformed port range", ErrInvalid)
		}
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil {
			return nil, fmt.Errorf("%w: malformed port range", ErrInvalid)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("%w: malformed port range", ErrInvalid)
			}
		}
		if start < 1 || start > end || end > 65535 {
			return nil, fmt.Errorf("%w: port range must be within 1-65535", ErrInvalid)
		}
		out = append(out, [2]int{start, end})
	}
	return out, nil
}
