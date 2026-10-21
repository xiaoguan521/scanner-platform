package scanplans

import (
	"errors"
	"testing"
)

func TestCatalogContainsSafeReadOnlyPresets(t *testing.T) {
	plans := Catalog()
	if len(plans) != 2 {
		t.Fatalf("catalog length=%d, want 2", len(plans))
	}
	if plans[0].ID != "quick" || plans[1].ID != "standard" {
		t.Fatalf("unexpected plan order: %+v", plans)
	}
	for _, plan := range plans {
		if plan.Kind != "PRESET" || !plan.ReadOnly || plan.Defaults.Intensity == "" || plan.Defaults.PortPreset == "" {
			t.Fatalf("unsafe or incomplete plan: %+v", plan)
		}
	}
}

func TestInputValidationKeepsPlansProductLevel(t *testing.T) {
	valid, err := (Input{
		Title: "自定义 SSH 检查", Summary: "常见端口加 SSH", Detail: "仅用于已授权的实验主机。",
		Defaults: Defaults{PortPreset: "custom", Intensity: "gentle", PortRanges: "22, 18080", PortExclusions: "443"},
		SourceID: "quick",
	}).NormalizeAndValidate()
	if err != nil || valid.Defaults.PortPreset != "custom" {
		t.Fatalf("valid input rejected: %+v, %v", valid, err)
	}
	cases := []Input{
		{Title: "", Summary: "summary", Detail: "detail"},
		{Title: "title", Summary: "summary", Detail: "detail", Defaults: Defaults{PortPreset: "custom", PortRanges: ""}},
		{Title: "title", Summary: "summary", Detail: "detail", Defaults: Defaults{PortPreset: "common", PortRanges: "80"}},
		{Title: "title", Summary: "summary", Detail: "detail", Defaults: Defaults{PortPreset: "custom", PortRanges: "80--81"}},
		{Title: "title", Summary: "summary", Detail: "detail", Defaults: Defaults{PortPreset: "unknown"}},
		{Title: "title", Summary: "summary", Detail: "detail", SourceID: "custom-plan"},
	}
	for index, input := range cases {
		if _, err := input.NormalizeAndValidate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d error=%v, want ErrInvalid", index, err)
		}
	}
}

func FuzzNormalizeAndValidateNoPanic(f *testing.F) {
	for _, seed := range []string{"80", "1-65535", "80,,81", "\x00", "端口"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, ranges string) {
		_, _ = (Input{
			Title: "方案", Summary: "摘要", Detail: "说明",
			Defaults: Defaults{PortPreset: "custom", Intensity: "gentle", PortRanges: ranges},
		}).NormalizeAndValidate()
	})
}
