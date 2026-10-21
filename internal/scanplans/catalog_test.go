package scanplans

import "testing"

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
