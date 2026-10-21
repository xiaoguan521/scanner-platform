// Package scanplans exposes the product-level scan plan catalog. Plans only
// describe safe, read-only policy defaults; engine command-line flags remain
// internal to the Worker.
package scanplans

type Defaults struct {
	PortPreset     string   `json:"portPreset"`
	Intensity      string   `json:"intensity"`
	PortRanges     string   `json:"portRanges"`
	PortExclusions string   `json:"portExclusions"`
	CustomRuleIDs  []string `json:"customRuleIds"`
}

type Plan struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Detail   string   `json:"detail"`
	Kind     string   `json:"kind"`
	ReadOnly bool     `json:"readOnly"`
	Defaults Defaults `json:"defaults"`
}

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
