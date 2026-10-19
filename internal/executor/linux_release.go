package executor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"scanner-platform/internal/taskflow"
)

// Check the actual distribution ID. ID_LIKE must not silently turn an
// unsupported vendor distribution into another vendor's advisory feed.
func validateLinuxRelease(root string) error {
	var data []byte
	for _, name := range []string{"etc/os-release", "usr/lib/os-release"} {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(name)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read Linux release metadata: %w", err)
		}
		data, err = io.ReadAll(io.LimitReader(file, (64<<10)+1))
		file.Close()
		if err != nil || len(data) > 64<<10 {
			return &taskflow.ExecutionError{UserMessage: "Linux 发行版信息缺失或无效，请重新采集系统包快照"}
		}
		break
	}
	return checkLinuxRelease(data)
}

func checkLinuxRelease(data []byte) error {
	if len(data) > 64<<10 {
		return &taskflow.ExecutionError{UserMessage: "Linux 发行版信息过大，拒绝判断漏洞覆盖"}
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		value = strings.Trim(value, `"'`)
		if _, exists := values[key]; exists {
			return &taskflow.ExecutionError{UserMessage: "Linux 发行版信息含重复字段，拒绝判断漏洞覆盖"}
		}
		values[key] = value
	}
	id := values["ID"]
	// IDs listed by the pinned Trivy OS analyzers and its documented coverage.
	switch id {
	case "alpine", "wolfi", "chainguard", "minimos", "rhel", "centos", "almalinux", "rocky", "ol", "mariner", "azurelinux", "amzn", "opensuse-leap", "opensuse-tumbleweed", "sles", "sle-micro", "photon", "debian", "ubuntu", "echo":
	default:
		return &taskflow.ExecutionError{UserMessage: "该 Linux 发行版尚未适配漏洞源（含麒麟）；系统包任务不会按其他发行版替代判定。应用依赖和镜像可分别检查"}
	}
	major, _, _ := strings.Cut(values["VERSION_ID"], ".")
	if id == "centos" && (strings.Contains(strings.ToLower(values["NAME"]), "stream") || values["VARIANT_ID"] == "stream" || (major != "6" && major != "7" && major != "8")) || id == "rhel" && major == "10" {
		return &taskflow.ExecutionError{UserMessage: "此系统版本不在当前 Trivy 系统漏洞覆盖范围内，不能将 SBOM 识别视为漏洞检查完成"}
	}
	return nil
}
