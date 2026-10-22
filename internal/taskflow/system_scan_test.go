package taskflow

import (
	"encoding/json"
	"testing"
)

func TestSystemScanCodeCoversEveryStatus(t *testing.T) {
	seen := map[string]bool{}
	for status, code := range systemScanCodes {
		if code == "" || code == "unknown" || seen[code] {
			t.Fatalf("status %q has an empty or duplicate code %q", status, code)
		}
		seen[code] = true
		if SystemScanCode(status) != code {
			t.Fatalf("lookup mismatch for %q", status)
		}
	}
	if len(systemScanCodes) != 14 {
		t.Fatalf("every SystemScan* constant needs a code, have %d", len(systemScanCodes))
	}
	if SystemScanCode("") != "" || SystemScanCode("其他说明") != "unknown" {
		t.Fatal("empty and unrecognized statuses")
	}
}

func TestTaskJSONIncludesSystemScanCode(t *testing.T) {
	data, err := json.Marshal(Task{ID: "task-1", SystemScanStatus: SystemScanAuthFailed})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["systemScanCode"] != "auth_failed" || decoded["systemScanStatus"] != SystemScanAuthFailed || decoded["id"] != "task-1" {
		t.Fatalf("unexpected task JSON: %s", data)
	}
	var round Task
	if err := json.Unmarshal(data, &round); err != nil || round.SystemScanStatus != SystemScanAuthFailed {
		t.Fatalf("task JSON must still decode: %+v %v", round, err)
	}
	data, _ = json.Marshal(Task{ID: "task-2"})
	empty := map[string]any{}
	if json.Unmarshal(data, &empty); empty["systemScanCode"] != nil {
		t.Fatalf("no status means no code: %s", data)
	}
	pointer, _ := json.Marshal(&Task{ID: "task-3", SystemScanStatus: SystemScanCompleted})
	if json.Unmarshal(pointer, &decoded); decoded["systemScanCode"] != "completed" {
		t.Fatalf("pointer marshal: %s", pointer)
	}
}
