//go:build linux && lab

package poc01

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/portprobe"
	"scanner-platform/internal/taskflow"
)

// These wire structs intentionally mirror the private bootstrap protocol. The
// test only supplies a fixed port-probe task and never exercises a real target.
type fencedWorkerConfigWire struct {
	Executable    string `json:"Executable"`
	NftPath       string `json:"NftPath"`
	SetprivPath   string `json:"SetprivPath"`
	ParentNetNSFD int    `json:"ParentNetNSFD"`
	BinDir        string `json:"BinDir"`
	RulesDir      string `json:"RulesDir"`
	RuntimeDir    string `json:"RuntimeDir"`
	InputsDir     string `json:"InputsDir"`
	Rate          int    `json:"Rate"`
	Timeout       int    `json:"Timeout"`
}

type fencedWorkerPermitWire struct {
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

type fencedWorkerInputWire struct {
	Operation      string                   `json:"operation"`
	Task           taskflow.Task            `json:"task"`
	Config         fencedWorkerConfigWire   `json:"config"`
	Infrastructure []fencedWorkerPermitWire `json:"infrastructure"`
}

func TestFencedWorkerTask(t *testing.T) {
	if os.Getenv("LAB_ENV") != "isolated" {
		t.Skip("requires an explicitly approved isolated lab")
	}
	workerPath := os.Getenv("LAB_WORKER_BIN")
	if workerPath == "" {
		t.Skip("LAB_WORKER_BIN is required for the end-to-end worker fence check")
	}
	workerPath, err := filepath.Abs(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(workerPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("LAB_WORKER_BIN is not a regular file: %v", err)
	}

	if os.Getenv("_POC01_WORKER_UNSHARE_CHILD") != "1" {
		parentNS, err := os.Open("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer parentNS.Close()
		progressRead, progressWrite, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer progressRead.Close()
		child := exec.Command("unshare", "--net", os.Args[0], "-test.run=^TestFencedWorkerTask$", "-test.v")
		child.ExtraFiles = []*os.File{parentNS, progressWrite}
		child.Env = append(os.Environ(),
			"_POC01_WORKER_UNSHARE_CHILD=1",
			"LAB_WORKER_BIN="+workerPath,
			"LAB_ENV=isolated",
		)
		var stdout, stderr bytes.Buffer
		child.Stdout, child.Stderr = &stdout, &stderr
		if err := child.Start(); err != nil {
			progressWrite.Close()
			t.Fatal(err)
		}
		_ = progressWrite.Close()
		progressDone := make(chan []byte, 1)
		go func() {
			data, _ := io.ReadAll(progressRead)
			progressDone <- data
		}()
		waitErr := child.Wait()
		progress := <-progressDone
		if waitErr != nil {
			t.Fatalf("worker namespace child failed: %v\nstdout=%s\nstderr=%s\nprogress=%s", waitErr, stdout.String(), stderr.String(), progress)
		}
		if !bytes.Contains(stdout.Bytes(), []byte(`"status":"ok"`)) {
			t.Fatalf("worker did not return success: %s", stdout.String())
		}
		if !bytes.Contains(progress, []byte(`"phase":"tcp_probe"`)) || !bytes.Contains(progress, []byte(`"completed":1`)) {
			t.Fatalf("worker progress was not forwarded: %s", progress)
		}
		return
	}

	parentNS := os.NewFile(3, "parent-network-namespace")
	progress := os.NewFile(4, "fenced-progress")
	if parentNS == nil || progress == nil {
		t.Fatal("trusted worker descriptors unavailable")
	}
	defer parentNS.Close()
	defer progress.Close()
	input := fencedWorkerInputWire{
		Operation: "probe-ports",
		Task: taskflow.Task{
			ID:           "lab-fence-port-probe",
			AssetID:      "lab-asset",
			Engines:      []string{"port-probe"},
			HardDeadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
			Chunks:       []taskflow.Chunk{{Targets: []string{"127.0.0.1"}}},
			PortProbeConfig: portprobe.Config{
				Preset:      portprobe.PresetCustom,
				Ranges:      []portprobe.Range{{Start: 1, End: 1}},
				OpsApproved: true,
				Intensity:   portprobe.IntensityGentle,
			},
			PortProbePorts: []int{1},
		},
		Config: fencedWorkerConfigWire{
			Executable:    workerPath,
			NftPath:       "/usr/sbin/nft",
			SetprivPath:   "/usr/bin/setpriv",
			ParentNetNSFD: 3,
			BinDir:        "/runtime/bin",
			RulesDir:      "/vuln-data",
			RuntimeDir:    "/runtime/worker",
			InputsDir:     "/runtime/inputs",
			Rate:          5,
			Timeout:       10,
		},
		Infrastructure: []fencedWorkerPermitWire{{IP: "198.51.100.7", Port: 8443, Protocol: "tcp"}},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(workerPath, "--fence-child")
	command.Stdin = bytes.NewReader(raw)
	command.ExtraFiles = []*os.File{parentNS, progress}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("fenced worker failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"ok"`) {
		t.Fatalf("fenced worker did not return success: %s", stdout.String())
	}
	fmt.Fprint(os.Stdout, stdout.String())
}
