package taskflow

import (
	"context"
	"strings"
	"testing"
)

func TestLiveServicesClipsTextAndDropsOversizedLists(t *testing.T) {
	long := strings.Repeat("a", MaxLiveText+50)
	got := LiveServices([]ServiceResult{{Port: 80, Kind: "HTTP", Scheme: "http", Title: long, Software: "nginx"}})
	if len(got) != 1 || len(got[0].Title) != MaxLiveText || got[0].Software != "nginx" {
		t.Fatalf("clipped services = %+v", got)
	}
	if LiveServices(make([]ServiceResult, MaxLiveServices+1)) != nil {
		t.Fatal("oversized service lists must be omitted")
	}
}

func TestWorkerProgressKeepsFoundResultsAcrossCounterUpdates(t *testing.T) {
	var p workerProgress
	p.update(TaskProgress{Phase: "service_identification", Total: 2, OpenPorts: []int{22, 80}})
	p.update(TaskProgress{Phase: "http_scan", Total: 1, HTTPPorts: []int{80}, Services: []LiveService{{Port: 80, Kind: "HTTP", Scheme: "http"}}})
	p.update(TaskProgress{Phase: "http_scan", Completed: 1, Total: 1})
	got, _ := p.snapshot()
	if len(got.OpenPorts) != 2 || len(got.HTTPPorts) != 1 || len(got.Services) != 1 || got.Completed != 1 {
		t.Fatalf("snapshot lost found results: %+v", got)
	}
}

func TestReportFoundDropsOversizedPortLists(t *testing.T) {
	var seen TaskProgress
	ctx := WithProgressReporter(context.Background(), func(p TaskProgress) { seen = p })
	ReportFound(ctx, "service_identification", 0, 1, Found{Open: make([]int, MaxLivePorts+1)})
	if seen.OpenPorts != nil {
		t.Fatal("oversized open-port list must be omitted")
	}
	ReportFound(ctx, "service_identification", 0, 1, Found{Open: []int{80}})
	if len(seen.OpenPorts) != 1 {
		t.Fatalf("open ports = %v", seen.OpenPorts)
	}
}
