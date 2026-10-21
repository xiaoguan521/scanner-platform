//go:build linux

package bootstrap

import (
	"context"
	"strings"
	"testing"

	"scanner-platform/internal/taskflow"
)

func TestReadFencedProgressForwardsOnlyBoundedUpdates(t *testing.T) {
	var updates []taskflow.TaskProgress
	ctx := taskflow.WithProgressReporter(context.Background(), func(value taskflow.TaskProgress) {
		updates = append(updates, value)
	})
	err := readFencedProgress(ctx, strings.NewReader("{\"phase\":\"tcp_probe\",\"completed\":1,\"total\":2}\n{\"phase\":\"tcp_probe\",\"completed\":2,\"total\":2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 || updates[0].Completed != 1 || updates[1].Completed != 2 {
		t.Fatalf("updates = %#v", updates)
	}
}

func TestReadFencedProgressRejectsMalformedUpdate(t *testing.T) {
	ctx := context.Background()
	if err := readFencedProgress(ctx, strings.NewReader("{\"phase\":\"tcp_probe\",\"completed\":2,\"total\":1}\n")); err == nil {
		t.Fatal("invalid progress update accepted")
	}
	if err := readFencedProgress(ctx, strings.NewReader("{\"phase\":\"tcp_probe\",\"completed\":0,\"total\":0,\"unexpected\":true}\n")); err == nil {
		t.Fatal("unknown progress field accepted")
	}
}
