package assets

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"scanner-platform/internal/account"
)

func TestSQLiteAssetRegistry(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "accounts.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "testadmin", "Strong-Sample-Password-28"); err != nil {
		t.Fatal(err)
	}
	store, err := New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []Input{
		{Kind: "host", Address: "192.0.2.4/24", BusinessGroup: "QA", Owner: "Owner"},
		{Kind: "host", Address: "example.com", BusinessGroup: "QA", Owner: "Owner"},
		{Kind: "host", Address: "192.0.2.4", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{80, 80}},
		{Kind: "host", Address: "192.0.2.4", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{70000}},
		{Kind: "image_repo", Address: "https://example.com/x", BusinessGroup: "QA", Owner: "Owner"},
		{Kind: "host", Address: "192.0.2.4", BusinessGroup: "", Owner: "Owner"},
	} {
		if _, err := store.Create(ctx, "testadmin", input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe asset was accepted: %+v / %v", input, err)
		}
	}
	input := Input{Kind: "host", Address: "192.0.2.4", BusinessGroup: "QA", Owner: "Owner", RequestedPorts: []int{443, 80}}
	asset, err := store.Create(ctx, "testadmin", input)
	if err != nil {
		t.Fatal(err)
	}
	if len(asset.Ports) != 0 || len(asset.RequestedPorts) != 2 || asset.RequestedPorts[0] != 80 {
		t.Fatalf("port request incorrectly granted: %+v", asset)
	}
	if _, err := store.Create(ctx, "testadmin", input); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate accepted: %v", err)
	}
	if _, err := store.Update(ctx, "testadmin", "missing", Edit{BusinessGroup: "A", Owner: "Owner"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown asset update: %v", err)
	}
	updated, err := store.Update(ctx, "testadmin", asset.ID, Edit{BusinessGroup: "New Group", Owner: "New Owner", RequestedPorts: []int{8080}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.BusinessGroup != "New Group" || updated.Owner != "New Owner" || len(updated.Ports) != 0 || len(updated.RequestedPorts) != 1 {
		t.Fatalf("unexpected update: %+v", updated)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 1 || list[0].RequestedPorts[0] != 8080 || len(list[0].Ports) != 0 {
		t.Fatalf("bad list: %+v / %v", list, err)
	}
	var auditCount int
	if err := accounts.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE object_type='asset'").Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit missing: %d %v", auditCount, err)
	}
	image, err := store.Create(ctx, "testadmin", Input{Kind: "image_repo", Address: "registry.example/repo/image", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil || image.Kind != "image_repo" {
		t.Fatalf("image registry rejected: %+v %v", image, err)
	}
}
