package assets

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"scanner-platform/internal/account"
)

const csvHeader = "kind,address,businessGroup,owner,name\n"

func TestParseAssetImportCSV(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		fail       error
		invalid    int
	}{
		{"host", csvHeader + "host,192.0.2.10, QA , Owner ,Example\n", nil, 0},
		{"image", csvHeader + "image_repo,registry.example.com/team/image,QA,Owner,Example\n", nil, 0},
		{"optional name", "kind,address,businessGroup,owner\nhost,192.0.2.10,QA,Owner\n", nil, 0},
		{"empty", "", ErrImportFormat, 0},
		{"header only", csvHeader, ErrImportFormat, 0},
		{"bad encoding", csvHeader + string([]byte{255}), ErrImportFormat, 0},
		{"unknown column", "kind,address,businessGroup,owner,requestedPorts\n", ErrImportFormat, 0},
		{"duplicate header", "kind,address,owner,owner\n", ErrImportFormat, 0},
		{"reordered header", "address,kind,businessGroup,owner\n", ErrImportFormat, 0},
		{"BOM", "\ufeff" + csvHeader, ErrImportFormat, 0},
		{"ragged", csvHeader + "host,192.0.2.10,QA,Owner\n", nil, 1},
		{"domain", csvHeader + "host,example.com,QA,Owner,Example\n", nil, 1},
		{"CIDR", csvHeader + "host,192.0.2.0/24,QA,Owner,Example\n", nil, 1},
		{"invalid image", csvHeader + "image_repo,https://registry.example.com/image,QA,Owner,Example\n", nil, 1},
		{"missing group", csvHeader + "host,192.0.2.10,,Owner,Example\n", nil, 1},
		{"long name", csvHeader + "host,192.0.2.10,QA,Owner," + strings.Repeat("x", 501) + "\n", nil, 1},
		{"control", csvHeader + "host,192.0.2.10,QA,Owner,Example\x00\n", nil, 1},
		{"duplicate", csvHeader + strings.Repeat("host,192.0.2.10,QA,Owner,Example\n", 2), nil, 1},
		{"canonical duplicate", csvHeader + "host,192.0.2.10,QA,Owner,A\nhost,::ffff:192.0.2.10,QA,Owner,B\n", nil, 1},
		{"quote", csvHeader + "host,\"192.0.2.10,QA,Owner,A\n", ErrImportFormat, 0},
		{"byte limit", strings.Repeat("x", MaxImportBytes+1), ErrImportLimit, 0},
		{"row limit", csvHeader + strings.Repeat("host,192.0.2.10,QA,Owner,Example\n", MaxImportRows+1), ErrImportLimit, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseImportCSV([]byte(tc.data))
			if !errors.Is(err, tc.fail) {
				t.Fatalf("err=%v want=%v", err, tc.fail)
			}
			if err == nil {
				invalid := 0
				for _, row := range got.Rows {
					if row.Reason != "" {
						invalid++
					}
				}
				if invalid != tc.invalid {
					t.Fatalf("invalid=%d want=%d", invalid, tc.invalid)
				}
			}
		})
	}
}
func importFixture(t *testing.T) (*Store, *account.Store, string) {
	t.Helper()
	accounts, err := account.New(filepath.Join(t.TempDir(), "import.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accounts.Close() })
	ctx := context.Background()
	if err := accounts.InitAdmin(ctx, "testadmin", "Safe-Example-Password-14"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "testadmin", "Safe-Example-Password-14")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { t.Error("import must never ping"); return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	return store, accounts, admin.ID
}
func TestAssetImportPreviewConfirmAndPrivacy(t *testing.T) {
	s, a, actor := importFixture(t)
	ctx := context.Background()
	var auditBefore int
	if err := a.SQLDB().QueryRow("SELECT count(*) FROM audit_logs").Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewImport(ctx, actor, []byte(ImportTemplate))
	if err != nil || preview.Valid != 2 || preview.PreviewID == "" {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	for _, table := range []string{"assets", "asset_profiles", "audit_logs"} {
		var count int
		if err := a.SQLDB().QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || (table != "audit_logs" && count != 0) || (table == "audit_logs" && count != auditBefore) {
			t.Fatalf("preview changed %s count=%d err=%v", table, count, err)
		}
	}
	if _, err := s.ConfirmImport(ctx, "another-user", preview.PreviewID); !errors.Is(err, ErrImportUnavailable) {
		t.Fatalf("cross user confirm=%v", err)
	}
	result, err := s.ConfirmImport(ctx, actor, preview.PreviewID)
	if err != nil || result.Imported != 2 {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
	if _, err := s.ConfirmImport(ctx, actor, preview.PreviewID); !errors.Is(err, ErrImportUnavailable) {
		t.Fatalf("repeat confirm=%v", err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("assets=%+v err=%v", list, err)
	}
	for _, asset := range list {
		if asset.Name == "" || asset.ReachabilityStatus != "UNCHECKED" || len(asset.Ports)+len(asset.RequestedPorts)+len(asset.SkippedPorts) != 0 {
			t.Fatalf("unsafe import=%+v", asset)
		}
	}
	var detail, objectID, encoded string
	if err := a.SQLDB().QueryRow("SELECT detail,object_id FROM audit_logs WHERE action='import_assets'").Scan(&detail, &objectID); err != nil || detail != `{"imported":2}` || objectID != "" {
		t.Fatalf("audit=%q id=%q err=%v", detail, objectID, err)
	}
	if err := a.SQLDB().QueryRow("SELECT rows_json FROM asset_import_previews WHERE id=?", preview.PreviewID).Scan(&encoded); err != nil || encoded != "[]" {
		t.Fatalf("retained rows=%q err=%v", encoded, err)
	}
	duplicate, err := s.PreviewImport(ctx, actor, []byte(ImportTemplate))
	if err != nil || duplicate.Invalid != 2 || duplicate.PreviewID != "" {
		t.Fatalf("existing duplicate=%+v err=%v", duplicate, err)
	}
}
func TestAssetImportExpiryReplacementAndAtomicConflict(t *testing.T) {
	s, a, actor := importFixture(t)
	ctx := context.Background()
	data := []byte(csvHeader + "host,192.0.2.10,QA,Owner,One\nhost,192.0.2.11,QA,Owner,Two\n")
	preview, err := s.PreviewImport(ctx, actor, data)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.PreviewImport(ctx, actor, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmImport(ctx, actor, preview.PreviewID); !errors.Is(err, ErrImportUnavailable) {
		t.Fatalf("replaced=%v", err)
	}
	if _, err := a.SQLDB().Exec("UPDATE asset_import_previews SET expires_at=0 WHERE id=?", next.PreviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmImport(ctx, actor, next.PreviewID); !errors.Is(err, ErrImportUnavailable) {
		t.Fatalf("expired=%v", err)
	}
	preview, err = s.PreviewImport(ctx, actor, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, actor, Input{Kind: "host", Address: "192.0.2.11", BusinessGroup: "QA", Owner: "Owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmImport(ctx, actor, preview.PreviewID); !errors.Is(err, ErrImportConflict) {
		t.Fatalf("conflict=%v", err)
	}
	var count int
	for _, table := range []string{"assets", "asset_profiles"} {
		if err := a.SQLDB().QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("partial %s count=%d err=%v", table, count, err)
		}
	}
	if err := a.SQLDB().QueryRow("SELECT count(*) FROM audit_logs WHERE action='import_assets'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed confirmation audit=%d err=%v", count, err)
	}
}
func TestAssetImportConcurrentConfirmation(t *testing.T) {
	s, a, actor := importFixture(t)
	ctx := context.Background()
	p, err := s.PreviewImport(ctx, actor, []byte(ImportTemplate))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.ConfirmImport(ctx, actor, p.PreviewID); errs <- err }()
	}
	wg.Wait()
	close(errs)
	success, denied := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrImportUnavailable) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("success=%d denied=%d", success, denied)
	}
	var count int
	if err := a.SQLDB().QueryRow("SELECT count(*) FROM assets").Scan(&count); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
func FuzzParseAssetImportCSV(f *testing.F) {
	f.Add([]byte(ImportTemplate))
	f.Add([]byte(csvHeader))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseImportCSV(data)
		if err == nil && (len(p.Rows) == 0 || len(p.Rows) > MaxImportRows) {
			t.Fatal("invalid accepted row count")
		}
	})
}
