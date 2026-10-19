package assets

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"scanner-platform/internal/account"
)

func TestCheckIPUsesOneBoundedPlatformPingAndRejectsNonIPTargets(t *testing.T) {
	for _, tc := range []struct {
		goos string
		ip   string
		args []string
	}{
		{"linux", "192.0.2.4", []string{"-n", "-c", "1", "-W", "2", "192.0.2.4"}},
		{"darwin", "2001:db8::4", []string{"-n", "-c", "1", "-W", "1800", "2001:db8::4"}},
		{"windows", "192.0.2.4", []string{"-n", "1", "-w", "1800", "192.0.2.4"}},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			called := false
			got, err := checkIP(context.Background(), tc.ip, tc.goos, func(ctx context.Context, name string, args ...string) (bool, error) {
				called = true
				if name != "ping" || !reflect.DeepEqual(args, tc.args) {
					t.Fatalf("ping command=%s args=%v", name, args)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("ping command has no timeout")
				}
				return true, nil
			})
			if err != nil || !got || !called {
				t.Fatalf("reachable=%v called=%v err=%v", got, called, err)
			}
		})
	}
	for _, target := range []string{"example.com", "192.0.2.1/24", "0.0.0.0", "224.0.0.1", "fe80::1%eth0"} {
		called := false
		if _, err := checkIP(context.Background(), target, "linux", func(context.Context, string, ...string) (bool, error) {
			called = true
			return false, nil
		}); !errors.Is(err, ErrInvalid) || called {
			t.Fatalf("target=%q called=%v err=%v", target, called, err)
		}
	}
}

func TestCheckReachabilityPersistsStatusAndAudit(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "accounts.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "testadmin", "Safe-Sample-Password-12"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "testadmin", "Safe-Sample-Password-12")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewWithPinger(accounts.SQLDB(), func(context.Context, string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	asset, err := store.Create(ctx, admin.ID, Input{Kind: "host", Address: "192.0.2.4", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.CheckReachability(ctx, admin.ID, asset.ID)
	if err != nil || result.Status != "NO_RESPONSE" || result.CheckedAt == "" {
		t.Fatalf("reachability=%+v err=%v", result, err)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 1 || list[0].ReachabilityStatus != "NO_RESPONSE" || list[0].ReachabilityCheckedAt != result.CheckedAt {
		t.Fatalf("persisted reachability=%+v err=%v", list, err)
	}
	var audits int
	if err := accounts.SQLDB().QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action='check_asset_reachability'").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("reachability audit count=%d err=%v", audits, err)
	}
	updated, err := store.Update(ctx, admin.ID, asset.ID, Edit{Address: "192.0.2.5", BusinessGroup: "QA", Owner: "Owner"})
	if err != nil || updated.ReachabilityStatus != "UNCHECKED" || updated.ReachabilityCheckedAt != "" {
		t.Fatalf("address change retained stale reachability: %+v err=%v", updated, err)
	}
	list, err = store.List(ctx)
	if err != nil || len(list) != 1 || list[0].ReachabilityStatus != "UNCHECKED" || list[0].ReachabilityCheckedAt != "" {
		t.Fatalf("address change did not clear persisted reachability: %+v err=%v", list, err)
	}
}
