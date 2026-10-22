package bootstrap

import "testing"

func TestRepeatableStringFlag(t *testing.T) {
	var flag repeatableStringFlag
	if err := flag.Set("  old.pem  "); err != nil {
		t.Fatalf("set first key: %v", err)
	}
	if err := flag.Set("new.pem"); err != nil {
		t.Fatalf("set second key: %v", err)
	}
	if got, want := flag.String(), "old.pem,new.pem"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if err := flag.Set("   "); err == nil {
		t.Fatal("blank key should be rejected")
	}
}
