package approvals

import (
	"errors"
	"testing"
)

func TestNewPostgresRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgres(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil database error=%v, want %v", err, ErrInvalid)
	}
}
