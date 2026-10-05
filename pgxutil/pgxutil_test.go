package pgxutil

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestUniqueViolationConstraint(t *testing.T) {
	uv := &pgconn.PgError{Code: "23505", ConstraintName: "users_email_key"}
	if name, ok := UniqueViolationConstraint(fmt.Errorf("insert: %w", uv)); !ok || name != "users_email_key" {
		t.Errorf("wrapped unique violation: %q %v", name, ok)
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Error("FK violation reported as unique violation")
	}
	if IsUniqueViolation(errors.New("plain")) || IsUniqueViolation(nil) {
		t.Error("non-pg error reported as unique violation")
	}
}

func TestPick(t *testing.T) {
	if pick(int32(0), 20) != 20 || pick(int32(5), 20) != 5 {
		t.Error("pick")
	}
}
