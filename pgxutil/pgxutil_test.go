package pgxutil

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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

func TestApplyOptions_SessionTimeouts(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://u@localhost/db")
	if err != nil {
		t.Fatal(err)
	}
	applyOptions(cfg, PoolOptions{StatementTimeout: 10 * time.Second, IdleInTxTimeout: 30 * time.Second})
	rp := cfg.ConnConfig.RuntimeParams
	if rp["statement_timeout"] != "10000" || rp["idle_in_transaction_session_timeout"] != "30000" {
		t.Fatalf("runtime params = %v", rp)
	}
	if cfg.MaxConns != DefaultPoolOptions.MaxConns {
		t.Fatalf("max conns = %d, want the default", cfg.MaxConns)
	}

	cfg, _ = pgxpool.ParseConfig("postgres://u@localhost/db")
	applyOptions(cfg, PoolOptions{})
	if _, set := cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"]; set {
		t.Fatal("zero IdleInTxTimeout should leave the server default")
	}
}
