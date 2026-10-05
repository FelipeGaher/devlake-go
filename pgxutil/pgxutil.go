// Package pgxutil holds small pgx/v5 helpers for PostgreSQL-backed services:
// pool construction, the DBTX interface for transaction-agnostic
// repositories, and unique-violation detection.
package pgxutil

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions tunes the connection pool. Zero fields use DefaultPoolOptions.
type PoolOptions struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	// StatementTimeout, if > 0, sets Postgres' statement_timeout on every
	// connection the pool opens: a server-side backstop against a runaway
	// query holding a pooled connection indefinitely. Zero leaves the server
	// default (normally no timeout).
	StatementTimeout time.Duration
}

// DefaultPoolOptions suits a single small service replica.
var DefaultPoolOptions = PoolOptions{
	MaxConns:          20,
	MinConns:          2,
	MaxConnLifetime:   30 * time.Minute,
	MaxConnIdleTime:   5 * time.Minute,
	HealthCheckPeriod: time.Minute,
}

// Connect creates a pool for databaseURL and pings it, so a bad URL or an
// unreachable database fails at startup.
func Connect(ctx context.Context, databaseURL string, opts PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("pgxutil: parse db config: %w", err)
	}
	d := DefaultPoolOptions
	cfg.MaxConns = pick(opts.MaxConns, d.MaxConns)
	cfg.MinConns = pick(opts.MinConns, d.MinConns)
	cfg.MaxConnLifetime = pick(opts.MaxConnLifetime, d.MaxConnLifetime)
	cfg.MaxConnIdleTime = pick(opts.MaxConnIdleTime, d.MaxConnIdleTime)
	cfg.HealthCheckPeriod = pick(opts.HealthCheckPeriod, d.HealthCheckPeriod)
	if opts.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(opts.StatementTimeout.Milliseconds(), 10)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgxutil: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgxutil: ping database: %w", err)
	}
	return pool, nil
}

func pick[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// DBTX is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx, so repository
// methods can run inside or outside a transaction transparently.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// TxBeginner is satisfied by *pgxpool.Pool and *pgx.Conn.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// WithTx runs fn in a transaction, committing if it returns nil and rolling
// back otherwise (including on panic, which is re-raised).
func WithTx(ctx context.Context, db TxBeginner, fn func(tx pgx.Tx) error) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgxutil: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UniqueViolationCode is Postgres' SQLSTATE for unique_violation.
const UniqueViolationCode = "23505"

// IsUniqueViolation reports whether err is a Postgres unique violation.
func IsUniqueViolation(err error) bool {
	_, ok := UniqueViolationConstraint(err)
	return ok
}

// UniqueViolationConstraint reports the constraint/index name of a unique
// violation, so callers can tell which column collided (e.g. username vs
// email) and return a specific sentinel instead of a generic conflict.
func UniqueViolationConstraint(err error) (name string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == UniqueViolationCode {
		return pgErr.ConstraintName, true
	}
	return "", false
}
