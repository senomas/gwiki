package index

import (
	"context"
	"database/sql"
	"time"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type retryRow struct {
	ctx     context.Context
	query   func() *sql.Row
	timeout time.Duration
}

func (r retryRow) Scan(dest ...any) error {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		err := r.query().Scan(dest...)
		if err == nil || !isSQLiteBusy(err) {
			return err
		}
		if r.timeout <= 0 {
			return err
		}
		if r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		if time.Since(start) >= r.timeout {
			return err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) queryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	return retryRow{
		ctx:     ctx,
		query:   func() *sql.Row { return i.db.QueryRowContext(ctx, query, args...) },
		timeout: i.lockTimeout,
	}
}

func (i *Index) queryRowContextTx(ctx context.Context, tx *sql.Tx, query string, args ...any) rowScanner {
	return retryRow{
		ctx:     ctx,
		query:   func() *sql.Row { return tx.QueryRowContext(ctx, query, args...) },
		timeout: i.lockTimeout,
	}
}

func (i *Index) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		res, err := i.db.ExecContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			return res, err
		}
		if i.lockTimeout <= 0 {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) execContextTx(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		res, err := tx.ExecContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			return res, err
		}
		if i.lockTimeout <= 0 {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) queryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		rows, err := i.db.QueryContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			return rows, err
		}
		if i.lockTimeout <= 0 {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func retryDelay(attempt int) time.Duration {
	delay := time.Duration(attempt+1) * 40 * time.Millisecond
	if delay > 300*time.Millisecond {
		delay = 300 * time.Millisecond
	}
	return delay
}
