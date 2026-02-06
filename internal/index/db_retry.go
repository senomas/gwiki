package index

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type retryRow struct {
	ctx         context.Context
	query       func() *sql.Row
	timeout     time.Duration
	queryText   string
	queryArgs   []any
	queryCaller string
}

func (r retryRow) Scan(dest ...any) error {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		if attempt == 0 {
			slog.Debug("sql query row attempt", "query", r.queryText, "args", r.queryArgs, "caller", r.queryCaller, "attempt", attempt+1)
		}
		err := r.query().Scan(dest...)
		if err == nil || !isSQLiteBusy(err) {
			slog.Debug("sql query row done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err)
			return err
		}
		slog.Debug("sql query row busy", "query", r.queryText, "args", r.queryArgs, "caller", r.queryCaller, "attempt", attempt+1, "err", err)
		if attempt >= 1 {
			slog.Debug("sql query row done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "max-retries")
			return err
		}
		if r.timeout <= 0 {
			slog.Debug("sql query row done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "no-timeout")
			return err
		}
		if r.ctx.Err() != nil {
			slog.Debug("sql query row done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", r.ctx.Err(), "reason", "context")
			return r.ctx.Err()
		}
		if time.Since(start) >= r.timeout {
			slog.Debug("sql query row done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "timeout")
			return err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) queryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	_, file, line, ok := runtime.Caller(1)
	caller := "unknown"
	if ok {
		caller = file + ":" + fmt.Sprint(line)
	}
	slog.Debug("sql query", "query", query, "args", args, "caller", caller)
	return retryRow{
		ctx:         ctx,
		query:       func() *sql.Row { return i.db.QueryRowContext(ctx, query, args...) },
		timeout:     i.lockTimeout,
		queryText:   query,
		queryArgs:   args,
		queryCaller: caller,
	}
}

func (i *Index) queryRowContextTx(ctx context.Context, tx *sql.Tx, query string, args ...any) rowScanner {
	_, file, line, ok := runtime.Caller(1)
	caller := "unknown"
	if ok {
		caller = file + ":" + fmt.Sprint(line)
	}
	slog.Debug("sql query tx", "query", query, "args", args, "caller", caller)
	return retryRow{
		ctx:         ctx,
		query:       func() *sql.Row { return tx.QueryRowContext(ctx, query, args...) },
		timeout:     i.lockTimeout,
		queryText:   query,
		queryArgs:   args,
		queryCaller: caller,
	}
}

func (i *Index) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	slog.Debug("sql exec", "query", query, "args", args)
	start := time.Now()
	for attempt := 0; ; attempt++ {
		res, err := i.db.ExecContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			slog.Debug("sql exec done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err)
			return res, err
		}
		if attempt >= 1 {
			slog.Debug("sql exec done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "max-retries")
			return nil, err
		}
		if i.lockTimeout <= 0 {
			slog.Debug("sql exec done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "no-timeout")
			return nil, err
		}
		if ctx.Err() != nil {
			slog.Debug("sql exec done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", ctx.Err(), "reason", "context")
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			slog.Debug("sql exec done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "timeout")
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) execContextTx(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	slog.Debug("sql exec tx", "query", query, "args", args)
	start := time.Now()
	for attempt := 0; ; attempt++ {
		res, err := tx.ExecContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			slog.Debug("sql exec tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err)
			return res, err
		}
		if attempt >= 1 {
			slog.Debug("sql exec tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "max-retries")
			return nil, err
		}
		if i.lockTimeout <= 0 {
			slog.Debug("sql exec tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "no-timeout")
			return nil, err
		}
		if ctx.Err() != nil {
			slog.Debug("sql exec tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", ctx.Err(), "reason", "context")
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			slog.Debug("sql exec tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "timeout")
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) queryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	slog.Debug("sql query", "query", query, "args", args)
	start := time.Now()
	for attempt := 0; ; attempt++ {
		rows, err := i.db.QueryContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			slog.Debug("sql query done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err)
			return rows, err
		}
		if attempt >= 1 {
			slog.Debug("sql query done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "max-retries")
			return nil, err
		}
		if i.lockTimeout <= 0 {
			slog.Debug("sql query done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "no-timeout")
			return nil, err
		}
		if ctx.Err() != nil {
			slog.Debug("sql query done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", ctx.Err(), "reason", "context")
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			slog.Debug("sql query done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "timeout")
			return nil, err
		}
		time.Sleep(retryDelay(attempt))
	}
}

func (i *Index) queryContextTx(ctx context.Context, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	slog.Debug("sql query tx", "query", query, "args", args)
	start := time.Now()
	for attempt := 0; ; attempt++ {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err == nil || !isSQLiteBusy(err) {
			slog.Debug("sql query tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err)
			return rows, err
		}
		if attempt >= 1 {
			slog.Debug("sql query tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "max-retries")
			return nil, err
		}
		if i.lockTimeout <= 0 {
			slog.Debug("sql query tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "no-timeout")
			return nil, err
		}
		if ctx.Err() != nil {
			slog.Debug("sql query tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", ctx.Err(), "reason", "context")
			return nil, ctx.Err()
		}
		if time.Since(start) >= i.lockTimeout {
			slog.Debug("sql query tx done", "duration_ms", time.Since(start).Milliseconds(), "attempts", attempt+1, "err", err, "reason", "timeout")
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

func (i *Index) beginTx(ctx context.Context, name string) (*sql.Tx, time.Time, error) {
	start := time.Now()
	slog.Debug("sql tx begin", "op", name)
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("sql tx begin failed", "op", name, "err", err)
		return nil, start, err
	}
	return tx, start, nil
}

func (i *Index) commitTx(tx *sql.Tx, name string, start time.Time) error {
	if tx == nil {
		return sql.ErrTxDone
	}
	err := tx.Commit()
	slog.Debug("sql tx commit", "op", name, "duration_ms", time.Since(start).Milliseconds(), "err", err)
	return err
}

func (i *Index) rollbackTx(tx *sql.Tx, name string, start time.Time) {
	if tx == nil {
		return
	}
	err := tx.Rollback()
	if err == sql.ErrTxDone {
		slog.Debug("sql tx rollback", "op", name, "duration_ms", time.Since(start).Milliseconds(), "err", err)
		return
	}
	if err != nil {
		slog.Warn("sql tx rollback failed", "op", name, "duration_ms", time.Since(start).Milliseconds(), "err", err)
		return
	}
	slog.Debug("sql tx rollback", "op", name, "duration_ms", time.Since(start).Milliseconds(), "err", err)
}
