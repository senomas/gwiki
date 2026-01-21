package index

import (
	"context"
	"errors"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type CollapsedSection struct {
	LineNo int
}

func (i *Index) SetCollapsedSections(ctx context.Context, noteID string, sections []CollapsedSection) error {
	noteID = strings.TrimSpace(noteID)
	if noteID == "" {
		return errors.New("note id required")
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		tx, err := i.db.BeginTx(ctx, nil)
		if err != nil {
			if isSQLiteBusy(err) {
				lastErr = err
				time.Sleep(time.Duration(attempt+1) * 40 * time.Millisecond)
				continue
			}
			return err
		}

		if _, err := i.execContextTx(ctx, tx, "DELETE FROM collapsed_sections WHERE note_id=?", noteID); err != nil {
			_ = tx.Rollback()
			if isSQLiteBusy(err) {
				lastErr = err
				time.Sleep(time.Duration(attempt+1) * 40 * time.Millisecond)
				continue
			}
			return err
		}
		for _, section := range sections {
			if section.LineNo <= 0 {
				continue
			}
			if _, err := i.execContextTx(ctx, tx, `
				INSERT INTO collapsed_sections(note_id, line_no)
				VALUES(?, ?)
			`, noteID, section.LineNo); err != nil {
				_ = tx.Rollback()
				if isSQLiteBusy(err) {
					lastErr = err
					time.Sleep(time.Duration(attempt+1) * 40 * time.Millisecond)
					continue
				}
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			if isSQLiteBusy(err) {
				lastErr = err
				time.Sleep(time.Duration(attempt+1) * 40 * time.Millisecond)
				continue
			}
			return err
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}

func (i *Index) CollapsedSections(ctx context.Context, noteID string) ([]CollapsedSection, error) {
	noteID = strings.TrimSpace(noteID)
	if noteID == "" {
		return nil, errors.New("note id required")
	}
	rows, err := i.queryContext(ctx, `
		SELECT line_no
		FROM collapsed_sections
		WHERE note_id=?
		ORDER BY line_no
	`, noteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sections := []CollapsedSection{}
	for rows.Next() {
		var section CollapsedSection
		if err := rows.Scan(&section.LineNo); err != nil {
			return nil, err
		}
		sections = append(sections, section)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

func isSQLiteBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		if se.Code() == sqlite3.SQLITE_BUSY || se.Code() == sqlite3.SQLITE_LOCKED {
			return true
		}
	}
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "database is locked") || strings.Contains(msg, "database is busy") {
			return true
		}
	}
	return false
}
