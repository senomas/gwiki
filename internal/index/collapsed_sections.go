package index

import (
	"context"
	"errors"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const maxCollapsedLineLen = 500

type CollapsedSection struct {
	LineNo int
	Line   string
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

		if _, err := tx.ExecContext(ctx, "DELETE FROM collapsed_sections WHERE note_id=?", noteID); err != nil {
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
			line := strings.TrimSpace(section.Line)
			if line == "" {
				continue
			}
			if len(line) > maxCollapsedLineLen {
				line = line[:maxCollapsedLineLen]
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO collapsed_sections(note_id, line_no, line)
				VALUES(?, ?, ?)
			`, noteID, section.LineNo, line); err != nil {
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
	rows, err := i.db.QueryContext(ctx, `
		SELECT line_no, line
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
		if err := rows.Scan(&section.LineNo, &section.Line); err != nil {
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
		if se.Code() == sqlite3.SQLITE_BUSY {
			return true
		}
	}
	return false
}
