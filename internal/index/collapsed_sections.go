package index

import (
	"context"
	"errors"
	"strings"
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
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM collapsed_sections WHERE note_id=?", noteID); err != nil {
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
			return err
		}
	}
	return tx.Commit()
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
