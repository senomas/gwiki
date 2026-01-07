package index

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Index struct {
	db *sql.DB
}

type NoteSummary struct {
	Path  string
	Title string
}

type SearchResult struct {
	Path    string
	Title   string
	Snippet string
}

type TagSummary struct {
	Name  string
	Count int
}

type UpdateDaySummary struct {
	Day   string
	Count int
}

type fileRecord struct {
	ID        int
	Hash      string
	MTimeUnix int64
	Size      int64
}

const secondsPerDay = 86400

func Open(path string) (*Index, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	return &Index{db: db}, nil
}

func (i *Index) Close() error {
	if i.db == nil {
		return nil
	}
	return i.db.Close()
}

func (i *Index) Init(ctx context.Context, repoPath string) error {
	if _, err := i.db.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	version, err := i.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if version != schemaVersion {
		if err := i.setSchemaVersion(ctx, schemaVersion); err != nil {
			return err
		}
		return i.RebuildFromFS(ctx, repoPath)
	}
	return i.RecheckFromFS(ctx, repoPath)
}

func (i *Index) schemaVersion(ctx context.Context) (int, error) {
	var v int
	err := i.db.QueryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

func (i *Index) setSchemaVersion(ctx context.Context, v int) error {
	_, err := i.db.ExecContext(ctx, "DELETE FROM schema_version")
	if err != nil {
		return err
	}
	_, err = i.db.ExecContext(ctx, "INSERT INTO schema_version(version) VALUES(?)", v)
	return err
}

func (i *Index) RebuildFromFS(ctx context.Context, repoPath string) error {
	notesRoot := filepath.Join(repoPath, "notes")
	clear := []string{
		"DELETE FROM file_updates",
		"DELETE FROM file_tags",
		"DELETE FROM tags",
		"DELETE FROM links",
		"DELETE FROM tasks",
		"DELETE FROM files",
		"DELETE FROM fts",
	}
	for _, stmt := range clear {
		if _, err := i.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	return filepath.WalkDir(notesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(notesRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return i.IndexNote(ctx, rel, content, info.ModTime(), info.Size())
	})
}

func (i *Index) RecheckFromFS(ctx context.Context, repoPath string) error {
	notesRoot := filepath.Join(repoPath, "notes")
	records, err := i.loadFileRecords(ctx)
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(records))
	err = filepath.WalkDir(notesRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(notesRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		seen[rel] = true

		info, err := d.Info()
		if err != nil {
			return err
		}
		rec, ok := records[rel]
		if !ok {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return i.IndexNote(ctx, rel, content, info.ModTime(), info.Size())
		}
		if rec.MTimeUnix == info.ModTime().Unix() && rec.Size == info.Size() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(content)
		checksum := hex.EncodeToString(hash[:])
		if checksum == rec.Hash {
			_, err := i.db.ExecContext(ctx, "UPDATE files SET mtime_unix=?, size=? WHERE id=?", info.ModTime().Unix(), info.Size(), rec.ID)
			return err
		}
		return i.IndexNote(ctx, rel, content, info.ModTime(), info.Size())
	})
	if err != nil {
		return err
	}

	return i.removeMissingRecords(ctx, records, seen)
}

func (i *Index) IndexNote(ctx context.Context, notePath string, content []byte, mtime time.Time, size int64) error {
	meta := ParseContent(string(content))
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])

	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingID int
	var createdAt int64
	err = tx.QueryRowContext(ctx, "SELECT id, created_at FROM files WHERE path=?", notePath).Scan(&existingID, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		createdAt = time.Now().Unix()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO files(path, title, hash, mtime_unix, size, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?)
		`, notePath, meta.Title, checksum, mtime.Unix(), size, createdAt, time.Now().Unix())
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT id FROM files WHERE path=?", notePath).Scan(&existingID); err != nil {
			return err
		}
	} else if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE files SET title=?, hash=?, mtime_unix=?, size=?, updated_at=? WHERE id=?
		`, meta.Title, checksum, mtime.Unix(), size, time.Now().Unix(), existingID)
		if err != nil {
			return err
		}
	} else {
		return err
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM file_tags WHERE file_id=?", existingID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM links WHERE from_file_id=?", existingID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM tasks WHERE file_id=?", existingID); err != nil {
		return err
	}
	updatedAt := mtime.Unix()
	updatedDay := updatedAt / secondsPerDay
	if _, err := tx.ExecContext(ctx, "INSERT INTO file_updates(file_id, updated_at, updated_day) VALUES(?, ?, ?)", existingID, updatedAt, updatedDay); err != nil {
		return err
	}

	for _, tag := range meta.Tags {
		if tag == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO tags(name) VALUES(?)", tag)
		if err != nil {
			return err
		}
		var tagID int
		if err := tx.QueryRowContext(ctx, "SELECT id FROM tags WHERE name=?", tag).Scan(&tagID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO file_tags(file_id, tag_id) VALUES(?, ?)", existingID, tagID); err != nil {
			return err
		}
	}

	for _, link := range meta.Links {
		if link.Ref == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO links(from_file_id, to_ref, to_file_id, kind) VALUES(?, ?, NULL, ?)", existingID, link.Ref, link.Kind); err != nil {
			return err
		}
	}

	for _, task := range meta.Tasks {
		checked := 0
		if task.Done {
			checked = 1
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(file_id, line_no, text, checked, due_date) VALUES(?, ?, ?, ?, ?)", existingID, task.LineNo, task.Text, checked, nullIfEmpty(task.Due)); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM fts WHERE path=?", notePath); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO fts(path, title, body) VALUES(?, ?, ?)", notePath, meta.Title, string(content)); err != nil {
		return err
	}

	return tx.Commit()
}

func (i *Index) RecentNotes(ctx context.Context, limit int) ([]NoteSummary, error) {
	rows, err := i.db.QueryContext(ctx, "SELECT path, title FROM files ORDER BY updated_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		if err := rows.Scan(&n.Path, &n.Title); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	rows, err := i.db.QueryContext(ctx, "SELECT path, title, snippet(fts, 2, '', '', '...', 10) FROM fts WHERE fts MATCH ? LIMIT ?", query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.Path, &r.Title, &r.Snippet); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func (i *Index) ListTags(ctx context.Context, limit int) ([]TagSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := i.db.QueryContext(ctx, `
		SELECT tags.name, COUNT(file_tags.file_id)
		FROM tags
		LEFT JOIN file_tags ON tags.id = file_tags.tag_id
		GROUP BY tags.id
		ORDER BY tags.name
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []TagSummary
	for rows.Next() {
		var t TagSummary
		if err := rows.Scan(&t.Name, &t.Count); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (i *Index) ListUpdateDays(ctx context.Context, limit int) ([]UpdateDaySummary, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := i.db.QueryContext(ctx, `
		SELECT updated_day, COUNT(*)
		FROM file_updates
		GROUP BY updated_day
		ORDER BY updated_day DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var days []UpdateDaySummary
	for rows.Next() {
		var dayUnix int64
		var count int
		if err := rows.Scan(&dayUnix, &count); err != nil {
			return nil, err
		}
		day := time.Unix(dayUnix*secondsPerDay, 0).UTC().Format("2006-01-02")
		days = append(days, UpdateDaySummary{Day: day, Count: count})
	}
	return days, rows.Err()
}

func (i *Index) loadFileRecords(ctx context.Context) (map[string]fileRecord, error) {
	rows, err := i.db.QueryContext(ctx, "SELECT id, path, hash, mtime_unix, size FROM files")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := map[string]fileRecord{}
	for rows.Next() {
		var path string
		var rec fileRecord
		if err := rows.Scan(&rec.ID, &path, &rec.Hash, &rec.MTimeUnix, &rec.Size); err != nil {
			return nil, err
		}
		records[path] = rec
	}
	return records, rows.Err()
}

func (i *Index) removeMissingRecords(ctx context.Context, records map[string]fileRecord, seen map[string]bool) error {
	type missing struct {
		id   int
		path string
	}
	var missingRows []missing
	for path, rec := range records {
		if !seen[path] {
			missingRows = append(missingRows, missing{id: rec.ID, path: path})
		}
	}
	if len(missingRows) == 0 {
		return nil
	}

	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, row := range missingRows {
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_tags WHERE file_id=?", row.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM links WHERE from_file_id=?", row.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM tasks WHERE file_id=?", row.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_updates WHERE file_id=?", row.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM fts WHERE path=?", row.path); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM files WHERE id=?", row.id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func (i *Index) NoteExists(ctx context.Context, notePath string) (bool, error) {
	var id int
	err := i.db.QueryRowContext(ctx, "SELECT id FROM files WHERE path=?", notePath).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (i *Index) DumpNoteList(ctx context.Context) ([]NoteSummary, error) {
	rows, err := i.db.QueryContext(ctx, "SELECT path, title FROM files ORDER BY path")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		if err := rows.Scan(&n.Path, &n.Title); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) DebugDump(ctx context.Context) (string, error) {
	notes, err := i.DumpNoteList(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, n := range notes {
		fmt.Fprintf(&b, "%s\t%s\n", n.Path, n.Title)
	}
	return b.String(), nil
}
