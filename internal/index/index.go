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
	"path"
	"path/filepath"
	"sort"
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
	MTime time.Time
}

type NoteListFilter struct {
	Tags   []string
	Date   string
	Query  string
	Folder string
	Root   bool
	Limit  int
	Offset int
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

type TaskItem struct {
	Path      string
	Title     string
	LineNo    int
	Text      string
	DueDate   string
	UpdatedAt time.Time
}

type Backlink struct {
	FromPath  string
	FromTitle string
	LineNo    int
	Line      string
	Kind      string
}

type fileRecord struct {
	ID        int
	Hash      string
	MTimeUnix int64
	Size      int64
}

const secondsPerDay = 86400

func dateToDay(date string) (int64, error) {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0, err
	}
	return parsed.UTC().Unix() / secondsPerDay, nil
}

func applyVisibilityFilter(ctx context.Context, clauses *[]string, args *[]interface{}, table string) {
	if !publicOnly(ctx) {
		return
	}
	if table == "" {
		table = "files"
	}
	*clauses = append(*clauses, table+".visibility = ?")
	*args = append(*args, "public")
}

func applyFolderFilter(folder string, rootOnly bool, clauses *[]string, args *[]interface{}, table string) {
	if table == "" {
		table = "files"
	}
	if rootOnly {
		*clauses = append(*clauses, table+".path NOT LIKE ?")
		*args = append(*args, "%/%")
		return
	}
	if strings.TrimSpace(folder) == "" {
		return
	}
	folder = strings.TrimSuffix(folder, "/")
	*clauses = append(*clauses, table+".path LIKE ?")
	*args = append(*args, folder+"/%")
}

func folderWhere(folder string, rootOnly bool, table string) (string, []interface{}) {
	if table == "" {
		table = "files"
	}
	if rootOnly {
		return table + ".path NOT LIKE ?", []interface{}{"%/%"}
	}
	if strings.TrimSpace(folder) == "" {
		return "", nil
	}
	folder = strings.TrimSuffix(folder, "/")
	return table + ".path LIKE ?", []interface{}{folder + "/%"}
}

func slugify(input string) string {
	input = strings.ToLower(input)
	var b strings.Builder
	lastDash := false
	for _, r := range input {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "note"
	}
	return slug
}

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

func (i *Index) RemoveNoteByPath(ctx context.Context, path string) error {
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var id int
	err = tx.QueryRowContext(ctx, "SELECT id FROM files WHERE path=?", path).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	stmts := []string{
		"DELETE FROM file_histories WHERE file_id=?",
		"DELETE FROM file_tags WHERE file_id=?",
		"DELETE FROM links WHERE from_file_id=? OR to_file_id=?",
		"DELETE FROM tasks WHERE file_id=?",
		"DELETE FROM fts WHERE path=?",
		"DELETE FROM files WHERE id=?",
	}
	for _, stmt := range stmts {
		switch stmt {
		case "DELETE FROM links WHERE from_file_id=? OR to_file_id=?":
			if _, err := tx.ExecContext(ctx, stmt, id, id); err != nil {
				return err
			}
		case "DELETE FROM fts WHERE path=?":
			if _, err := tx.ExecContext(ctx, stmt, path); err != nil {
				return err
			}
		default:
			if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
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
		"DELETE FROM embed_cache",
		"DELETE FROM file_histories",
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
	attrs := FrontmatterAttributes(string(content))
	uid := strings.TrimSpace(attrs.ID)
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
		visibility := attrs.Visibility
		if visibility == "" {
			visibility = "private"
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO files(path, title, uid, visibility, hash, mtime_unix, size, created_at, updated_at, priority)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, notePath, meta.Title, uid, visibility, checksum, mtime.Unix(), size, createdAt, time.Now().Unix(), meta.Priority)
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT id FROM files WHERE path=?", notePath).Scan(&existingID); err != nil {
			return err
		}
	} else if err == nil {
		visibility := attrs.Visibility
		if visibility == "" {
			visibility = "private"
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE files SET title=?, uid=?, visibility=?, hash=?, mtime_unix=?, size=?, updated_at=?, priority=? WHERE id=?
		`, meta.Title, uid, visibility, checksum, mtime.Unix(), size, time.Now().Unix(), meta.Priority, existingID)
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM file_histories WHERE file_id=?", existingID); err != nil {
		return err
	}
	historyEntries := ParseHistoryEntries(string(content))
	validHistory := 0
	for _, entry := range historyEntries {
		if entry.At.IsZero() || entry.Action == "" {
			continue
		}
		user := entry.User
		if user == "" {
			user = dummyHistoryUser
		}
		actionTime := entry.At.UTC().Unix()
		actionDate := actionTime / secondsPerDay
		if _, err := tx.ExecContext(ctx, "INSERT INTO file_histories(file_id, user, action, action_time, action_date) VALUES(?, ?, ?, ?, ?)", existingID, user, entry.Action, actionTime, actionDate); err != nil {
			return err
		}
		validHistory++
	}
	if validHistory == 0 {
		actionTime := mtime.Unix()
		actionDate := actionTime / secondsPerDay
		if _, err := tx.ExecContext(ctx, "INSERT INTO file_histories(file_id, user, action, action_time, action_date) VALUES(?, ?, ?, ?, ?)", existingID, dummyHistoryUser, "save", actionTime, actionDate); err != nil {
			return err
		}
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO links(from_file_id, to_ref, to_file_id, kind, line_no, line) VALUES(?, ?, NULL, ?, ?, ?)", existingID, link.Ref, link.Kind, link.LineNo, link.Line); err != nil {
			return err
		}
	}

	for _, task := range meta.Tasks {
		checked := 0
		if task.Done {
			checked = 1
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tasks(file_id, line_no, text, checked, due_date, updated_at)
			VALUES(?, ?, ?, ?, ?, ?)`,
			existingID,
			task.LineNo,
			task.Text,
			checked,
			nullIfEmpty(task.Due),
			time.Now().Unix(),
		); err != nil {
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

func (i *Index) IndexNoteIfChanged(ctx context.Context, notePath string, content []byte, mtime time.Time, size int64) error {
	var rec fileRecord
	err := i.db.QueryRowContext(ctx, "SELECT id, hash, mtime_unix, size FROM files WHERE path=?", notePath).
		Scan(&rec.ID, &rec.Hash, &rec.MTimeUnix, &rec.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return i.IndexNote(ctx, notePath, content, mtime, size)
	}
	if err != nil {
		return err
	}
	if rec.MTimeUnix == mtime.Unix() && rec.Size == size {
		return nil
	}

	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])
	if checksum == rec.Hash {
		_, err := i.db.ExecContext(ctx, "UPDATE files SET mtime_unix=?, size=? WHERE id=?", mtime.Unix(), size, rec.ID)
		return err
	}
	return i.IndexNote(ctx, notePath, content, mtime, size)
}

func (i *Index) RecentNotes(ctx context.Context, limit int) ([]NoteSummary, error) {
	query := "SELECT path, title, mtime_unix FROM files"
	args := []interface{}{}
	if publicOnly(ctx) {
		query += " WHERE visibility = ?"
		args = append(args, "public")
	}
	query += " ORDER BY priority ASC, updated_at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

// Intentionally no stable task IDs; tasks are fully rebuilt from markdown on change.

func (i *Index) RecentNotesPage(ctx context.Context, limit int, offset int) ([]NoteSummary, error) {
	if limit <= 0 {
		return nil, nil
	}
	if offset < 0 {
		offset = 0
	}
	query := "SELECT path, title, mtime_unix FROM files"
	args := []interface{}{}
	if publicOnly(ctx) {
		query += " WHERE visibility = ?"
		args = append(args, "public")
	}
	query += " ORDER BY priority ASC, updated_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) NoteList(ctx context.Context, filter NoteListFilter) ([]NoteSummary, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	query := strings.TrimSpace(filter.Query)
	joins := make([]string, 0, 3)
	clauses := make([]string, 0, 3)
	args := make([]interface{}, 0, 8)
	groupBy := false

	if query != "" {
		joins = append(joins, "JOIN fts ON fts.path = files.path")
		clauses = append(clauses, "fts MATCH ?")
		args = append(args, query)
	}
	if filter.Date != "" {
		day, err := dateToDay(filter.Date)
		if err != nil {
			return nil, err
		}
		joins = append(joins, "JOIN file_histories ON files.id = file_histories.file_id")
		clauses = append(clauses, "file_histories.action_date = ?")
		args = append(args, day)
		groupBy = true
	}
	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat("?,", len(filter.Tags))
		placeholders = strings.TrimRight(placeholders, ",")
		joins = append(joins, "JOIN file_tags ON files.id = file_tags.file_id")
		joins = append(joins, "JOIN tags ON tags.id = file_tags.tag_id")
		clauses = append(clauses, "tags.name IN ("+placeholders+")")
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
		groupBy = true
	}
	applyVisibilityFilter(ctx, &clauses, &args, "files")
	applyFolderFilter(filter.Folder, filter.Root, &clauses, &args, "files")

	sqlStr := "SELECT files.path, files.title, files.mtime_unix FROM files"
	if len(joins) > 0 {
		sqlStr += " " + strings.Join(joins, " ")
	}
	if len(clauses) > 0 {
		sqlStr += " WHERE " + strings.Join(clauses, " AND ")
	}
	if groupBy {
		sqlStr += " GROUP BY files.id"
	}
	if len(filter.Tags) > 0 {
		sqlStr += " HAVING COUNT(DISTINCT tags.name) = ?"
		args = append(args, len(filter.Tags))
	}
	sqlStr += " ORDER BY files.priority ASC, files.updated_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := i.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) OpenTasks(ctx context.Context, tags []string, limit int, dueOnly bool, dueDate string, folder string, rootOnly bool) ([]TaskItem, error) {
	if limit <= 0 {
		limit = 200
	}
	var (
		rows *sql.Rows
		err  error
	)
	if dueOnly && dueDate == "" {
		return nil, fmt.Errorf("due date required for due-only tasks")
	}
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		if dueOnly {
			query := `
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
			`
			args := []interface{}{dueDate}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				ORDER BY tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
			args = append(args, limit)
			rows, err = i.db.QueryContext(ctx, query, args...)
		} else {
			query := `
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				WHERE tasks.checked = 0
			`
			args := []interface{}{}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				ORDER BY (tasks.due_date IS NULL), tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
			args = append(args, limit)
			rows, err = i.db.QueryContext(ctx, query, args...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		base := `
			SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
			FROM tasks
			JOIN files ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		if folderClause != "" {
			base += " AND " + folderClause
		}
		if dueOnly {
			base += ` AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?`
		}
		query := base + `
			GROUP BY tasks.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY ` + func() string {
			if dueOnly {
				return "tasks.due_date ASC, tasks.updated_at DESC"
			}
			return "(tasks.due_date IS NULL), tasks.due_date ASC, tasks.updated_at DESC"
		}() + `
			LIMIT ?`
		args := make([]interface{}, 0, len(tags)+3+len(folderArgs))
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, folderArgs...)
		if dueOnly {
			args = append(args, dueDate)
		}
		args = append(args, len(tags), limit)
		rows, err = i.db.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TaskItem
	for rows.Next() {
		var item TaskItem
		var due sql.NullString
		var updatedUnix int64
		if err := rows.Scan(&item.Path, &item.Title, &item.LineNo, &item.Text, &due, &updatedUnix); err != nil {
			return nil, err
		}
		if due.Valid {
			item.DueDate = due.String
		}
		item.UpdatedAt = time.Unix(updatedUnix, 0).Local()
		out = append(out, item)
	}
	return out, rows.Err()
}

func (i *Index) OpenTasksByDate(ctx context.Context, tags []string, limit int, dueOnly bool, dueDate string, activityDate string, folder string, rootOnly bool) ([]TaskItem, error) {
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if dueOnly && dueDate == "" {
		return nil, fmt.Errorf("due date required for due-only tasks")
	}
	if limit <= 0 {
		limit = 50
	}
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	var (
		query string
		args  []interface{}
		rows  *sql.Rows
	)
	if len(tags) == 0 {
		if dueOnly {
			query = `
				WITH matching_files AS (
					SELECT DISTINCT file_id
					FROM file_histories
					WHERE action_date = ?
				)
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				JOIN matching_files ON matching_files.file_id = files.id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
			`
			args = []interface{}{day, dueDate}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				ORDER BY tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
			args = append(args, limit)
		} else {
			query = `
				WITH matching_files AS (
					SELECT DISTINCT file_id
					FROM file_histories
					WHERE action_date = ?
				)
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				JOIN matching_files ON matching_files.file_id = files.id
				WHERE tasks.checked = 0
			`
			args = []interface{}{day}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				ORDER BY (tasks.due_date IS NULL), tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
			args = append(args, limit)
		}
		rows, err = i.db.QueryContext(ctx, query, args...)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		base := `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN file_histories ON files.id = file_histories.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				WHERE file_histories.action_date = ? AND tags.name IN (` + placeholders + `)
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.due_date, tasks.updated_at
			FROM tasks
			JOIN files ON files.id = tasks.file_id
			JOIN matching_files ON matching_files.id = files.id
			WHERE tasks.checked = 0`
		if folderClause != "" {
			base += " AND " + folderClause
		}
		if dueOnly {
			query = base + ` AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
				ORDER BY tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
		} else {
			query = base + `
				ORDER BY (tasks.due_date IS NULL), tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
		}
		args = make([]interface{}, 0, len(tags)+4+len(folderArgs))
		args = append(args, day)
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags))
		args = append(args, folderArgs...)
		if dueOnly {
			args = append(args, dueDate, limit)
		} else {
			args = append(args, limit)
		}
		rows, err = i.db.QueryContext(ctx, query, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TaskItem
	for rows.Next() {
		var item TaskItem
		var due sql.NullString
		var updatedUnix int64
		if err := rows.Scan(&item.Path, &item.Title, &item.LineNo, &item.Text, &due, &updatedUnix); err != nil {
			return nil, err
		}
		if due.Valid {
			item.DueDate = due.String
		}
		item.UpdatedAt = time.Unix(updatedUnix, 0).Local()
		out = append(out, item)
	}
	return out, rows.Err()
}

func (i *Index) NotesWithOpenTasks(ctx context.Context, tags []string, limit int, offset int, folder string, rootOnly bool) ([]NoteSummary, error) {
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		if args == nil {
			args = make([]interface{}, 0, len(tags)+3+len(folderArgs))
		}
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags), limit, offset)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) NotesWithDueTasks(ctx context.Context, tags []string, dueDate string, limit int, offset int, folder string, rootOnly bool) ([]NoteSummary, error) {
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	if dueDate == "" {
		return nil, fmt.Errorf("due date required for due tasks")
	}

	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
		`
		args = []interface{}{dueDate}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND tags.name IN (` + placeholders + `)
		`
		args = make([]interface{}, 0, len(tags)+4+len(folderArgs))
		args = append(args, dueDate)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags), limit, offset)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) NotesWithOpenTasksByDate(ctx context.Context, tags []string, activityDate string, limit int, offset int, folder string, rootOnly bool) ([]NoteSummary, error) {
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ?
		`
		args = []interface{}{day}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)
		`
		args = make([]interface{}, 0, len(tags)+4+len(folderArgs))
		args = append(args, day)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags), limit, offset)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) NotesWithDueTasksByDate(ctx context.Context, tags []string, activityDate string, dueDate string, limit int, offset int, folder string, rootOnly bool) ([]NoteSummary, error) {
	if dueDate == "" {
		return nil, fmt.Errorf("due date required for due tasks")
	}
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ?
		`
		args = []interface{}{dueDate, day}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.path, files.title, files.mtime_unix
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)
		`
		args = make([]interface{}, 0, len(tags)+5+len(folderArgs))
		args = append(args, dueDate, day)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY files.priority ASC, files.updated_at DESC
			LIMIT ? OFFSET ?`
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags), limit, offset)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (i *Index) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	var rows *sql.Rows
	var err error
	if publicOnly(ctx) {
		rows, err = i.db.QueryContext(ctx, `
			SELECT fts.path, fts.title, snippet(fts, 2, '', '', '...', 10)
			FROM fts
			JOIN files ON files.path = fts.path
			WHERE fts MATCH ? AND files.visibility = ?
			LIMIT ?`, query, "public", limit)
	} else {
		rows, err = i.db.QueryContext(ctx, "SELECT path, title, snippet(fts, 2, '', '', '...', 10) FROM fts WHERE fts MATCH ? LIMIT ?", query, limit)
	}
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

func (i *Index) ListTags(ctx context.Context, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if publicOnly(ctx) {
		query := `
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN files ON files.id = file_tags.file_id
			WHERE files.visibility = ?`
		args := []interface{}{"public"}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, query, args...)
	} else {
		query := `
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			LEFT JOIN file_tags ON tags.id = file_tags.tag_id
			LEFT JOIN files ON files.id = file_tags.file_id`
		args := []interface{}{}
		if folderClause != "" {
			query += " WHERE " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, query, args...)
	}
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

func (i *Index) ListTagsFiltered(ctx context.Context, active []string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if len(active) == 0 {
		return i.ListTags(ctx, limit, folder, rootOnly)
	}
	if limit <= 0 {
		limit = 100
	}
	placeholders := strings.Repeat("?,", len(active))
	placeholders = strings.TrimRight(placeholders, ",")
	visibilityClause := ""
	if publicOnly(ctx) {
		visibilityClause = " AND files.visibility = ?"
	}
	folderClause := ""
	if rootOnly {
		folderClause = " AND files.path NOT LIKE ?"
	} else if strings.TrimSpace(folder) != "" {
		folderClause = " AND files.path LIKE ?"
	}
	query := `
		WITH matching_files AS (
			SELECT files.id
			FROM files
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tags.name IN (` + placeholders + `)` + visibilityClause + folderClause + `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
		)
		SELECT tags.name, COUNT(file_tags.file_id)
		FROM tags
		JOIN file_tags ON tags.id = file_tags.tag_id
		JOIN matching_files ON matching_files.id = file_tags.file_id
		GROUP BY tags.id
		ORDER BY tags.name
		LIMIT ?`

	args := make([]interface{}, 0, len(active)+4)
	for _, tag := range active {
		args = append(args, tag)
	}
	if publicOnly(ctx) {
		args = append(args, "public")
	}
	if rootOnly {
		args = append(args, "%/%")
	} else if strings.TrimSpace(folder) != "" {
		folder = strings.TrimSuffix(folder, "/")
		args = append(args, folder+"/%")
	}
	args = append(args, len(active), limit)

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListTagsFilteredByDate(ctx context.Context, active []string, activityDate string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if len(active) == 0 {
		if limit <= 0 {
			limit = 100
		}
		var rows *sql.Rows
		var err error
		folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
		if publicOnly(ctx) {
			query := `
				WITH matching_files AS (
					SELECT DISTINCT file_histories.file_id
					FROM file_histories
					JOIN files ON files.id = file_histories.file_id
					WHERE file_histories.action_date = ? AND files.visibility = ?`
			args := []interface{}{day, "public"}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				)
				SELECT tags.name, COUNT(file_tags.file_id)
				FROM tags
				JOIN file_tags ON tags.id = file_tags.tag_id
				JOIN matching_files ON matching_files.file_id = file_tags.file_id
				GROUP BY tags.id
				ORDER BY tags.name
				LIMIT ?`
			args = append(args, limit)
			rows, err = i.db.QueryContext(ctx, query, args...)
		} else {
			query := `
				WITH matching_files AS (
					SELECT DISTINCT file_histories.file_id
					FROM file_histories
					JOIN files ON files.id = file_histories.file_id
					WHERE file_histories.action_date = ?`
			args := []interface{}{day}
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				)
				SELECT tags.name, COUNT(file_tags.file_id)
				FROM tags
				JOIN file_tags ON tags.id = file_tags.tag_id
				JOIN matching_files ON matching_files.file_id = file_tags.file_id
				GROUP BY tags.id
				ORDER BY tags.name
				LIMIT ?`
			args = append(args, limit)
			rows, err = i.db.QueryContext(ctx, query, args...)
		}
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
	if limit <= 0 {
		limit = 100
	}
	placeholders := strings.Repeat("?,", len(active))
	placeholders = strings.TrimRight(placeholders, ",")
	visibilityClause := ""
	if publicOnly(ctx) {
		visibilityClause = " AND files.visibility = ?"
	}
	folderClause := ""
	if rootOnly {
		folderClause = " AND files.path NOT LIKE ?"
	} else if strings.TrimSpace(folder) != "" {
		folderClause = " AND files.path LIKE ?"
	}
	query := `
		WITH matching_files AS (
			SELECT files.id
			FROM files
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE file_histories.action_date = ? AND tags.name IN (` + placeholders + `)` + visibilityClause + folderClause + `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
		)
		SELECT tags.name, COUNT(file_tags.file_id)
		FROM tags
		JOIN file_tags ON tags.id = file_tags.tag_id
		JOIN matching_files ON matching_files.id = file_tags.file_id
		GROUP BY tags.id
		ORDER BY tags.name
		LIMIT ?`

	args := make([]interface{}, 0, len(active)+5)
	args = append(args, day)
	for _, tag := range active {
		args = append(args, tag)
	}
	if publicOnly(ctx) {
		args = append(args, "public")
	}
	if rootOnly {
		args = append(args, "%/%")
	} else if strings.TrimSpace(folder) != "" {
		folder = strings.TrimSuffix(folder, "/")
		args = append(args, folder+"/%")
	}
	args = append(args, len(active), limit)

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListTagsWithOpenTasks(ctx context.Context, active []string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(active) == 0 {
		query = `
			WITH matching_files AS (
				SELECT DISTINCT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				WHERE tasks.checked = 0`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
	} else {
		placeholders := strings.Repeat("?,", len(active))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		if args == nil {
			args = make([]interface{}, 0, len(active)+2+len(folderArgs))
		}
		for _, tag := range active {
			args = append(args, tag)
		}
		args = append(args, len(active), limit)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListTagsWithOpenTasksByDate(ctx context.Context, active []string, activityDate string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(active) == 0 {
		query = `
			WITH matching_files AS (
				SELECT DISTINCT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_histories ON files.id = file_histories.file_id
				WHERE tasks.checked = 0 AND file_histories.action_date = ?`
		args = []interface{}{day}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
	} else {
		placeholders := strings.Repeat("?,", len(active))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_histories ON files.id = file_histories.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				WHERE tasks.checked = 0 AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		args = make([]interface{}, 0, len(active)+3+len(folderArgs))
		args = append(args, day)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		for _, tag := range active {
			args = append(args, tag)
		}
		args = append(args, len(active), limit)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListTagsWithDueTasks(ctx context.Context, active []string, dueDate string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if dueDate == "" {
		return nil, fmt.Errorf("due date required for due tasks")
	}
	if limit <= 0 {
		limit = 100
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(active) == 0 {
		query = `
			WITH matching_files AS (
				SELECT DISTINCT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?`
		args = []interface{}{dueDate}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
	} else {
		placeholders := strings.Repeat("?,", len(active))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND tags.name IN (` + placeholders + `)
		`
		args = make([]interface{}, 0, len(active)+3+len(folderArgs))
		args = append(args, dueDate)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		for _, tag := range active {
			args = append(args, tag)
		}
		args = append(args, len(active), limit)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListTagsWithDueTasksByDate(ctx context.Context, active []string, activityDate string, dueDate string, limit int, folder string, rootOnly bool) ([]TagSummary, error) {
	if dueDate == "" {
		return nil, fmt.Errorf("due date required for due tasks")
	}
	if activityDate == "" {
		return nil, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(active) == 0 {
		whereClause := "WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ?"
		args = []interface{}{dueDate, day}
		if folderClause != "" {
			whereClause += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query = `
			WITH matching_files AS (
				SELECT DISTINCT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_histories ON files.id = file_histories.file_id
				` + whereClause + `
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = append(args, limit)
	} else {
		placeholders := strings.Repeat("?,", len(active))
		placeholders = strings.TrimRight(placeholders, ",")
		whereClause := "WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ? AND tags.name IN (" + placeholders + ")"
		if folderClause != "" {
			whereClause += " AND " + folderClause
		}
		query = `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN tasks ON files.id = tasks.file_id
				JOIN file_histories ON files.id = file_histories.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				` + whereClause + `
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT tags.name, COUNT(file_tags.file_id)
			FROM tags
			JOIN file_tags ON tags.id = file_tags.tag_id
			JOIN matching_files ON matching_files.id = file_tags.file_id
			GROUP BY tags.id
			ORDER BY tags.name
			LIMIT ?`
		args = make([]interface{}, 0, len(active)+4+len(folderArgs))
		args = append(args, dueDate, day)
		if folderClause != "" {
			args = append(args, folderArgs...)
		}
		for _, tag := range active {
			args = append(args, tag)
		}
		args = append(args, len(active), limit)
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
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

func (i *Index) ListFolders(ctx context.Context) ([]string, bool, error) {
	query := "SELECT path FROM files"
	args := []interface{}{}
	if publicOnly(ctx) {
		query += " WHERE visibility = ?"
		args = append(args, "public")
	}
	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	folderSet := map[string]struct{}{}
	hasRoot := false
	for rows.Next() {
		var notePath string
		if err := rows.Scan(&notePath); err != nil {
			return nil, false, err
		}
		dir := path.Dir(notePath)
		if dir == "." || dir == "/" {
			hasRoot = true
			continue
		}
		parts := strings.Split(dir, "/")
		var current string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if current == "" {
				current = part
			} else {
				current = current + "/" + part
			}
			folderSet[current] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	folders := make([]string, 0, len(folderSet))
	for folder := range folderSet {
		folders = append(folders, folder)
	}
	sort.Strings(folders)
	return folders, hasRoot, nil
}

func (i *Index) ListUpdateDays(ctx context.Context, limit int, folder string, rootOnly bool) ([]UpdateDaySummary, error) {
	if limit <= 0 {
		limit = 30
	}
	var (
		rows *sql.Rows
		err  error
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if publicOnly(ctx) {
		query := `
			SELECT file_histories.action_date, COUNT(DISTINCT file_histories.file_id)
			FROM file_histories
			JOIN files ON files.id = file_histories.file_id
			WHERE files.visibility = ?`
		args := []interface{}{"public"}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY file_histories.action_date
			ORDER BY file_histories.action_date DESC
			LIMIT ?`
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, query, args...)
	} else {
		query := `
			SELECT file_histories.action_date, COUNT(DISTINCT file_histories.file_id)
			FROM file_histories
			JOIN files ON files.id = file_histories.file_id`
		args := []interface{}{}
		if folderClause != "" {
			query += " WHERE " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY file_histories.action_date
			ORDER BY file_histories.action_date DESC
			LIMIT ?`
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, query, args...)
	}
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

func (i *Index) CountNotesWithOpenTasks(ctx context.Context, tags []string, folder string, rootOnly bool) (int, error) {
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?`
		if args == nil {
			args = make([]interface{}, 0, len(tags)+1+len(folderArgs))
		}
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) CountNotesWithOpenTasksByDate(ctx context.Context, tags []string, activityDate string, folder string, rootOnly bool) (int, error) {
	if activityDate == "" {
		return 0, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return 0, err
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ?`
		args = []interface{}{day}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.id
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?`
		if args == nil {
			args = make([]interface{}, 0, len(tags)+2+len(folderArgs))
		}
		args = append(args, day)
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) CountNotesWithDueTasks(ctx context.Context, tags []string, dueDate string, folder string, rootOnly bool) (int, error) {
	if dueDate == "" {
		return 0, fmt.Errorf("due date required for due tasks")
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?`
		args = []interface{}{dueDate}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND tags.name IN (` + placeholders + `)`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?`
		if args == nil {
			args = make([]interface{}, 0, len(tags)+2+len(folderArgs))
		}
		args = append(args, dueDate)
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) CountNotesWithDueTasksByDate(ctx context.Context, tags []string, activityDate string, dueDate string, folder string, rootOnly bool) (int, error) {
	if dueDate == "" {
		return 0, fmt.Errorf("due date required for due tasks")
	}
	if activityDate == "" {
		return 0, fmt.Errorf("activity date required")
	}
	day, err := dateToDay(activityDate)
	if err != nil {
		return 0, err
	}
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ?`
		args = []interface{}{dueDate, day}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.id
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?`
		if args == nil {
			args = make([]interface{}, 0, len(tags)+3+len(folderArgs))
		}
		args = append(args, dueDate, day)
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) Backlinks(ctx context.Context, notePath string, title string, uid string) ([]Backlink, error) {
	candidates := backlinkCandidates(notePath, title, uid)
	if len(candidates) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(candidates))
	placeholders = strings.TrimRight(placeholders, ",")
	visibilityClause := ""
	if publicOnly(ctx) {
		visibilityClause = " AND files.visibility = ?"
	}
	query := `
		SELECT files.path, files.title, links.line_no, links.line, links.kind
		FROM links
		JOIN files ON files.id = links.from_file_id
		WHERE lower(links.to_ref) IN (` + placeholders + `) AND files.path != ?` + visibilityClause + `
		ORDER BY files.updated_at DESC, files.title`

	args := make([]interface{}, 0, len(candidates)+2)
	for _, candidate := range candidates {
		args = append(args, strings.ToLower(candidate))
	}
	args = append(args, notePath)
	if publicOnly(ctx) {
		args = append(args, "public")
	}

	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backlinks []Backlink
	for rows.Next() {
		var link Backlink
		if err := rows.Scan(&link.FromPath, &link.FromTitle, &link.LineNo, &link.Line, &link.Kind); err != nil {
			return nil, err
		}
		backlinks = append(backlinks, link)
	}
	return backlinks, rows.Err()
}

func backlinkCandidates(notePath string, title string, uid string) []string {
	notePath = strings.TrimSpace(notePath)
	title = strings.TrimSpace(title)
	uid = strings.TrimSpace(uid)
	if notePath == "" && title == "" && uid == "" {
		return nil
	}
	noExt := strings.TrimSuffix(notePath, ".md")
	titleSlug := slugify(title)
	var candidates []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		candidates = append(candidates, value)
	}
	add(notePath)
	add(noExt)
	add("notes/" + notePath)
	add("notes/" + noExt)
	add("/notes/" + notePath)
	add("/notes/" + noExt)
	add(title)
	add(titleSlug)
	add(titleSlug + ".md")
	add("notes/" + titleSlug + ".md")
	add("/notes/" + titleSlug + ".md")
	add("notes/" + titleSlug)
	add("/notes/" + titleSlug)
	add(uid)
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, candidate)
	}
	return unique
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
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_histories WHERE file_id=?", row.id); err != nil {
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
	query := "SELECT id FROM files WHERE path=?"
	args := []interface{}{notePath}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	err := i.db.QueryRowContext(ctx, query, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (i *Index) FileIDByPath(ctx context.Context, notePath string) (int, error) {
	var id int
	query := "SELECT id FROM files WHERE path=?"
	args := []interface{}{notePath}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (i *Index) PathByFileID(ctx context.Context, id int) (string, error) {
	var path string
	query := "SELECT path FROM files WHERE id=?"
	args := []interface{}{id}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&path); err != nil {
		return "", err
	}
	return path, nil
}

func (i *Index) PathByUID(ctx context.Context, uid string) (string, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", sql.ErrNoRows
	}
	var path string
	query := "SELECT path FROM files WHERE lower(uid)=lower(?)"
	args := []interface{}{uid}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&path); err != nil {
		return "", err
	}
	return path, nil
}

func (i *Index) PathTitleByUID(ctx context.Context, uid string) (string, string, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", "", sql.ErrNoRows
	}
	var path string
	var title string
	query := "SELECT path, title FROM files WHERE lower(uid)=lower(?)"
	args := []interface{}{uid}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&path, &title); err != nil {
		return "", "", err
	}
	return path, title, nil
}

func (i *Index) PathByTitleNewest(ctx context.Context, title string) (string, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return "", sql.ErrNoRows
	}
	var path string
	query := `
		SELECT path
		FROM files
		WHERE lower(title)=lower(?)`
	args := []interface{}{title}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	query += `
		ORDER BY updated_at DESC
		LIMIT 1`
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&path); err != nil {
		return "", err
	}
	return path, nil
}

func (i *Index) DumpNoteList(ctx context.Context) ([]NoteSummary, error) {
	query := "SELECT path, title, mtime_unix FROM files"
	args := []interface{}{}
	if publicOnly(ctx) {
		query += " WHERE visibility = ?"
		args = append(args, "public")
	}
	query += " ORDER BY path"
	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []NoteSummary
	for rows.Next() {
		var n NoteSummary
		var mtimeUnix int64
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix); err != nil {
			return nil, err
		}
		n.MTime = time.Unix(mtimeUnix, 0).UTC()
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
		fmt.Fprintf(&b, "%s\t%s\t%s\n", n.Path, n.Title, n.MTime.Format(time.RFC3339))
	}
	return b.String(), nil
}
