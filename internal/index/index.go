package index

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	UID   string
}

type NoteListFilter struct {
	Tags       []string
	Date       string
	Query      string
	Folder     string
	Root       bool
	ExcludeUID string
	Limit      int
	Offset     int
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

type TaskCountFilter struct {
	Tags    []string
	Date    string
	Folder  string
	Root    bool
	DueOnly bool
	DueDate string
}

type NoteHistorySummary struct {
	Path  string
	Title string
	MTime time.Time
}

type TaskItem struct {
	Path      string
	Title     string
	LineNo    int
	Text      string
	Hash      string
	DueDate   string
	UpdatedAt time.Time
	FileID    int
}

type Backlink struct {
	FromPath  string
	FromTitle string
	LineNo    int
	Line      string
	Kind      string
}

type BrokenLink struct {
	ToRef     string
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

var journalPathRE = regexp.MustCompile(`^\d{4}-\d{2}/\d{2}\.md$`)

func dateToDay(date string) (int64, error) {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0, err
	}
	return parsed.UTC().Unix() / secondsPerDay, nil
}

func isJournalPath(notePath string) bool {
	notePath = strings.TrimPrefix(notePath, "/")
	return journalPathRE.MatchString(notePath)
}

func journalDateForPath(notePath string) (string, bool) {
	notePath = strings.TrimPrefix(notePath, "/")
	if !journalPathRE.MatchString(notePath) {
		return "", false
	}
	datePart := strings.TrimSuffix(notePath, ".md")
	parsed, err := time.Parse("2006-01/02", datePart)
	if err != nil {
		return "", false
	}
	return parsed.Format("2006-01-02"), true
}

func JournalDateForPath(notePath string) (string, bool) {
	return journalDateForPath(notePath)
}

func journalEndOfDayForPath(notePath string) (time.Time, bool) {
	notePath = strings.TrimPrefix(notePath, "/")
	notePath = strings.TrimSuffix(notePath, ".md")
	parsed, err := time.Parse("2006-01/02", notePath)
	if err != nil {
		return time.Time{}, false
	}
	return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 23, 59, 59, 0, time.Local), true
}

func normalizeTagName(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", false
	}
	if strings.HasSuffix(tag, "!") {
		return strings.TrimSuffix(tag, "!"), true
	}
	return tag, false
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func exclusiveTagFilterClause(tags []string, table string) (string, []interface{}) {
	if table == "" {
		table = "files"
	}
	if len(tags) == 0 {
		return fmt.Sprintf(`NOT EXISTS (
			SELECT 1
			FROM file_tags fet
			WHERE fet.file_id = %s.id AND fet.is_exclusive = 1
		)`, table), nil
	}
	placeholders := strings.Repeat("?,", len(tags))
	placeholders = strings.TrimRight(placeholders, ",")
	clause := fmt.Sprintf(`NOT EXISTS (
		SELECT 1
		FROM file_tags fet
		JOIN tags t_ex ON t_ex.id = fet.tag_id
		WHERE fet.file_id = %s.id AND fet.is_exclusive = 1 AND t_ex.name NOT IN (%s)
	)`, table, placeholders)
	args := make([]interface{}, 0, len(tags))
	for _, tag := range tags {
		args = append(args, tag)
	}
	return clause, args
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
	if version == 0 {
		if err := i.setSchemaVersion(ctx, 3); err != nil {
			return err
		}
		version = 3
	}
	if version != schemaVersion {
		if err := i.migrateSchema(ctx, version); err != nil {
			return err
		}
		if err := i.setSchemaVersion(ctx, schemaVersion); err != nil {
			return err
		}
		return i.RebuildFromFS(ctx, repoPath)
	}
	if err := i.ensureColumn(ctx, "file_tags", "is_exclusive", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	scanned, updated, cleaned, err := i.RecheckFromFS(ctx, repoPath)
	if err != nil {
		return err
	}
	slog.Info("index recheck complete", "scanned", scanned, "updated", updated, "cleaned", cleaned)
	return nil
}

func (i *Index) migrateSchema(ctx context.Context, fromVersion int) error {
	if fromVersion <= 0 {
		return nil
	}
	if fromVersion > schemaVersion {
		return fmt.Errorf("unsupported schema version: %d", fromVersion)
	}
	version := fromVersion
	for version < schemaVersion {
		switch version {
		case 3:
			slog.Info("schema migration", "from", 3, "to", 4)
			if err := i.migrate3To4(ctx); err != nil {
				return err
			}
			version = 4
		case 4:
			slog.Info("schema migration", "from", 4, "to", 5)
			if err := i.migrate4To5(ctx); err != nil {
				return err
			}
			version = 5
		case 5:
			slog.Info("schema migration", "from", 5, "to", 6)
			if err := i.migrate5To6(ctx); err != nil {
				return err
			}
			version = 6
		case 6:
			slog.Info("schema migration", "from", 6, "to", 7)
			if err := i.migrate6To7(ctx); err != nil {
				return err
			}
			version = 7
		case 7:
			slog.Info("schema migration", "from", 7, "to", 8)
			if err := i.migrate7To8(ctx); err != nil {
				return err
			}
			version = 8
		case 8:
			slog.Info("schema migration", "from", 8, "to", 9)
			if err := i.migrate8To9(ctx); err != nil {
				return err
			}
			version = 9
		case 9:
			slog.Info("schema migration", "from", 9, "to", 11)
			if err := i.migrate9To11(ctx); err != nil {
				return err
			}
			version = 11
		case 10:
			slog.Info("schema migration", "from", 10, "to", 11)
			if err := i.migrate9To11(ctx); err != nil {
				return err
			}
			version = 11
		case 11:
			slog.Info("schema migration", "from", 11, "to", 12)
			if err := i.migrate11To12(ctx); err != nil {
				return err
			}
			version = 12
		case 12:
			slog.Info("schema migration", "from", 12, "to", 13)
			if err := i.migrate12To13(ctx); err != nil {
				return err
			}
			version = 13
		case 13:
			slog.Info("schema migration", "from", 13, "to", 14)
			if err := i.migrate13To14(ctx); err != nil {
				return err
			}
			version = 14
		case 14:
			slog.Info("schema migration", "from", 14, "to", 15)
			if err := i.migrate14To15(ctx); err != nil {
				return err
			}
			version = 15
		case 15:
			slog.Info("schema migration", "from", 15, "to", 16)
			if err := i.migrate15To16(ctx); err != nil {
				return err
			}
			version = 16
		case 16:
			slog.Info("schema migration", "from", 16, "to", 17)
			if err := i.migrate16To17(ctx); err != nil {
				return err
			}
			version = 17
		default:
			return fmt.Errorf("unsupported schema version: %d", version)
		}
	}
	return nil
}

func (i *Index) migrate3To4(ctx context.Context) error {
	if _, err := i.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS embed_cache (
			url TEXT NOT NULL,
			kind TEXT NOT NULL,
			embed_url TEXT,
			status TEXT NOT NULL,
			error_msg TEXT,
			updated_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY(url, kind)
		)`); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate4To5(ctx context.Context) error {
	if err := i.ensureColumn(ctx, "tasks", "updated_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if _, err := i.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS tasks_by_file_checked ON tasks(file_id, checked)"); err != nil {
		return err
	}
	if _, err := i.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS tasks_by_file_due ON tasks(file_id, due_date)"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate5To6(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "priority", "INTEGER NOT NULL DEFAULT 10")
}

func (i *Index) migrate6To7(ctx context.Context) error {
	if _, err := i.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS file_histories (
			id INTEGER PRIMARY KEY,
			file_id INTEGER NOT NULL,
			action TEXT NOT NULL,
			action_time INTEGER NOT NULL,
			action_date INTEGER NOT NULL
		)`); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate7To8(ctx context.Context) error {
	return i.ensureColumn(ctx, "file_histories", "user", "TEXT NOT NULL DEFAULT ''")
}

func (i *Index) migrate8To9(ctx context.Context) error {
	if err := i.ensureColumn(ctx, "links", "line_no", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return i.ensureColumn(ctx, "links", "line", "TEXT NOT NULL DEFAULT ''")
}

func (i *Index) migrate9To11(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "uid", "TEXT")
}

func (i *Index) migrate11To12(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "visibility", "TEXT NOT NULL DEFAULT 'private'")
}

func (i *Index) migrate12To13(ctx context.Context) error {
	if _, err := i.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS collapsed_sections (
			note_id TEXT NOT NULL,
			line_no INTEGER NOT NULL,
			line TEXT NOT NULL,
			PRIMARY KEY(note_id, line_no)
		)`); err != nil {
		return err
	}
	_, err := i.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS collapsed_sections_by_note ON collapsed_sections(note_id)")
	return err
}

func (i *Index) migrate13To14(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "is_journal", "INTEGER NOT NULL DEFAULT 0")
}

func (i *Index) migrate14To15(ctx context.Context) error {
	return i.ensureColumn(ctx, "tasks", "hash", "TEXT NOT NULL DEFAULT ''")
}

func (i *Index) migrate15To16(ctx context.Context) error {
	return i.ensureColumn(ctx, "file_tags", "is_exclusive", "INTEGER NOT NULL DEFAULT 0")
}

func (i *Index) migrate16To17(ctx context.Context) error {
	if _, err := i.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS broken_links (
			id INTEGER PRIMARY KEY,
			from_file_id INTEGER NOT NULL,
			to_ref TEXT NOT NULL,
			kind TEXT NOT NULL,
			line_no INTEGER NOT NULL,
			line TEXT NOT NULL
		)`); err != nil {
		return err
	}
	_, err := i.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS broken_links_by_file ON broken_links(from_file_id)")
	return err
}

func (i *Index) ensureColumn(ctx context.Context, table string, column string, ddl string) error {
	hasColumn := false
	rows, err := i.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultVal, &pk); err != nil {
			return err
		}
		if name == column {
			hasColumn = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	_, err = i.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ddl))
	return err
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
	scanned, updated, cleaned, err := i.RebuildFromFSWithStats(ctx, repoPath)
	if err != nil {
		return err
	}
	slog.Info("index rebuild complete", "scanned", scanned, "updated", updated, "cleaned", cleaned)
	return nil
}

func (i *Index) RebuildFromFSWithStats(ctx context.Context, repoPath string) (int, int, int, error) {
	notesRoot := filepath.Join(repoPath, "notes")
	cleaned := 0
	if err := i.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM files").Scan(&cleaned); err != nil {
		return 0, 0, 0, err
	}
	clear := []string{
		"DELETE FROM collapsed_sections",
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
			return 0, 0, 0, err
		}
	}

	scanned := 0
	err := filepath.WalkDir(notesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(notesRoot, path)
			if relErr == nil {
				rel = filepath.ToSlash(rel)
				if rel == "attachments" || strings.HasPrefix(rel, "attachments/") {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		scanned++
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
	if err != nil {
		return scanned, scanned, cleaned, err
	}
	return scanned, scanned, cleaned, nil
}

func (i *Index) RecheckFromFS(ctx context.Context, repoPath string) (int, int, int, error) {
	notesRoot := filepath.Join(repoPath, "notes")
	records, err := i.loadFileRecords(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	seen := make(map[string]bool, len(records))
	scanned := 0
	updated := 0
	err = filepath.WalkDir(notesRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(notesRoot, path)
			if relErr == nil {
				rel = filepath.ToSlash(rel)
				if rel == "attachments" || strings.HasPrefix(rel, "attachments/") {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		scanned++
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
		if ok && rec.MTimeUnix == info.ModTime().Unix() && rec.Size == info.Size() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		updated++
		return i.IndexNoteIfChanged(ctx, rel, content, info.ModTime(), info.Size())
	})
	if err != nil {
		return scanned, updated, 0, err
	}

	cleaned, err := i.removeMissingRecords(ctx, records, seen)
	if err != nil {
		return scanned, updated, 0, err
	}
	return scanned, updated, cleaned, nil
}

func (i *Index) IndexNote(ctx context.Context, notePath string, content []byte, mtime time.Time, size int64) error {
	meta := ParseContent(string(content))
	attrs := FrontmatterAttributes(string(content))
	uid := strings.TrimSpace(attrs.ID)
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])
	isJournal := 0
	if isJournalPath(notePath) {
		isJournal = 1
	}
	updatedAt := mtime.Unix()
	if isJournal == 1 {
		if journalUpdated, ok := journalEndOfDayForPath(notePath); ok {
			updatedAt = journalUpdated.Unix()
		}
	} else if !attrs.Updated.IsZero() {
		updatedAt = attrs.Updated.UTC().Unix()
	}

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
			INSERT INTO files(path, title, uid, visibility, hash, mtime_unix, size, created_at, updated_at, priority, is_journal)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, notePath, meta.Title, uid, visibility, checksum, mtime.Unix(), size, createdAt, updatedAt, meta.Priority, isJournal)
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
			UPDATE files SET title=?, uid=?, visibility=?, hash=?, mtime_unix=?, size=?, updated_at=?, priority=?, is_journal=? WHERE id=?
		`, meta.Title, uid, visibility, checksum, mtime.Unix(), size, updatedAt, meta.Priority, isJournal, existingID)
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM broken_links WHERE from_file_id=?", existingID); err != nil {
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
		name, isExclusive := normalizeTagName(tag)
		if name == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO tags(name) VALUES(?)", name)
		if err != nil {
			return err
		}
		var tagID int
		if err := tx.QueryRowContext(ctx, "SELECT id FROM tags WHERE name=?", name).Scan(&tagID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO file_tags(file_id, tag_id, is_exclusive) VALUES(?, ?, ?)", existingID, tagID, boolToInt(isExclusive)); err != nil {
			return err
		}
	}

	for _, link := range meta.Links {
		if link.Ref == "" {
			continue
		}
		toFileID, err := i.resolveLinkTargetID(ctx, tx, link.Ref)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO links(from_file_id, to_ref, to_file_id, kind, line_no, line) VALUES(?, ?, ?, ?, ?, ?)", existingID, link.Ref, nullIfZero(toFileID), link.Kind, link.LineNo, link.Line); err != nil {
			return err
		}
		if link.Kind == "wikilink" && toFileID == 0 {
			if _, err := tx.ExecContext(ctx, "INSERT INTO broken_links(from_file_id, to_ref, kind, line_no, line) VALUES(?, ?, ?, ?, ?)", existingID, link.Ref, link.Kind, link.LineNo, link.Line); err != nil {
				return err
			}
		}
	}

	for _, task := range meta.Tasks {
		checked := 0
		if task.Done {
			checked = 1
		}
		due := task.Due
		if due == "" && isJournal == 1 {
			if journalDate, ok := journalDateForPath(notePath); ok {
				due = journalDate
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tasks(file_id, line_no, text, hash, checked, due_date, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?)`,
			existingID,
			task.LineNo,
			task.Text,
			task.Hash,
			checked,
			nullIfEmpty(due),
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
	tagList := make([]string, 0, len(filter.Tags))
	for _, tag := range filter.Tags {
		tagList = append(tagList, tag)
	}
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
	if len(tagList) > 0 {
		placeholders := strings.Repeat("?,", len(tagList))
		placeholders = strings.TrimRight(placeholders, ",")
		joins = append(joins, "JOIN file_tags ON files.id = file_tags.file_id")
		joins = append(joins, "JOIN tags ON tags.id = file_tags.tag_id")
		clauses = append(clauses, "tags.name IN ("+placeholders+")")
		for _, tag := range tagList {
			args = append(args, tag)
		}
		groupBy = true
	}
	if strings.TrimSpace(filter.ExcludeUID) != "" {
		clauses = append(clauses, "(files.uid IS NULL OR files.uid != ?)")
		args = append(args, filter.ExcludeUID)
	}
	applyVisibilityFilter(ctx, &clauses, &args, "files")
	applyFolderFilter(filter.Folder, filter.Root, &clauses, &args, "files")
	if clause, clauseArgs := exclusiveTagFilterClause(tagList, "files"); clause != "" {
		clauses = append(clauses, clause)
		args = append(args, clauseArgs...)
	}

	sqlStr := "SELECT files.path, files.title, files.mtime_unix, files.uid FROM files"
	if len(joins) > 0 {
		sqlStr += " " + strings.Join(joins, " ")
	}
	if len(clauses) > 0 {
		sqlStr += " WHERE " + strings.Join(clauses, " AND ")
	}
	if groupBy {
		sqlStr += " GROUP BY files.id"
	}
	if len(tagList) > 0 {
		sqlStr += " HAVING COUNT(DISTINCT tags.name) = ?"
		args = append(args, len(tagList))
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
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix, &n.UID); err != nil {
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
			exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
			query := `
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
			`
			args := []interface{}{dueDate}
			query += " AND " + exclusiveClause
			args = append(args, exclusiveArgs...)
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
			exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
			query := `
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				WHERE tasks.checked = 0
			`
			args := []interface{}{}
			query += " AND " + exclusiveClause
			args = append(args, exclusiveArgs...)
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
			SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
			FROM tasks
			JOIN files ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		base += " AND " + exclusiveClause
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
		args := make([]interface{}, 0, len(tags)+len(exclusiveArgs)+3+len(folderArgs))
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&item.Path, &item.Title, &item.LineNo, &item.Text, &item.Hash, &due, &updatedUnix, &item.FileID); err != nil {
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
			exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
			query = `
				WITH matching_files AS (
					SELECT DISTINCT file_id
					FROM file_histories
					WHERE action_date = ?
				)
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				JOIN matching_files ON matching_files.file_id = files.id
				WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
			`
			args = []interface{}{day, dueDate}
			query += " AND " + exclusiveClause
			args = append(args, exclusiveArgs...)
			if folderClause != "" {
				query += " AND " + folderClause
				args = append(args, folderArgs...)
			}
			query += `
				ORDER BY tasks.due_date ASC, tasks.updated_at DESC
				LIMIT ?`
			args = append(args, limit)
		} else {
			exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
			query = `
				WITH matching_files AS (
					SELECT DISTINCT file_id
					FROM file_histories
					WHERE action_date = ?
				)
				SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
				FROM tasks
				JOIN files ON files.id = tasks.file_id
				JOIN matching_files ON matching_files.file_id = files.id
				WHERE tasks.checked = 0
			`
			args = []interface{}{day}
			query += " AND " + exclusiveClause
			args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		base := `
			WITH matching_files AS (
				SELECT files.id
				FROM files
				JOIN file_histories ON files.id = file_histories.file_id
				JOIN file_tags ON files.id = file_tags.file_id
				JOIN tags ON tags.id = file_tags.tag_id
				WHERE file_histories.action_date = ? AND tags.name IN (` + placeholders + `) AND ` + exclusiveClause + `
				GROUP BY files.id
				HAVING COUNT(DISTINCT tags.name) = ?
			)
			SELECT files.path, files.title, tasks.line_no, tasks.text, tasks.hash, tasks.due_date, tasks.updated_at, files.id
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
		args = make([]interface{}, 0, len(tags)+len(exclusiveArgs)+4+len(folderArgs))
		args = append(args, day)
		for _, tag := range tags {
			args = append(args, tag)
		}
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&item.Path, &item.Title, &item.LineNo, &item.Text, &item.Hash, &due, &updatedUnix, &item.FileID); err != nil {
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0`
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix, &n.UID); err != nil {
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?
		`
		args = []interface{}{dueDate}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND tags.name IN (` + placeholders + `)
		`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix, &n.UID); err != nil {
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ?
		`
		args = []interface{}{day}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)
		`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix, &n.UID); err != nil {
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ?
		`
		args = []interface{}{dueDate, day}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.path, files.title, files.mtime_unix, files.uid
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)
		`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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
		if err := rows.Scan(&n.Path, &n.Title, &mtimeUnix, &n.UID); err != nil {
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
	exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
	if publicOnly(ctx) {
		queryStr := `
			SELECT fts.path, fts.title, snippet(fts, 2, '', '', '...', 10)
			FROM fts
			JOIN files ON files.path = fts.path
			WHERE fts MATCH ? AND files.visibility = ? AND ` + exclusiveClause + `
			LIMIT ?`
		args := []interface{}{query, "public"}
		args = append(args, exclusiveArgs...)
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, queryStr, args...)
	} else {
		queryStr := `
			SELECT fts.path, fts.title, snippet(fts, 2, '', '', '...', 10)
			FROM fts
			JOIN files ON files.path = fts.path
			WHERE fts MATCH ? AND ` + exclusiveClause + `
			LIMIT ?`
		args := []interface{}{query}
		args = append(args, exclusiveArgs...)
		args = append(args, limit)
		rows, err = i.db.QueryContext(ctx, queryStr, args...)
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
			if len(args) == 0 {
				query += " WHERE " + folderClause
			} else {
				query += " AND " + folderClause
			}
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
	exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(active, "files")
	query := `
		WITH matching_files AS (
			SELECT files.id
			FROM files
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tags.name IN (` + placeholders + `)` + visibilityClause + folderClause + ` AND ` + exclusiveClause + `
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

	args := make([]interface{}, 0, len(active)+len(exclusiveArgs)+4)
	for _, tag := range active {
		args = append(args, tag)
	}
	args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		if publicOnly(ctx) {
			query := `
				WITH matching_files AS (
					SELECT DISTINCT file_histories.file_id
					FROM file_histories
					JOIN files ON files.id = file_histories.file_id
					WHERE file_histories.action_date = ? AND files.visibility = ? AND ` + exclusiveClause
			args := []interface{}{day, "public"}
			args = append(args, exclusiveArgs...)
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
					WHERE file_histories.action_date = ? AND ` + exclusiveClause
			args := []interface{}{day}
			args = append(args, exclusiveArgs...)
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
	exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(active, "files")
	query := `
		WITH matching_files AS (
			SELECT files.id
			FROM files
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE file_histories.action_date = ? AND tags.name IN (` + placeholders + `)` + visibilityClause + folderClause + ` AND ` + exclusiveClause + `
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

	args := make([]interface{}, 0, len(active)+len(exclusiveArgs)+5)
	args = append(args, day)
	for _, tag := range active {
		args = append(args, tag)
	}
	args = append(args, exclusiveArgs...)
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
	dayCounts := map[string]int{}
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

	for rows.Next() {
		var dayUnix int64
		var count int
		if err := rows.Scan(&dayUnix, &count); err != nil {
			return nil, err
		}
		day := time.Unix(dayUnix*secondsPerDay, 0).UTC().Format("2006-01-02")
		dayCounts[day] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	journalQuery := `
		SELECT updated_at
		FROM files
		WHERE is_journal = 1`
	journalArgs := []interface{}{}
	if publicOnly(ctx) {
		journalQuery += " AND visibility = ?"
		journalArgs = append(journalArgs, "public")
	}
	if folderClause != "" {
		journalQuery += " AND " + folderClause
		journalArgs = append(journalArgs, folderArgs...)
	}
	journalQuery += `
		ORDER BY updated_at DESC
		LIMIT ?`
	journalArgs = append(journalArgs, limit)
	journalRows, err := i.db.QueryContext(ctx, journalQuery, journalArgs...)
	if err != nil {
		return nil, err
	}
	defer journalRows.Close()
	for journalRows.Next() {
		var updatedAt int64
		if err := journalRows.Scan(&updatedAt); err != nil {
			return nil, err
		}
		day := time.Unix(updatedAt, 0).UTC().Format("2006-01-02")
		dayCounts[day]++
	}
	if err := journalRows.Err(); err != nil {
		return nil, err
	}

	dayKeys := make([]string, 0, len(dayCounts))
	for day := range dayCounts {
		dayKeys = append(dayKeys, day)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dayKeys)))
	if len(dayKeys) > limit {
		dayKeys = dayKeys[:limit]
	}
	days := make([]UpdateDaySummary, 0, len(dayKeys))
	for _, day := range dayKeys {
		days = append(days, UpdateDaySummary{Day: day, Count: dayCounts[day]})
	}
	return days, nil
}

func (i *Index) CountNotesWithOpenTasks(ctx context.Context, tags []string, folder string, rootOnly bool) (int, error) {
	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0`
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tags.name IN (` + placeholders + `)
		`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) NoteSummaryByPath(ctx context.Context, notePath string) (NoteSummary, error) {
	var note NoteSummary
	row := i.db.QueryRowContext(ctx, `
		SELECT path, title, mtime_unix, uid
		FROM files
		WHERE path=?
	`, notePath)
	var mtimeUnix int64
	if err := row.Scan(&note.Path, &note.Title, &mtimeUnix, &note.UID); err != nil {
		return NoteSummary{}, err
	}
	note.MTime = time.Unix(mtimeUnix, 0)
	return note, nil
}

func (i *Index) JournalNoteByDate(ctx context.Context, date string) (NoteSummary, bool, error) {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return NoteSummary{}, false, err
	}
	notePath := filepath.ToSlash(filepath.Join(parsed.Format("2006-01"), parsed.Format("02")+".md"))
	if publicOnly(ctx) {
		var note NoteSummary
		var mtimeUnix int64
		err := i.db.QueryRowContext(ctx, `
			SELECT path, title, mtime_unix, uid
			FROM files
			WHERE path=? AND visibility=? AND is_journal=1
		`, notePath, "public").Scan(&note.Path, &note.Title, &mtimeUnix, &note.UID)
		if errors.Is(err, sql.ErrNoRows) {
			return NoteSummary{}, false, nil
		}
		if err != nil {
			return NoteSummary{}, false, err
		}
		note.MTime = time.Unix(mtimeUnix, 0)
		return note, true, nil
	}
	note, err := i.NoteSummaryByPath(ctx, notePath)
	if errors.Is(err, sql.ErrNoRows) {
		return NoteSummary{}, false, nil
	}
	if err != nil {
		return NoteSummary{}, false, err
	}
	return note, true, nil
}

func (i *Index) NotesWithHistoryOnDate(ctx context.Context, date string, excludeUID string, tags []string, folder string, rootOnly bool, limit int, offset int) ([]NoteSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	dayUnix, err := dateToDay(date)
	if err != nil {
		return nil, err
	}

	var (
		query string
		args  []interface{}
	)
	folderClause, folderArgs := folderWhere(folder, rootOnly, "files")
	if len(tags) == 0 {
		query = `
			SELECT files.path, files.title, MAX(file_histories.action_time) AS last_action, files.uid
			FROM file_histories
			JOIN files ON files.id = file_histories.file_id
			WHERE file_histories.action_date = ?`
		args = []interface{}{dayUnix}
		if publicOnly(ctx) {
			query += " AND files.visibility = ?"
			args = append(args, "public")
		}
		if strings.TrimSpace(excludeUID) != "" {
			query += " AND files.uid != ?"
			args = append(args, excludeUID)
		}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			ORDER BY last_action DESC
			LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		query = `
			SELECT files.path, files.title, MAX(file_histories.action_time) AS last_action, files.uid
			FROM file_histories
			JOIN files ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		args = make([]interface{}, 0, len(tags)+5+len(folderArgs))
		args = append(args, dayUnix)
		if publicOnly(ctx) {
			query += " AND files.visibility = ?"
			args = append(args, "public")
		}
		if strings.TrimSpace(excludeUID) != "" {
			query += " AND files.uid != ?"
			args = append(args, excludeUID)
		}
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
		query += `
			GROUP BY files.id
			HAVING COUNT(DISTINCT tags.name) = ?
			ORDER BY last_action DESC
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
		var note NoteSummary
		var lastAction int64
		if err := rows.Scan(&note.Path, &note.Title, &lastAction, &note.UID); err != nil {
			return nil, err
		}
		note.MTime = time.Unix(lastAction, 0)
		notes = append(notes, note)
	}
	return notes, rows.Err()
}

func (i *Index) JournalDates(ctx context.Context) ([]time.Time, error) {
	query := "SELECT path FROM files WHERE is_journal = 1"
	args := []interface{}{}
	if publicOnly(ctx) {
		query += " AND visibility = ?"
		args = append(args, "public")
	}
	rows, err := i.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dates []time.Time
	for rows.Next() {
		var notePath string
		if err := rows.Scan(&notePath); err != nil {
			return nil, err
		}
		trimmed := strings.TrimSuffix(notePath, ".md")
		parts := strings.Split(trimmed, "/")
		if len(parts) != 2 {
			continue
		}
		dateStr := parts[0] + "-" + parts[1]
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}
		dates = append(dates, parsed)
	}
	return dates, rows.Err()
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ?`
		args = []interface{}{day}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.id
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
		args = append(args, len(tags))
		query = `SELECT COUNT(*) FROM (` + query + `)`
	}

	var count int
	if err := i.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (i *Index) CountTasks(ctx context.Context, filter TaskCountFilter) (int, error) {
	clauses := []string{"tasks.checked = 0"}
	args := make([]interface{}, 0, 6)

	if filter.DueOnly {
		dueDate := filter.DueDate
		if dueDate == "" {
			dueDate = time.Now().Format("2006-01-02")
		}
		clauses = append(clauses, "tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?")
		args = append(args, dueDate)
	}

	if filter.Date != "" {
		day, err := dateToDay(filter.Date)
		if err != nil {
			return 0, err
		}
		clauses = append(clauses, "file_histories.action_date = ?")
		args = append(args, day)
	}

	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat("?,", len(filter.Tags))
		placeholders = strings.TrimRight(placeholders, ",")
		clauses = append(clauses, "tags.name IN ("+placeholders+")")
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	if clause, clauseArgs := exclusiveTagFilterClause(filter.Tags, "files"); clause != "" {
		clauses = append(clauses, clause)
		args = append(args, clauseArgs...)
	}

	folderClause, folderArgs := folderWhere(filter.Folder, filter.Root, "files")
	if folderClause != "" {
		clauses = append(clauses, folderClause)
		args = append(args, folderArgs...)
	}

	sqlStr := `
		SELECT COUNT(*)
		FROM tasks
		JOIN files ON files.id = tasks.file_id
	`
	if filter.Date != "" {
		sqlStr += " JOIN file_histories ON files.id = file_histories.file_id"
	}
	if len(filter.Tags) > 0 {
		sqlStr += " JOIN file_tags ON files.id = file_tags.file_id JOIN tags ON tags.id = file_tags.tag_id"
	}
	applyVisibilityFilter(ctx, &clauses, &args, "files")
	if len(clauses) > 0 {
		sqlStr += " WHERE " + strings.Join(clauses, " AND ")
	}
	if len(filter.Tags) > 0 {
		sqlStr += " GROUP BY tasks.id HAVING COUNT(DISTINCT tags.name) = ?"
		args = append(args, len(filter.Tags))
	}

	var count int
	err := i.db.QueryRowContext(ctx, sqlStr, args...).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ?`
		args = []interface{}{dueDate}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND tags.name IN (` + placeholders + `)`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(nil, "files")
		query = `
			SELECT COUNT(DISTINCT files.id)
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ?`
		args = []interface{}{dueDate, day}
		query += " AND " + exclusiveClause
		args = append(args, exclusiveArgs...)
		if folderClause != "" {
			query += " AND " + folderClause
			args = append(args, folderArgs...)
		}
	} else {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		exclusiveClause, exclusiveArgs := exclusiveTagFilterClause(tags, "files")
		query = `
			SELECT files.id
			FROM files
			JOIN tasks ON files.id = tasks.file_id
			JOIN file_histories ON files.id = file_histories.file_id
			JOIN file_tags ON files.id = file_tags.file_id
			JOIN tags ON tags.id = file_tags.tag_id
			WHERE tasks.checked = 0 AND tasks.due_date IS NOT NULL AND tasks.due_date != '' AND tasks.due_date <= ? AND file_histories.action_date = ? AND tags.name IN (` + placeholders + `)`
		query += " AND " + exclusiveClause
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
		args = append(args, exclusiveArgs...)
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

func (i *Index) BrokenLinks(ctx context.Context) ([]BrokenLink, error) {
	visibilityClause := ""
	args := []any{}
	if publicOnly(ctx) {
		visibilityClause = " AND files.visibility = ?"
		args = append(args, "public")
	}
	rows, err := i.db.QueryContext(ctx, `
		SELECT broken_links.to_ref, files.path, files.title, broken_links.line_no, broken_links.line, broken_links.kind
		FROM broken_links
		JOIN files ON files.id = broken_links.from_file_id
		WHERE 1=1`+visibilityClause+`
		ORDER BY lower(broken_links.to_ref), lower(files.title), broken_links.line_no
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BrokenLink
	for rows.Next() {
		var link BrokenLink
		if err := rows.Scan(&link.ToRef, &link.FromPath, &link.FromTitle, &link.LineNo, &link.Line, &link.Kind); err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
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

func (i *Index) removeMissingRecords(ctx context.Context, records map[string]fileRecord, seen map[string]bool) (int, error) {
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
		return 0, nil
	}

	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	for _, row := range missingRows {
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_tags WHERE file_id=?", row.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM links WHERE from_file_id=?", row.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM tasks WHERE file_id=?", row.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_histories WHERE file_id=?", row.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM fts WHERE path=?", row.path); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM files WHERE id=?", row.id); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(missingRows), nil
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullIfZero(value int) any {
	if value == 0 {
		return nil
	}
	return value
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

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (i *Index) resolveLinkTargetID(ctx context.Context, q queryer, ref string) (int, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, nil
	}
	var id int
	err := q.QueryRowContext(ctx, "SELECT id FROM files WHERE uid=? LIMIT 1", ref).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	path := strings.TrimPrefix(ref, "/notes/")
	path = strings.TrimPrefix(path, "notes/")
	path = strings.TrimPrefix(path, "/")
	if path != "" {
		candidates := []string{path}
		if !strings.HasSuffix(strings.ToLower(path), ".md") {
			candidates = append(candidates, path+".md")
		}
		for _, candidate := range candidates {
			err = q.QueryRowContext(ctx, "SELECT id FROM files WHERE lower(path)=lower(?) LIMIT 1", candidate).Scan(&id)
			if err == nil {
				return id, nil
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return 0, err
			}
		}
	}
	err = q.QueryRowContext(ctx, "SELECT id FROM files WHERE lower(title)=lower(?) LIMIT 1", ref).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return 0, nil
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
