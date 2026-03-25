package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

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
		case 17:
			slog.Info("schema migration", "from", 17, "to", 18)
			if err := i.migrate17To18(ctx); err != nil {
				return err
			}
			version = 18
		case 18:
			slog.Info("schema migration", "from", 18, "to", 19)
			if err := i.migrate18To19(ctx); err != nil {
				return err
			}
			version = 19
		case 19:
			slog.Info("schema migration", "from", 19, "to", 20)
			if err := i.migrate19To20(ctx); err != nil {
				return err
			}
			version = 20
		case 20:
			slog.Info("schema migration", "from", 20, "to", 21)
			if err := i.migrate20To21(ctx); err != nil {
				return err
			}
			version = 21
		case 21:
			slog.Info("schema migration", "from", 21, "to", 22)
			if err := i.migrate21To22(ctx); err != nil {
				return err
			}
			version = 22
		case 22:
			slog.Info("schema migration", "from", 22, "to", 23)
			if err := i.migrate22To23(ctx); err != nil {
				return err
			}
			version = 23
		case 23:
			slog.Info("schema migration", "from", 23, "to", 24)
			if err := i.migrate23To24(ctx); err != nil {
				return err
			}
			version = 24
		case 24:
			slog.Info("schema migration", "from", 24, "to", 25)
			if err := i.migrate24To25(ctx); err != nil {
				return err
			}
			version = 25
		case 25:
			slog.Info("schema migration", "from", 25, "to", 26)
			if err := i.migrate25To26(ctx); err != nil {
				return err
			}
			version = 26
		case 26:
			slog.Info("schema migration", "from", 26, "to", 27)
			if err := i.migrate26To27(ctx); err != nil {
				return err
			}
			version = 27
		case 27:
			slog.Info("schema migration", "from", 27, "to", 28)
			if err := i.migrate27To28(ctx); err != nil {
				return err
			}
			version = 28
		case 28:
			slog.Info("schema migration", "from", 28, "to", 29)
			if err := i.migrate28To29(ctx); err != nil {
				return err
			}
			version = 29
		case 29:
			slog.Info("schema migration", "from", 29, "to", 30)
			if err := i.migrate29To30(ctx); err != nil {
				return err
			}
			version = 30
		case 30:
			slog.Info("schema migration", "from", 30, "to", 31)
			if err := i.migrate30To31(ctx); err != nil {
				return err
			}
			version = 31
		case 31:
			slog.Info("schema migration", "from", 31, "to", 32)
			if err := i.migrate31To32(ctx); err != nil {
				return err
			}
			version = 32
		case 32:
			slog.Info("schema migration", "from", 32, "to", 33)
			if err := i.migrate32To33(ctx); err != nil {
				return err
			}
			version = 33
		case 33:
			slog.Info("schema migration", "from", 33, "to", 34)
			if err := i.migrate33To34(ctx); err != nil {
				return err
			}
			version = 34
		case 34:
			slog.Info("schema migration", "from", 34, "to", 35)
			if err := i.migrate34To35(ctx); err != nil {
				return err
			}
			version = 35
		case 35:
			slog.Info("schema migration", "from", 35, "to", 36)
			if err := i.migrate35To36(ctx); err != nil {
				return err
			}
			version = 36
		case 36:
			slog.Info("schema migration", "from", 36, "to", 37)
			if err := i.migrate36To37(ctx); err != nil {
				return err
			}
			version = 37
		case 37:
			slog.Info("schema migration", "from", 37, "to", 38)
			if err := i.migrate37To38(ctx); err != nil {
				return err
			}
			version = 38
		default:
			return fmt.Errorf("unsupported schema version: %d", version)
		}
	}
	return nil
}

func (i *Index) migrate3To4(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
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
	if _, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS tasks_by_file_checked ON tasks(file_id, checked)"); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS tasks_by_file_due ON tasks(file_id, due_date)"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate5To6(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "priority", "INTEGER NOT NULL DEFAULT 10")
}

func (i *Index) migrate6To7(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
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
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS collapsed_sections (
			note_id TEXT NOT NULL,
			line_no INTEGER NOT NULL,
			line TEXT NOT NULL,
			PRIMARY KEY(note_id, line_no)
		)`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS collapsed_sections_by_note ON collapsed_sections(note_id)")
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
	if _, err := i.execContext(ctx, `
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
	_, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS broken_links_by_file ON broken_links(from_file_id)")
	return err
}

func (i *Index) migrate17To18(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS collapsed_sections_new (
			note_id TEXT NOT NULL,
			line_no INTEGER NOT NULL,
			PRIMARY KEY(note_id, line_no)
		)
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		INSERT INTO collapsed_sections_new(note_id, line_no)
		SELECT DISTINCT note_id, line_no FROM collapsed_sections
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `DROP TABLE collapsed_sections`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `ALTER TABLE collapsed_sections_new RENAME TO collapsed_sections`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS collapsed_sections_by_note ON collapsed_sections(note_id)"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate18To19(ctx context.Context) error {
	if _, err := i.execContext(ctx, `DROP TABLE IF EXISTS fts`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
			path UNINDEXED,
			title,
			body,
			tokenize='trigram'
		)
	`); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate19To20(ctx context.Context) error {
	return nil
}

func (i *Index) migrate20To21(ctx context.Context) error {
	drops := []string{
		"DROP TABLE IF EXISTS files",
		"DROP TABLE IF EXISTS file_histories",
		"DROP TABLE IF EXISTS tags",
		"DROP TABLE IF EXISTS file_tags",
		"DROP TABLE IF EXISTS task_tags",
		"DROP TABLE IF EXISTS links",
		"DROP TABLE IF EXISTS tasks",
		"DROP TABLE IF EXISTS embed_cache",
		"DROP TABLE IF EXISTS collapsed_sections",
		"DROP TABLE IF EXISTS broken_links",
		"DROP TABLE IF EXISTS users",
		"DROP TABLE IF EXISTS groups",
		"DROP TABLE IF EXISTS group_members",
		"DROP TABLE IF EXISTS fts",
		"DROP TABLE IF EXISTS schema_version",
	}
	for _, stmt := range drops {
		if _, err := i.execContext(ctx, stmt); err != nil {
			return err
		}
	}
	_, err := i.execContext(ctx, schemaSQL)
	return err
}

func (i *Index) migrate21To22(ctx context.Context) error {
	if _, err := i.execContext(ctx, "DROP TABLE IF EXISTS file_histories"); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS file_histories (
			id INTEGER PRIMARY KEY,
			file_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			action_date INTEGER NOT NULL,
			UNIQUE(file_id, user_id, action_date)
		)`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS file_histories_by_date ON file_histories(action_date)")
	return err
}

func (i *Index) migrate22To23(ctx context.Context) error {
	_, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS git_sync_state (
			owner_name TEXT NOT NULL PRIMARY KEY,
			last_sync_unix INTEGER NOT NULL
		)`)
	return err
}

func (i *Index) migrate23To24(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS task_tags (
			user_id INTEGER NOT NULL,
			task_id INTEGER NOT NULL,
			tag_id INTEGER NOT NULL
		)`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS task_tags_user ON task_tags(user_id, task_id, tag_id)"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate24To25(ctx context.Context) error {
	return i.ensureColumn(ctx, "files", "etag_time", "INTEGER NOT NULL DEFAULT 0")
}

func (i *Index) migrate25To26(ctx context.Context) error {
	if _, err := i.execContext(ctx, `DROP TABLE IF EXISTS fts`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, `
		CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
			user_id UNINDEXED,
			path,
			title,
			body,
			tokenize='trigram'
		)
	`)
	return err
}

func (i *Index) migrate26To27(ctx context.Context) error {
	_, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS user_access (
			owner_user_id INTEGER NOT NULL,
			grantee_user_id INTEGER NOT NULL,
			access TEXT NOT NULL,
			PRIMARY KEY(owner_user_id, grantee_user_id)
		)
	`)
	return err
}

func (i *Index) migrate27To28(ctx context.Context) error {
	drops := []string{
		"DROP TABLE IF EXISTS files",
		"DROP TABLE IF EXISTS file_histories",
		"DROP TABLE IF EXISTS tags",
		"DROP TABLE IF EXISTS file_tags",
		"DROP TABLE IF EXISTS links",
		"DROP TABLE IF EXISTS tasks",
		"DROP TABLE IF EXISTS task_tags",
		"DROP TABLE IF EXISTS embed_cache",
		"DROP TABLE IF EXISTS collapsed_sections",
		"DROP TABLE IF EXISTS broken_links",
		"DROP TABLE IF EXISTS fts",
		"DROP TABLE IF EXISTS user_access",
		"DROP TABLE IF EXISTS path_access",
		"DROP TABLE IF EXISTS path_access_files",
		"DROP TABLE IF EXISTS file_access",
	}
	for _, stmt := range drops {
		if _, err := i.execContext(ctx, stmt); err != nil {
			return err
		}
	}
	_, err := i.execContext(ctx, schemaSQL)
	return err
}

func (i *Index) migrate28To29(ctx context.Context) error {
	drops := []string{
		"DROP TABLE IF EXISTS files",
		"DROP TABLE IF EXISTS file_histories",
		"DROP TABLE IF EXISTS tags",
		"DROP TABLE IF EXISTS file_tags",
		"DROP TABLE IF EXISTS links",
		"DROP TABLE IF EXISTS tasks",
		"DROP TABLE IF EXISTS task_tags",
		"DROP TABLE IF EXISTS embed_cache",
		"DROP TABLE IF EXISTS collapsed_sections",
		"DROP TABLE IF EXISTS broken_links",
		"DROP TABLE IF EXISTS fts",
		"DROP TABLE IF EXISTS user_access",
		"DROP TABLE IF EXISTS path_access",
		"DROP TABLE IF EXISTS path_access_files",
		"DROP TABLE IF EXISTS file_access",
	}
	for _, stmt := range drops {
		if _, err := i.execContext(ctx, stmt); err != nil {
			return err
		}
	}
	_, err := i.execContext(ctx, schemaSQL)
	return err
}

func (i *Index) ensureColumn(ctx context.Context, table string, column string, ddl string) error {
	hasColumn := false
	rows, err := i.queryContext(ctx, "PRAGMA table_info("+table+")")
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
	_, err = i.execContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ddl))
	return err
}

func (i *Index) schemaVersion(ctx context.Context) (int, error) {
	var v int
	err := i.queryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

func (i *Index) setSchemaVersion(ctx context.Context, v int) error {
	_, err := i.execContext(ctx, "DELETE FROM schema_version")
	if err != nil {
		return err
	}
	_, err = i.execContext(ctx, "INSERT INTO schema_version(version) VALUES(?)", v)
	return err
}

func (i *Index) migrate29To30(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS file_cleanup (
			user_id INTEGER NOT NULL,
			path TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY(user_id, path)
		)`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS file_cleanup_expires ON file_cleanup(user_id, expires_at)"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate30To31(ctx context.Context) error {
	if err := i.ensureColumn(ctx, "users", "last_sync_unix", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := i.ensureColumn(ctx, "users", "last_sync_status", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate31To32(ctx context.Context) error {
	if err := i.ensureColumn(ctx, "users", "last_success_sync_unix", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate32To33(ctx context.Context) error {
	if err := i.ensureColumn(ctx, "path_access_files", "visibility", "TEXT NOT NULL DEFAULT 'private'"); err != nil {
		return err
	}
	return nil
}

func (i *Index) migrate33To34(ctx context.Context) error {
	_, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS attachment_dates (
			owner_user_id INTEGER NOT NULL,
			note_id TEXT NOT NULL,
			name TEXT NOT NULL,
			commit_unix INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(owner_user_id, note_id, name)
		)
	`)
	return err
}

func (i *Index) migrate34To35(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS attachment_dates_new (
			owner_user_id INTEGER NOT NULL,
			note_id TEXT NOT NULL,
			name TEXT NOT NULL,
			commit_unix INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(owner_user_id, note_id, name)
		)
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		INSERT INTO attachment_dates_new(owner_user_id, note_id, name, commit_unix, updated_at)
		SELECT owner_user_id, note_id, name, commit_unix, updated_at
		FROM attachment_dates
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `DROP TABLE IF EXISTS attachment_dates`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, `ALTER TABLE attachment_dates_new RENAME TO attachment_dates`)
	return err
}

func (i *Index) migrate35To36(ctx context.Context) error {
	if _, err := i.execContext(ctx, `DROP TABLE IF EXISTS fts_backup`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		CREATE TABLE fts_backup (
			user_id INTEGER NOT NULL,
			path TEXT NOT NULL,
			title TEXT,
			body TEXT
		)
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		INSERT INTO fts_backup(user_id, path, title, body)
		SELECT user_id, path, title, body
		FROM fts
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `DROP TABLE IF EXISTS fts`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
			user_id UNINDEXED,
			path,
			title,
			h1,
			h2,
			h3,
			h4,
			h5,
			h6,
			body,
			tokenize='trigram'
		)
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		INSERT INTO fts(user_id, path, title, h1, h2, h3, h4, h5, h6, body)
		SELECT user_id, path, title, '', '', '', '', '', '', body
		FROM fts_backup
	`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, `DROP TABLE IF EXISTS fts_backup`)
	return err
}

func (i *Index) migrate36To37(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS note_blocks (
			file_id INTEGER NOT NULL,
			block_id INTEGER NOT NULL,
			parent_block_id INTEGER NOT NULL,
			level INTEGER NOT NULL,
			start_line INTEGER NOT NULL,
			end_line INTEGER NOT NULL,
			PRIMARY KEY(file_id, block_id)
		)
	`); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS note_blocks_by_parent ON note_blocks(file_id, parent_block_id)"); err != nil {
		return err
	}
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS note_block_tags (
			file_id INTEGER NOT NULL,
			block_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY(file_id, block_id, tag)
		)
	`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS note_block_tags_by_file_tag ON note_block_tags(file_id, tag)")
	return err
}

func (i *Index) migrate37To38(ctx context.Context) error {
	if _, err := i.execContext(ctx, `
		CREATE TABLE IF NOT EXISTS signal_attachment_retries (
			owner_name TEXT NOT NULL,
			note_id TEXT NOT NULL,
			attachment_id TEXT NOT NULL,
			filename TEXT NOT NULL DEFAULT '',
			content_type TEXT NOT NULL DEFAULT '',
			attempt INTEGER NOT NULL DEFAULT 0,
			next_retry_unix INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(owner_name, note_id, attachment_id)
		)
	`); err != nil {
		return err
	}
	_, err := i.execContext(ctx, "CREATE INDEX IF NOT EXISTS signal_attachment_retries_due ON signal_attachment_retries(owner_name, next_retry_unix)")
	return err
}
