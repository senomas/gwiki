package index

const schemaVersion = 30

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS path_access_files (
	owner_user_id INTEGER NOT NULL,
	path TEXT NOT NULL,
	depth INTEGER NOT NULL,
	PRIMARY KEY(owner_user_id, path)
);

CREATE INDEX IF NOT EXISTS path_access_files_owner_depth ON path_access_files(owner_user_id, depth DESC);

CREATE TABLE IF NOT EXISTS path_access (
	owner_user_id INTEGER NOT NULL,
	path TEXT NOT NULL,
	grantee_user_id INTEGER NOT NULL,
	access TEXT NOT NULL,
	PRIMARY KEY(owner_user_id, path, grantee_user_id)
);

CREATE INDEX IF NOT EXISTS path_access_owner_user ON path_access(owner_user_id, grantee_user_id);

CREATE TABLE IF NOT EXISTS files (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	path TEXT NOT NULL,
	title TEXT,
	uid TEXT,
	visibility TEXT NOT NULL DEFAULT 'private',
	hash TEXT,
	mtime_unix INTEGER,
	size INTEGER,
	created_at INTEGER,
	updated_at INTEGER,
	etag_time INTEGER NOT NULL DEFAULT 0,
	priority INTEGER NOT NULL DEFAULT 10,
	is_journal INTEGER NOT NULL DEFAULT 0,
	UNIQUE(user_id, path)
);

CREATE TABLE IF NOT EXISTS file_access (
	file_id INTEGER NOT NULL,
	grantee_user_id INTEGER NOT NULL,
	access TEXT NOT NULL,
	PRIMARY KEY(file_id, grantee_user_id)
);

CREATE INDEX IF NOT EXISTS file_access_by_user ON file_access(grantee_user_id);

CREATE TABLE IF NOT EXISTS file_histories (
	id INTEGER PRIMARY KEY,
	file_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	action_date INTEGER NOT NULL,
	UNIQUE(file_id, user_id, action_date)
);

CREATE INDEX IF NOT EXISTS file_histories_by_date ON file_histories(action_date);

CREATE TABLE IF NOT EXISTS git_sync_state (
	owner_name TEXT NOT NULL PRIMARY KEY,
	last_sync_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS file_tags (
	user_id INTEGER NOT NULL,
	file_id INTEGER NOT NULL,
	tag_id INTEGER NOT NULL,
	is_exclusive INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(file_id, tag_id)
);

CREATE TABLE IF NOT EXISTS links (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	from_file_id INTEGER NOT NULL,
	to_ref TEXT NOT NULL,
	to_file_id INTEGER,
	kind TEXT NOT NULL,
	line_no INTEGER NOT NULL,
	line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	file_id INTEGER NOT NULL,
	line_no INTEGER NOT NULL,
	text TEXT NOT NULL,
	hash TEXT NOT NULL,
	checked INTEGER NOT NULL,
	due_date TEXT,
	updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tasks_by_file_checked ON tasks(file_id, checked);
CREATE INDEX IF NOT EXISTS tasks_by_file_due ON tasks(file_id, due_date);

CREATE TABLE IF NOT EXISTS task_tags (
	user_id INTEGER NOT NULL,
	task_id INTEGER NOT NULL,
	tag_id INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS task_tags_user ON task_tags(user_id, task_id, tag_id);

CREATE TABLE IF NOT EXISTS embed_cache (
	user_id INTEGER NOT NULL,
	url TEXT NOT NULL,
	kind TEXT NOT NULL,
	embed_url TEXT,
	status TEXT NOT NULL,
	error_msg TEXT,
	updated_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY(user_id, url, kind)
);

CREATE TABLE IF NOT EXISTS collapsed_sections (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	note_id TEXT NOT NULL,
	line_no INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS collapsed_sections_user ON collapsed_sections(user_id, note_id, line_no);
CREATE INDEX IF NOT EXISTS collapsed_sections_by_note ON collapsed_sections(note_id);

CREATE TABLE IF NOT EXISTS broken_links (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	from_file_id INTEGER NOT NULL,
	to_ref TEXT NOT NULL,
	kind TEXT NOT NULL,
	line_no INTEGER NOT NULL,
	line TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS broken_links_by_file ON broken_links(from_file_id);

CREATE TABLE IF NOT EXISTS file_cleanup (
	user_id INTEGER NOT NULL,
	path TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY(user_id, path)
);

CREATE INDEX IF NOT EXISTS file_cleanup_expires ON file_cleanup(user_id, expires_at);

CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
	user_id UNINDEXED,
	path,
	title,
	body,
	tokenize='trigram'
);
`
