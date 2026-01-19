package index

const schemaVersion = 15

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
	id INTEGER PRIMARY KEY,
	path TEXT UNIQUE NOT NULL,
	title TEXT,
	uid TEXT,
	visibility TEXT NOT NULL DEFAULT 'private',
	hash TEXT,
	mtime_unix INTEGER,
	size INTEGER,
	created_at INTEGER,
	updated_at INTEGER,
	priority INTEGER NOT NULL DEFAULT 10,
	is_journal INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS file_histories (
	id INTEGER PRIMARY KEY,
	file_id INTEGER NOT NULL,
	user TEXT NOT NULL,
	action TEXT NOT NULL,
	action_time INTEGER NOT NULL,
	action_date INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
	id INTEGER PRIMARY KEY,
	name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS file_tags (
	file_id INTEGER NOT NULL,
	tag_id INTEGER NOT NULL,
	PRIMARY KEY(file_id, tag_id)
);

CREATE TABLE IF NOT EXISTS links (
	id INTEGER PRIMARY KEY,
	from_file_id INTEGER NOT NULL,
	to_ref TEXT NOT NULL,
	to_file_id INTEGER,
	kind TEXT NOT NULL,
	line_no INTEGER NOT NULL,
	line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
	id INTEGER PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS embed_cache (
	url TEXT NOT NULL,
	kind TEXT NOT NULL,
	embed_url TEXT,
	status TEXT NOT NULL,
	error_msg TEXT,
	updated_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY(url, kind)
);

CREATE TABLE IF NOT EXISTS collapsed_sections (
	note_id TEXT NOT NULL,
	line_no INTEGER NOT NULL,
	line TEXT NOT NULL,
	PRIMARY KEY(note_id, line_no)
);

CREATE INDEX IF NOT EXISTS collapsed_sections_by_note ON collapsed_sections(note_id);

CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
	path UNINDEXED,
	title,
	body
);
`
