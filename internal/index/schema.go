package index

const schemaVersion = 4

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
	id INTEGER PRIMARY KEY,
	path TEXT UNIQUE NOT NULL,
	title TEXT,
	hash TEXT,
	mtime_unix INTEGER,
	size INTEGER,
	created_at INTEGER,
	updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS file_updates (
	id INTEGER PRIMARY KEY,
	file_id INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	updated_day INTEGER NOT NULL
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
	kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
	id INTEGER PRIMARY KEY,
	file_id INTEGER NOT NULL,
	line_no INTEGER NOT NULL,
	text TEXT NOT NULL,
	checked INTEGER NOT NULL,
	due_date TEXT
);

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

CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
	path UNINDEXED,
	title,
	body
);
`
