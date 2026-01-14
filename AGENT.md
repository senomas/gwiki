# agent.md — Personal Wiki (Go + HTMX + Markdown + Git)

You are Codex working inside this repository. Implement a personal wiki app in **Golang** with **HTMX** UI. The **filesystem Markdown files are the source of truth**. A **DB (SQLite first, Postgres optional)** is used only for indexing/caching (tags, links, tasks, search, render cache). **Git sync/commit is delayed** and used only for backup/history.

## Product goals (v1)

- Web-first editing (mobile-friendly), minimal JS.
- Notes stored as Markdown files in a repo directory.
- Fast browsing/search via DB index (rebuildable).
- Safe saving (atomic writes), no data loss.
- Delayed git commit/push (debounced) for history/backup.

Non-goals (v1)

- Multi-user permissions/roles.
- Realtime collaborative editing.
- Complex WYSIWYG editor.

---

## Key principles

1. **FS is truth, DB is derived**
   - If DB is deleted, the app can rebuild the index by scanning the repo.
2. **Never store canonical content only in DB**
   - Markdown file content must always exist and be current.
3. **Git is for history/backup**
   - Do not commit internal indexes/caches (ignore `.wiki/`).
4. **Security-by-default**
   - Single-user auth is required if exposed outside localhost.
5. **Testing discipline**
   - After completing any planned work, run the full test suite (e.g., `go test ./...`) before reporting.
6. **Workflow**
   - Before making changes, explain the plan and wait for confirmation unless the task is trivial.

---

## Repository layout (expected)

```

wiki/
notes/                # canonical markdown notes
notes/attachments/    # per-note attachments (notes/attachments/{note-id}/...)
templates/            # html/template files
.wiki/                # internal data (default WIKI_DATA_PATH if not set)
index.sqlite        # derived DB (ignored by git)
drafts/             # autosave drafts (ignored by git)
cache/              # optional render cache (ignored by git)

```

- Notes live under `notes/`. Treat all note identifiers as **repo-relative paths under notes**.
- Attachments live under `notes/attachments/` and must follow the same path safety rules as notes.
- Internal data (index, auth, drafts) lives under `WIKI_DATA_PATH` (defaults to `.wiki/` under the repo path).
- Ignore `.wiki/` in `.gitignore` (or your `WIKI_DATA_PATH` location).

---

## Markdown conventions

Support:

- YAML frontmatter (optional):
  - `id`, `title`, `tags`, `created`, `updated`
- Inline tags: `#tag` and nested tags with `/` (e.g., `#travel/food`)
- Tasks:
  - `- [ ] task text`
  - `- [x] done text`
  - Optional due marker: `@due(YYYY-MM-DD)` or `due:YYYY-MM-DD`
Links:
  - Wiki links: `[[Some Note]]` or `[[file-id]]` (resolve by uid, title, or path)
  - Markdown links: `[text](relative/path.md)`

Rendering:

- Use a Go Markdown renderer (e.g., goldmark).
- Sanitize/disable raw HTML in Markdown by default.
- Title resolution: frontmatter `title` wins; else first Markdown H1.

Slugging and link resolution:

- Slug rule: `title` -> lowercase -> replace non-alnum with `-` -> trim `-`.
- Collisions: if `notes/{slug}.md` exists, append `-2`, `-3`, etc.
- Wiki links: `[[Some Note]]` resolves via the same slugging rule; if multiple matches exist, prefer exact-title match, then shortest path.
- Store a stable `id` (UUID) in frontmatter for internal identity; paths remain slug-based.

---

## HTMX UI (v1 pages)

1. **Home/Search**
   - search input with HTMX results swap
   - recent notes list
2. **View note**
   - rendered HTML
   - tags, backlinks
   - buttons: Edit, Rename, Delete
3. **Edit note**
   - `<textarea>` for markdown
   - optional live preview panel updated via HTMX debounce
   - Save button
4. **New note**
   - title -> slug -> create file -> redirect to edit

HTMX patterns

- Use partial templates for:
  - search results
  - note view content
  - preview content
  - toast/flash messages
- Prefer `hx-swap="outerHTML"` or `innerHTML` intentionally (no accidental layout changes).
- Use `hx-trigger="keyup changed delay:600ms"` for preview typing debounce.
- Ensure all endpoints return HTML fragments for HTMX, full page for normal navigation.

---

## HTTP endpoints (minimal)

- `GET  /` home
- `GET  /notes/{path}` view
- `GET  /notes/{path}/edit` edit
- `POST /notes/{path}/save` save markdown (atomic)
- `POST /notes/{path}/preview` render markdown preview fragment
- `POST /notes/new` create note (title -> path)
- `GET  /search?q=...` search results fragment
- `GET  /tags/{tag}` tagged list fragment
- (optional) `POST /sync/commit` commit now
- (optional) `POST /sync/push` push now
- (optional) `GET  /status` returns a small status fragment (dirty, last commit)

Path safety rules

- `{path}` is a repo-relative path under `notes/`.
- Reject `..`, absolute paths, backslashes, NUL, and any path escaping `notes/`.
- Normalize separators to `/`.

---

## Persistence (DB) — derived index

SQLite first. Postgres optional later behind an interface.

Current schema (SQLite)

- `schema_version(version)`
- `files(id, path UNIQUE, title, uid, hash, mtime_unix, size, created_at, updated_at, priority DEFAULT 10)`
- `file_histories(id, file_id, user, action, action_time, action_date)`
- `tags(id, name UNIQUE)`
- `file_tags(file_id, tag_id, PRIMARY KEY(file_id, tag_id))`
- `links(id, from_file_id, to_ref, to_file_id NULL, kind, line_no, line)` where kind in ('wikilink','mdlink')
- `tasks(id, file_id, line_no, text, checked, due_date NULL, updated_at)`
- `embed_cache(url, kind, embed_url, status, error_msg, updated_at, expires_at, PRIMARY KEY(url, kind))`
- Search (FTS5):
  - `fts(path UNINDEXED, title, body)`
  - Keep `fts` synced on file changes.

Rebuild

- On startup, if DB missing or schema mismatch: scan all notes, parse, populate tables.
- On startup, recheck filesystem vs DB and reindex notes whose size/mtime/hash changed; remove DB rows for missing files.
- Store a `schema_version` table/entry and rebuild on mismatch.

---

## Indexing pipeline

- On save or FS change:
  1. Read file content
  2. Compute `hash` (sha256 or xxhash)
  3. Parse metadata (title/tags/links/tasks)
  4. Upsert `files`
  5. Replace derived rows for that file (tags/links/tasks)
  6. Update FTS row (title+body)
- Optionally use fsnotify watcher + periodic scan as fallback.

Concurrency

- Use a per-note lock (in-memory mutex keyed by normalized path) to prevent concurrent writes.
- DB writes should be in transactions.

---

## Saving (atomic write)

When saving a note:

- Write to temp file in same directory: `.tmp.<name>.<pid>`
- `fsync` file
- `rename` to target path
- (optional) `fsync` directory
  This avoids partial writes on power loss.

Draft autosave (optional v1.1)

- Autosave to `${WIKI_DATA_PATH}/drafts/{note-id}.md` (not committed)
- On edit page load, if a newer draft exists, offer restore.

---

## Git sync (delayed)

Goal: backup/history, not constant noise.

Rules

- `.wiki/` must be ignored and never committed.
- After a successful real save:
  - mark repo as "dirty"
  - start/reset a debounce timer (e.g., 2–5 minutes)
- When timer fires:
  - `git add -A`
  - `git commit -m "wiki: autosave YYYY-MM-DD HH:mm"`
  - optionally a separate longer debounce for `git push` (or manual push button)
- If nothing to commit, do nothing.
- If git unavailable or fails, surface status but do not block editing.

Implementation

- Shell out to `git` CLI (simple, reliable).
- Capture stdout/stderr for debugging in logs.

---

## Security (required)

If not strictly localhost-only:

- Add Basic Auth or a simple session login.
- Set secure headers (at minimum):
  - `Content-Security-Policy` (restrict scripts)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
- Escape all user content in templates; only inject rendered markdown that has been sanitized.

---

## Config (minimal example)

```
WIKI_REPO_PATH=/path/to/wiki
WIKI_DATA_PATH=/path/to/wiki/.wiki
WIKI_LISTEN_ADDR=127.0.0.1:8080
WIKI_AUTH_USER=admin
WIKI_AUTH_PASS=changeme
WIKI_GIT_DEBOUNCE=3m
WIKI_GIT_PUSH_DEBOUNCE=10m
```

---

## Logging & observability

- Use Go `slog`.
- Log: save events, indexing duration, git commit/push results, errors.
- Avoid logging full note contents.

---

## Testing expectations

- Unit tests:
  - path normalization + traversal rejection
  - markdown parsing for tags/links/tasks
  - atomic save writes correct content
- Integration test:
  - create note -> save -> view -> search
- Rebuild test:
  - delete DB -> rebuild -> search works

---

## Code style / project structure

Prefer a clean layout:

- `cmd/wiki/` main
- `internal/web/` handlers + templates rendering
- `internal/storage/fs/` read/write markdown, path safety
- `internal/index/` parsing + DB upserts
- `internal/search/` query layer
- `internal/git/` debounce commit/push worker
- `internal/model/` shared structs

Guidelines

- Keep handlers thin; business logic in internal packages.
- Use context-aware DB calls.
- Avoid global state except for injected dependencies.
- Prefer Go stdlib where possible; keep third-party deps minimal and justified (e.g., markdown rendering).

---

## Deliverables for the first implementation

1. Working HTMX pages: home/search, view, edit, new.
2. Save endpoint with atomic writes.
3. SQLite index with FTS search.
4. Delayed git commit (debounce) after saves.
5. `.gitignore` excludes `.wiki/` and drafts/cache (or your `WIKI_DATA_PATH` location).
6. A simple config file/env vars:
   - repo path, listen addr, auth creds, git debounce durations.

When in doubt: prefer the simplest approach that preserves the principles:
**Markdown in FS is truth; DB is cache; Git is delayed backup.**
