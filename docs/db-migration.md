# Database Migration Guide

This project uses SQLite for a derived index/cache. Markdown files in `notes/` are the source of truth.

- Canonical data: filesystem (`<owner>/notes/**/*.md`)
- Derived data: SQLite (`.wiki/index.sqlite` by default)
- Migration entrypoint: `internal/index/index.go` (`InitWithOwners`)

Because DB is derived, migration safety is focused on index correctness and startup reliability, not content preservation.

## Current Migration Model

Schema versioning is implemented in code:

- Current schema version constant: `internal/index/schema.go` (`schemaVersion`)
- Target schema DDL: `internal/index/schema.go` (`schemaSQL`)
- Version switch and step migrations: `internal/index/index.go` (`migrateSchema`)
- Version read/write: `schemaVersion()` / `setSchemaVersion()`

Startup behavior in `InitWithOwners`:

1. Apply `schemaSQL` with `CREATE ... IF NOT EXISTS`.
2. Read `schema_version`.
3. If version is `0`, set it to legacy baseline (`3`).
4. If version differs from current:
   - run `migrateSchema(fromVersion)`
   - set final `schema_version` to current
   - sync owners
   - run full reindex: `RebuildFromFS(...)`
5. If version already current:
   - sync owners
   - run compatibility `ensureColumn(...)` checks
   - run incremental recheck: `RecheckFromFS(...)`

## When to Add a Migration

Add a migration when any existing table/index/FTS structure changes in a way that can affect existing DB files:

- New table/index/virtual table
- Column type/default/constraint changes
- Table reshape or dedup/cleanup transformation
- FTS schema/tokenizer/column changes
- Data backfill needed for new behavior

For purely additive and optional fields, prefer `ensureColumn(...)` if possible.

## How to Add a New Migration

Use this checklist:

1. Update target schema
- Edit `internal/index/schema.go`:
  - bump `schemaVersion` by `+1`
  - update `schemaSQL` to the new final shape

2. Add migration function
- In `internal/index/index.go`, add:
  - `func (i *Index) migrate<old>To<new>(ctx context.Context) error`

3. Wire migration step
- In `migrateSchema(...)` switch:
  - add `case <old>:` block
  - log with `slog.Info("schema migration", "from", <old>, "to", <new>)`
  - call your new function
  - set `version = <new>`

4. Choose migration style
- Additive:
  - `ensureColumn(...)`
  - `CREATE TABLE/INDEX IF NOT EXISTS`
- Transform:
  - create `_new` table
  - copy/normalize data
  - drop old table
  - rename `_new` to original
- Rebuild-oriented:
  - drop affected derived tables and recreate
  - rely on `RebuildFromFS(...)` after migration

5. Keep migration idempotent where practical
- Use `IF NOT EXISTS` / `DROP ... IF EXISTS`
- Handle partially migrated states safely

6. Add tests
- Add/extend index migration tests (pattern in `internal/index/user_sync_state_test.go`)
- Create a DB at old schema version, run `Init(...)`, assert:
  - migration success
  - expected columns/tables/data behavior

7. Run validation
- `make quick-test`
- `make test`

## Rollout Runbook

Before deploy:

1. Back up DB file(s)
- Example: copy `.wiki/index.sqlite` per environment.

2. Deploy binary with migration code.

3. Start app and verify logs:
- `schema migration` entries for each step
- `index rebuild complete` after version change
- `index recheck complete` on normal startup

4. Smoke test:
- open `/`
- open `/todo`
- run search
- open a note detail page

If startup fails during migration:

1. Stop app.
2. Restore DB backup.
3. Roll back binary to previous version.
4. Fix migration code and retry.

## Manual Inspection Commands

Check schema version:

```bash
sqlite3 .wiki/index.sqlite "SELECT version FROM schema_version;"
```

List tables:

```bash
sqlite3 .wiki/index.sqlite ".tables"
```

Inspect a table schema:

```bash
sqlite3 .wiki/index.sqlite "PRAGMA table_info(files);"
```

## Important Notes

- Never treat SQLite as canonical note storage.
- `RebuildFromFS(...)` clears derived tables and reindexes from markdown files.
- Attachments are not markdown index inputs; note files remain the authoritative source for index rebuild.
- Keep user-facing errors generic; put details in logs.

## Migration PR Checklist

- [ ] `schemaVersion` bumped
- [ ] `schemaSQL` updated
- [ ] new `migrateXToY` added
- [ ] `migrateSchema` switch updated
- [ ] migration test(s) added/updated
- [ ] `make test` passed
- [ ] startup logs verified in local run
