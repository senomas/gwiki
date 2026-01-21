# gwiki

Personal wiki server with keyboard-focused, vim-like navigation and Markdown notes on disk. Uses
standard Markdown with YAML frontmatter, keeps a fast SQLite index for browsing,
and relies on Git for backup/history.

## Docs

- Usage guide: `docs/usage.md`

## Highlights

- Keyboard-focused, vim-like navigation and quick launcher.
- Standard Markdown + YAML frontmatter stored on disk.
- Designed for personal or very small team usage.
- Git-based backup and history for changes.

## Requirements

- Docker (recommended)
- Go 1.22+ (from `go.mod`, for local dev)

## Run (Docker)

Build the image:

```bash
docker build -t gwiki .
```

Run with a mounted repo:

```bash
docker run --rm -p 8080:8080 -v /path/to/your/wiki/repo:/notes -v /path/to/your/wiki/.wiki:/data -e WIKI_REPO_PATH=/notes -e WIKI_DATA_PATH=/data gwiki
```

The server uses `WIKI_REPO_PATH` for notes (`notes/`) and `WIKI_DATA_PATH` for
internal data (SQLite index, auth file). It listens on `0.0.0.0:8080` in the
container (published to `localhost:8080` by default).

### Docker Compose

Set the host paths and start:

```bash
WIKI_REPO_PATH_HOST=/path/to/your/wiki/repo WIKI_DATA_PATH_HOST=/path/to/your/wiki/.wiki docker compose up --build
```

Defaults to the current directory if `WIKI_REPO_PATH_HOST` is not set:

```bash
docker compose up --build
```

Optional Compose envs:

- `TZ` (default: `Asia/Jakarta`)
- `UID` and `GID` (default: `1000`, container runs as this user)

## Run (Local)

Set the repo and data paths and start the server:

```bash
WIKI_REPO_PATH=/path/to/your/wiki/repo WIKI_DATA_PATH=/path/to/your/wiki/.wiki go run ./cmd/wiki
```

The server creates `notes/` under `WIKI_REPO_PATH` and stores internal data under
`WIKI_DATA_PATH` if missing and listens on `127.0.0.1:8080` by default.

### Optional environment variables

- `WIKI_LISTEN_ADDR` (default: `127.0.0.1:8080`)
- `WIKI_REPO_PATH` (notes root; `notes/` lives here)
- `WIKI_DATA_PATH` (internal data root; `index.sqlite` and auth file live here)
- `WIKI_AUTH_USER`
- `WIKI_AUTH_PASS`
- `WIKI_AUTH_FILE` (per-line `user:$argon2id$...` hashes)
- `WIKI_GIT_DEBOUNCE` (default: `3m`)
- `WIKI_GIT_PUSH_DEBOUNCE` (default: `10m`)

### Auth file format

Each non-empty, non-comment line is `user:argon2id_hash`:

```
alice:$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$FqYyK9XjY6Z8w1mYp0KXcg
```

If both `WIKI_AUTH_FILE` and `WIKI_AUTH_USER`/`WIKI_AUTH_PASS` are set, both are
accepted (env wins on duplicate usernames).

### Add or update a user

```bash
go run ./cmd/user-add <username>
```

The command writes to `WIKI_AUTH_FILE` when set, otherwise to
`$WIKI_DATA_PATH/auth.txt` (or `$WIKI_REPO_PATH/.wiki/auth.txt` if `WIKI_DATA_PATH` is unset).

## Note format

See `docs/usage.md` for supported Markdown and tips.
