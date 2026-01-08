# gwiki

Minimal wiki server for a notes repo.

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
docker run --rm -p 8080:8080 -v /path/to/your/wiki/repo:/data gwiki
```

The server creates `.wiki/` and `notes/` inside the repo if missing and listens on
`0.0.0.0:8080` in the container (published to `localhost:8080` by default).

### Docker Compose

Set the host path and start:

```bash
WIKI_REPO_PATH_HOST=/path/to/your/wiki/repo docker compose up --build
```

Defaults to the current directory if `WIKI_REPO_PATH_HOST` is not set:

```bash
docker compose up --build
```

### Make targets

```bash
make docker-build
WIKI_REPO_PATH=/path/to/your/wiki/repo make docker-run
make run
WIKI_REPO_PATH=/path/to/your/wiki/repo make run
```

## Run (Local)

Set the repo path and start the server:

```bash
WIKI_REPO_PATH=/path/to/your/wiki/repo go run ./cmd/wiki
```

The server creates `.wiki/` and `notes/` inside the repo if missing and listens on
`127.0.0.1:8080` by default.

### Optional environment variables

- `WIKI_LISTEN_ADDR` (default: `127.0.0.1:8080`)
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
`$WIKI_REPO_PATH/.wiki/auth.txt`.

## Note format

gwiki supports a few wiki-style extensions in Markdown:

- Wiki links: `[[My Note]]` renders as a link to `/notes/my-note.md`.
- Nested tags with `/`: `#travel/food` expands to tags `travel` and `travel/food`.
- Embedded maps: a `https://maps.app.goo.gl/...` link auto-renders as an iframe.

Example:

```markdown
# Staycation

Planning #travel/food and #travel/japan

[[Ama Awa Resort]]

https://maps.app.goo.gl/FiNsEb1Q9CSfmT1SA
```
