# Usage Guide

This page covers everyday use of gwiki: keyboard navigation, quick launcher, and supported markdown.

## Keyboard Navigation

- `Ctrl+Space`: open the quick launcher.
- `Ctrl+J` / `Ctrl+ArrowDown`: move to next item (notes/titles/tasks, depending on page).
- `Ctrl+K` / `Ctrl+ArrowUp`: move to previous item.
- `Ctrl+H` / `Ctrl+ArrowLeft`: history back (disabled inside inputs).
- `Ctrl+L` / `Ctrl+ArrowRight`: history forward (disabled inside inputs).
- `Ctrl+Y`: go to index (disabled inside inputs).
- `Ctrl+Enter`: save on the edit page.
- `Ctrl+Esc`: cancel on the edit page.
- `J` / `K`: scroll down/up (disabled inside inputs).
- `Y`: scroll to top (disabled inside inputs).

Tip: on index/todo pages, navigation focuses note titles. On note pages it focuses note content links, checkboxes, and section toggles.

## Quick Launcher

- Open with `Ctrl+Space` or click your username (top right).
- Type to search actions, tags, folders, and notes (ordered: actions → tags → folders → notes).
- Use Arrow Up/Down and Enter to select.
- Selecting a note opens a submenu (Open/Edit/Delete). Enter activates the focused item.
- Tag and folder results toggle filters on the current page (they keep your existing query params).

## Edit Commands

In the edit textarea, type a command and press space to expand it on the current line. Commands are configurable in Settings (Appearance → Edit commands) using a trigger + token system. Defaults shown below.

Defaults (trigger `!`):
- `!!` → task checkbox (`- [ ] `)
- `!d` → today’s date (e.g., `29 Jan 2026`)
- `!d+N` → today plus N days (e.g., `!d+3`)
- `!d-N` → today minus N days (e.g., `!d-2`)
- `!dN` → today plus N days (alias of `!d+N`)
- `!t` → current time (`HH:mm:ss`)

## Access Sharing

Share access by adding `.access.txt` files inside your `notes/` tree. The closest (deepest) `.access.txt` controls access for that subtree.

Example locations:
```
WIKI_REPO_PATH/<owner>/notes/.access.txt
WIKI_REPO_PATH/<owner>/notes/work/.access.txt
WIKI_REPO_PATH/<owner>/notes/work/demo/.access.txt
WIKI_REPO_PATH/<owner>/notes/hobby/.access.txt
```

Format:
```
public|protected|private|inherited   # optional first non-comment line (folder visibility)
alice:rw
bob:ro
```

Rules:
- The first non-empty, non-comment line can set folder visibility: `public`, `protected`, `private`, or `inherited`.
- Access values are `rw` (write) and `ro` (read).
- Folder visibility `inherited` follows the nearest parent folder visibility.
- Root folder default visibility is `private` when not explicitly defined.
- Other folders default to `inherited` when not explicitly defined.
- File frontmatter `visibility` defaults to `inherited`; inherited files use their folder visibility.
- `protected` means any authenticated user can read, while write still needs owner/rw access.
- If a file sets visibility to non-`inherited`, the file value overrides folder visibility.
- The deepest `.access.txt` still controls path-based `ro`/`rw` grants for that subtree.

## Settings

Open Settings from the launcher. You can switch the list view between compact and full. Admin users also see a User Management section.

Edit commands are configurable in Settings → Appearance. Each token is a single character:
- Trigger: prefix for all commands (default `!`).
- Todo token: trigger + token inserts checkbox (default `!` → `!!`).
- Today token: trigger + token inserts today (default `d` → `!d`).
- Date offset token: trigger + token + number inserts date with offset (default `d` → `!d+N`).
- Time token: trigger + token inserts current time (default `t` → `!t`).

Synchronization settings live here too. If the repo has git remotes, you can set a user and token per remote.

## Git Sync

- Open Settings → Synchronization to enter the git user/token for each remote.
- Leaving a token blank keeps the existing one; removing both user and token clears that entry.
- Credentials are saved per user to `WIKI_DATA_PATH/<username>.cred` in `.git-credentials` format.
- Token credentials apply to HTTPS remotes; SSH remotes use your local SSH keys.
- Sync runs one at a time; if another sync is active, the UI shows a "sync already in progress" message after a short wait.
- Run a manual sync from the launcher (Sync) or by visiting `/sync`.
- The server runs a built-in scheduler (`WIKI_GIT_SCHEDULE`, default `10m`) for all user repos. Set it to `0` to disable.

## Markdown Basics

### Headings
```
# Title
## Section
### Subsection
```

### Lists
```
- item
- item
  - nested
```

### Tasks
```
- [ ] Task not done
- [x] Task done
```

When you check a task, gwiki appends `done:YYYY-MM-DDTHH:mm:ss` to that line. When you uncheck it, `done:` is removed automatically.

### Due Dates
```
- [ ] Task due:@due(2026-01-20)
- [ ] Task due:2026-01-20
```

Due tokens render as badges. If a task is done, any due token on that line is hidden.

### Tags
```
#tag
#multi/part
#work!
```

- Tags are detected at the start of a line or after whitespace.
- `#work!` marks an exclusive tag (the note only appears when that tag is selected).

### Links
```
https://example.com
[label](https://example.com)
```

Inline URLs and standard markdown links both work.

## Embeds

Supported embeds include YouTube, TikTok, Instagram, Google Maps, and video attachments. Put a plain URL on its own line for the best preview.

## Tips and Tricks

- Use the quick launcher for fast navigation and actions.
- Keep task lines short; the badge rendering works best on one line.
