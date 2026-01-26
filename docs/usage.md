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

Tip: on index/todo/due pages, navigation focuses note titles. On note pages it focuses note content links, checkboxes, and section toggles.

## Quick Launcher

- Open with `Ctrl+Space` or click your username (top right).
- Type to search actions, tags, folders, and notes (ordered: actions → tags → folders → notes).
- Use Arrow Up/Down and Enter to select.
- Selecting a note opens a submenu (Open/Edit/Delete). Enter activates the focused item.
- Tag and folder results toggle filters on the current page (they keep your existing query params).

## Groups

Create a group by adding a `.member.txt` file in a top-level folder under `WIKI_REPO_PATH`. The folder name becomes the group name.

`.member.txt` format:
```
alice:rw
bob:rw
charlie:ro
```

Valid access values are `rw` and `ro`. Users listed with `rw` can create and edit notes in that group; `ro` users can only view notes.

## Settings

Open Settings from the launcher. You can switch the list view between compact and full. Admin users also see a User Management section.

## Git Sync

- Each user can store git credentials in `WIKI_DATA_PATH/<username>.cred`.
- The file format matches `.git-credentials` so `git credential-store` can write to it.
- Sync runs one at a time; if another sync is active, the UI shows a "sync already in progress" message after a short wait.
- The server runs a built-in scheduler (`WIKI_GIT_SCHEDULE`, default `10m`) for all users and groups with repos. Set it to `0` to disable.

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
