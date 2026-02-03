# Developer Notes

This document is a compact map of Go files and their functions. It is intended for orientation, not exhaustive API documentation.

## `cmd/user/main.go`
CLI to list/add/remove users in the auth file.

- `main`: helper for main
- `usage`: helper for usage
- `listUsers`: helper for list users
- `addUser`: helper for add user
- `removeUser`: helper for remove user
- `authFilePath`: helper for auth file path
- `promptPassword`: helper for prompt password
- `promptYesNo`: helper for prompt yes no
- `userExists`: helper for user exists
- `readAuthFile`: helper for read auth file
- `writeAuthFile`: helper for write auth file
- `upsertAuthFile`: helper for upsert auth file

## `cmd/wiki/main.go`
Main entrypoint for the gwiki web server CLI.

- `main`: helper for main
- `parseLogLevel`: parses log level
- `selectLogWriter`: helper for select log writer

## `internal/auth/auth.go`
Authentication helpers and password verification.

- `HashPassword`: helper for hash password
- `ParseArgon2idHash`: parses argon2id hash
- `Verify`: helper for verify
- `LoadFile`: loads file

## Group membership discovery

Groups are discovered by scanning top-level folders under `WIKI_REPO_PATH` for a `.member.txt` file. The folder name becomes the group name; each line is `user:access` with access `ro` or `rw`.

## Quick launcher pipeline

Quick launcher entries are generated server-side and rendered immediately on page load (no network on open). When the user types, the client calls `GET /quick/launcher?q=...&uri=...` to fetch a unified list ordered as actions → tags → folders → notes. Actions are also filtered by the query, and the visible list is capped to 10 items (with a “+N more…” indicator).

Default actions render immediately when the launcher opens; context actions (e.g., Sync/Settings/Search/Broken/Scroll-to-top) appear once the query is non-empty. Context actions are injected directly below the default actions and can be further restricted later using the `uri` parameter (pattern matching on the current page). FTS note results only appear when the query length is 3+ characters.

Current action behavior by page context:
- Default actions (any page): New note, Home, Todo, Logout (when auth enabled).
- Unauthenticated: Login is the only visible action (Create note is hidden but kept for the launcher UI).
- Note view (`/notes/{path}` only): Edit and Delete appear as default actions when the user is authenticated.
- Note edit (`/notes/{path}/edit`) and other blocked note routes (`/preview`, `/save`, `/wikilink`, `/detail`, `/card`, `/collapsed`, `/backlinks`): Edit/Delete are not shown.
- Context actions (query length ≥ 1): Search, Sync, Settings, Broken links, Scroll to top. These are added just below default actions. Note results appear at 3+ characters.

Tag and folder results toggle filters on the current page by mutating only the `t` or `f` query params while preserving other params. Notes are searched via FTS (`Index.Search`) after 3+ characters. The `JOURNAL` tag is injected into results when it matches the query.

Key pieces:
- `internal/web/handlers.go`: `quickLauncherEntries`, `handleQuickLauncher`, and URL toggle helpers.
- `templates/quick_launcher_entries.html`: shared rendering fragment.
- `templates/base.html`: quick launcher UI + HTMX wiring (passes `uri`, enforces 10-item cap).
- `templates/quick_launcher.html`: quick launcher markup.

## Note edit actions launcher

The note edit launcher is a lightweight quick action menu scoped to the edit textarea. It is opened with `Ctrl+Space` while focused in the textarea and is independent of the global quick launcher.

Behavior:
- Default actions (no network): Todo, Date, Time.
- Dynamic actions (query ≥ 1): tags plus date shortcuts (Tomorrow, Next week, Next month).
- FTS notes (query ≥ 3): note matches returned by the index.
- Selecting a tag inserts `#tag` at the cursor. Selecting a note inserts `[[note-path]]`.
- The list is capped to 10 visible items to avoid overflow.

Key pieces:
- `internal/web/handlers.go`: `handleQuickEditActions`, `quickEditActionsEntries`.
- `internal/web/server.go`: `/quick/edit-actions` route.
- `templates/note-edit-actions.html`: edit launcher UI.
- `templates/note_edit_actions_entries.html`: dynamic entries (tags, actions, notes).

## Edit command settings

The edit textarea supports shorthand commands expanded on space. These are configurable per user via Settings and stored in `config.json`.

Config keys and defaults:
- `edit-command-trigger` (`!`): prefix for all commands.
- `edit-command-todo` (`!`): trigger + token inserts `- [ ] `.
- `edit-command-today` (`d`): trigger + token inserts today’s date.
- `edit-command-date-base` (`d`): trigger + token + number inserts date offset (supports `+N`, `-N`, or `N`).
- `edit-command-time` (`t`): trigger + token inserts current time (`HH:mm:ss`).

Implementation notes:
- Values are single characters and validated in `handleSettingsSave` via `validEditCommandToken`.
- The edit page passes settings as `data-cmd-*` attributes on the textarea; JS in `templates/edit.html` builds the command strings from these values.

## Home index sections

Home/index note feed is grouped into time/priority sections and rendered as collapsible blocks.

Current section order:
1. Important (`priority <= 5`)
2. Today
3. Planned (future updates)
4. This Week
5. This Month
6. This Year
7. Last Year
8. Others

Notes are assigned to exactly one section by `section_rank` in `Index.NoteList` (home mode), then sorted by `priority ASC, updated_at DESC` inside each section.

UI behavior:
- Section headers show `(<n> notes)` and are collapsible (`<details>` / `<summary>`).
- No extra icon/glyph is added for the collapsible UI.
- `Today` header is always shown (including `0 notes`).
- Other sections are hidden when empty.
- Headers are rendered only on the first home chunk (`offset=0`) so they do not repeat on paging.

Key pieces:
- `internal/index/index.go`: `NoteList` home section ranking.
- `internal/web/handlers.go`: `loadHomeNotes`, `splitHomeSections`, home/page handlers.
- `templates/home_notes.html`: section headers + collapsible rendering.

## Git sync and credentials

Sync runs through `internal/syncer` and is guarded by a process-wide lock so only one sync happens at a time (the caller waits up to ~10s). Each user can have their own git credentials file stored at `WIKI_DATA_PATH/<username>.cred` (same format as `.git-credentials`). Sync uses `GIT_CONFIG_GLOBAL` pointing at `WIKI_DATA_PATH/<username>.gitconfig`, and writes `credential.helper` to store credentials in that per-user `.cred` file.

The web server schedules background syncs using a ticker (configured by `WIKI_GIT_SCHEDULE`, default `10m`). It builds an owner list from users in the auth file plus group names, and syncs `WIKI_REPO_PATH/<owner>` when that folder has a `.git` directory. Each owner uses `<owner>.cred` and `<owner>.gitconfig` in `WIKI_DATA_PATH`. Scheduler logging emits every git command at info level and errors at error level.

## `internal/auth/auth_test.go`
Auth unit tests.

- `TestHashAndVerify`: test case for hash and verify
- `TestLoadFile`: test case for load file
- `TestLoadFileDuplicateUser`: test case for load file duplicate user

## `internal/config/config.go`
Config struct and defaults.

- `Load`: loads 
- `envOr`: helper for env or
- `parseDurationOr`: parses duration or
- `parseIntOr`: parses int or

## `internal/config/env.go`
Environment/.env config loading.

- `initEnvFile`: helper for init env file
- `ensureEnvFile`: ensures v file
- `randomSecret`: helper for random secret
- `loadEnvFile`: loads env file

## `internal/index/collapsed_sections.go`
Persisted collapsed section state.

- `SetCollapsedSections`: sets collapsed sections
- `CollapsedSections`: helper for collapsed sections
- `isSQLiteBusy`: predicate for sqlite busy

## `internal/index/context.go`
Context helpers for visibility filters.

- `WithPublicVisibility`: helper for with public visibility
- `publicOnly`: helper for public only

## `internal/index/embed_cache.go`
Embed cache storage.

- `GetEmbedCache`: helper for get embed cache
- `UpsertEmbedCache`: helper for upsert embed cache

## `internal/index/frontmatter.go`
Frontmatter parsing and update utilities.

- `EnsureFrontmatter`: ensures frontmatter
- `EnsureFrontmatterWithTitle`: ensures frontmatter with title
- `EnsureFrontmatterWithTitleAndUser`: ensures frontmatter with title and user
- `EnsureFrontmatterWithTitleAndUserNoUpdated`: ensures frontmatter with title and user no updated
- `ensureFrontmatterWithTitleAndUser`: ensures frontmatter with title and user
- `SetVisibility`: sets visibility
- `SetFolder`: sets folder
- `SetPriority`: sets priority
- `HasFrontmatter`: helper for has frontmatter
- `FrontmatterBlock`: helper for frontmatter block
- `splitFrontmatterLines`: helper for split frontmatter lines
- `parseFrontmatterLine`: parses frontmatter line
- `valueOrEmpty`: helper for value or empty
- `setFrontmatterLine`: sets frontmatter line
- `removeFrontmatterLine`: helper for remove frontmatter line
- `DeriveTitleFromBody`: helper for derive title from body
- `ParseHistoryEntries`: parses history entries
- `LatestHistoryTime`: helper for latest history time
- `FrontmatterAttributes`: helper for frontmatter attributes
- `parseFrontmatterTime`: parses frontmatter time
- `countHistoryEntries`: counts history entries
- `addHistoryEntry`: helper for add history entry
- `upsertHistoryEntry`: helper for upsert history entry
- `trimHistoryEntries`: helper for trim history entries
- `isIndentedLine`: predicate for ndented line
- `insertLines`: helper for insert lines
- `removeRange`: helper for remove range

## `internal/index/frontmatter_test.go`
Frontmatter unit tests.

- `TestEnsureFrontmatterAddsFields`: test case for ensure frontmatter adds fields
- `TestEnsureFrontmatterPreservesIDAndCreated`: test case for ensure frontmatter preserves idand created
- `TestEnsureFrontmatterNoUpdated`: test case for ensure frontmatter no updated
- `TestEnsureFrontmatterHistoryMax`: test case for ensure frontmatter history max
- `TestEnsureFrontmatterHistoryMergeWindow`: test case for ensure frontmatter history merge window
- `fmLineMap`: helper for fm line map

## `internal/index/index.go`
SQLite index implementation (notes, tags, tasks, links, history).

- `dateToDay`: helper for date to day
- `isJournalPath`: predicate for journal path
- `journalEndOfDayForPath`: helper for journal end of day for path
- `applyVisibilityFilter`: helper for apply visibility filter
- `applyFolderFilter`: helper for apply folder filter
- `folderWhere`: helper for folder where
- `slugify`: helper for slugify
- `Open`: opens 
- `Close`: helper for close
- `RemoveNoteByPath`: helper for remove note by path
- `Init`: helper for init
- `schemaVersion`: helper for schema version
- `setSchemaVersion`: sets chema version
- `RebuildFromFS`: helper for rebuild from fs
- `RecheckFromFS`: helper for recheck from fs
- `IndexNote`: helper for index note
- `IndexNoteIfChanged`: helper for index note if changed
- `RecentNotes`: helper for recent notes
- `RecentNotesPage`: helper for recent notes page
- `NoteList`: helper for note list
- `OpenTasks`: opens tasks
- `OpenTasksByDate`: opens tasks by date
- `TaskCountFilter`: task count filter struct
- `CountTasks`: counts tasks with filters
- `NotesWithOpenTasks`: helper for notes with open tasks
- `NotesWithDueTasks`: helper for notes with due tasks
- `NotesWithOpenTasksByDate`: helper for notes with open tasks by date
- `NotesWithDueTasksByDate`: helper for notes with due tasks by date
- `Search`: helper for search
- `ListTags`: lists tags
- `ListTagsFiltered`: lists tags filtered
- `ListTagsFilteredByDate`: lists tags filtered by date
- `ListTagsWithOpenTasks`: lists tags with open tasks
- `ListTagsWithOpenTasksByDate`: lists tags with open tasks by date
- `ListTagsWithDueTasks`: lists tags with due tasks
- `ListTagsWithDueTasksByDate`: lists tags with due tasks by date
- `ListFolders`: lists folders
- `ListUpdateDays`: lists update days
- `CountNotesWithOpenTasks`: counts notes with open tasks
- `NoteSummaryByPath`: helper for note summary by path
- `JournalNoteByDate`: helper for journal note by date
- `NotesWithHistoryOnDate`: helper for notes with history on date
- `JournalDates`: helper for journal dates
- `CountNotesWithOpenTasksByDate`: counts notes with open tasks by date
- `CountNotesWithDueTasks`: counts notes with due tasks
- `CountNotesWithDueTasksByDate`: counts notes with due tasks by date
- `Backlinks`: helper for backlinks
- `BrokenLinks`: helper for broken links
- `backlinkCandidates`: helper for backlink candidates
- `loadFileRecords`: loads file records
- `removeMissingRecords`: helper for remove missing records
- `nullIfEmpty`: helper for null if empty
- `nullIfZero`: helper for null if zero
- `NoteExists`: helper for note exists
- `resolveLinkTargetID`: helper for resolve link target id
- `CountJournalNotes`: helper for count journal notes
- `FileIDByPath`: helper for file idby path
- `PathByFileID`: helper for path by file id
- `PathByUID`: helper for path by uid
- `PathTitleByUID`: helper for path title by uid
- `PathByTitleNewest`: helper for path by title newest
- `DumpNoteList`: helper for dump note list
- `DebugDump`: helper for debug dump

## `internal/index/index_visibility_test.go`
Visibility indexing tests.

- `TestPublicVisibilityFilter`: test case for public visibility filter

## `internal/index/parse.go`
Markdown parsing to metadata (tags, links, tasks).

- `ParseContent`: parses content
- `UncheckedTasksSnippet`: builds markdown snippet with unchecked tasks
- `DueTasksSnippet`: builds markdown snippet with due tasks
- `FilterCompletedTasksSnippet`: removes completed task blocks for index cards, returns completed count, and preserves original task line numbers for checkbox IDs
- `TaskLineHash`: helper for task line hash
- `countIndentSpaces`: helper for count indent spaces
- `expandTagPrefixes`: helper for expand tag prefixes
- `splitTagParts`: helper for split tag parts
- `StripFrontmatter`: helper for strip frontmatter
- `splitFrontmatter`: helper for split frontmatter
- `parseFrontmatter`: parses frontmatter
- `parseTitle`: parses title
- `parseTagsFromFrontmatter`: parses tags from frontmatter
- `parsePriority`: parses iority

## `internal/index/parse_test.go`
Parser unit tests.

- `TestParseContent`: test case for parse content
- `TestStripFrontmatter`: test case for strip frontmatter
- `TestUncheckedTasksSnippet`: test case for unchecked tasks snippet
- `TestDueTasksSnippet`: test case for due tasks snippet

## `internal/index/schema.go`
Database schema definition and version.

- (no functions)

## `internal/storage/fs/atomic.go`
Atomic file write helper.

- `WriteFileAtomic`: helper for write file atomic

## `internal/storage/fs/atomic_test.go`
Atomic write tests.

- `TestWriteFileAtomic`: test case for write file atomic

## `internal/storage/fs/locker.go`
In-memory path lock.

- `NewLocker`: constructs locker
- `Lock`: helper for lock

## `internal/storage/fs/path.go`
Path normalization helpers.

- `NormalizeNotePath`: helper for normalize note path
- `NoteFilePath`: helper for note file path
- `EnsureMDExt`: ensures mdext

## `internal/storage/fs/path_test.go`
Path helper tests.

- `TestNormalizeNotePath`: test case for normalize note path

## `internal/web/attachment_test.go`
Attachment handling tests.

- `TestAttachmentAccessByNoteID`: test case for attachment access by note id
- `TestRenderVideoAttachmentEmbed`: test case for render video attachment embed
- `TestAttachmentAndAssetAccessControl`: test case for attachment and asset access control

## `internal/web/auth.go`
Web auth middleware helpers.

- `newAuth`: helper for new auth
- `Middleware`: helper for middleware
- `verify`: helper for verify
- `Authenticate`: helper for authenticate
- `CreateToken`: helper for create token
- `tokenUser`: helper for token user
- `authSecret`: helper for auth secret
- `signJWT`: helper for sign jwt
- `parseJWT`: parses jwt
- `hmacSHA256`: helper for hmac sha256

## `internal/web/calendar.go`
Calendar model and URL builder.

- `buildCalendarMonth`: builds calendar month
- `buildDailyURL`: builds daily url

## `internal/web/context.go`
Web context helpers.

- `WithUser`: helper for with user
- `CurrentUser`: helper for current user
- `IsAuthenticated`: predicate for authenticated

## `internal/web/embed_test.go`
Embed rendering tests.

- `TestRenderMarkdownEmbeds`: test case for render markdown embeds
- `TestRenderMarkdownCollapsedSections`: test case for render markdown collapsed sections

## `internal/web/handlers.go`
HTTP handlers, markdown rendering, embeds, and UI helpers.

- `quickLauncherEntries`: builds quick launcher results
- `handleQuickLauncher`: HTMX endpoint for quick launcher search
- Index card rendering (`/notes/{path}/card`) hides completed task blocks and adds a completed-task summary footer; full note view (`/notes/{path}`) is unchanged.
- `Extend`: helper for extend
- `Transform`: helper for transform
- `shouldOpenNewTab`: helper for should open new tab
- `attachViewData`: helper for attach view data
- `buildJournalIndex`: builds journal index
- `buildJournalSidebar`: builds journal sidebar
- `buildJournalFilterQuery`: builds journal filter query
- `historyUser`: helper for history user
- `withCollapsibleSectionState`: helper for with collapsible section state
- `collapsibleSectionStateFromContext`: helper for collapsible section state from context
- `collapsedSectionState`: helper for collapsed section state
- `collapsedSectionStateFromSections`: helper for collapsed section state from sections
- `requireAuth`: helper for require auth
- `normalizeLineEndings`: helper for normalize line endings
- `normalizeFolderPath`: helper for normalize folder path
- `isJournalNotePath`: predicate for journal note path
- `listAttachmentNames`: lists attachment names
- `attachmentsRoot`: helper for attachments root
- `tempAttachmentsDir`: helper for temp attachments dir
- `noteAttachmentsDir`: helper for note attachments dir
- `assetsRoot`: helper for assets root
- `parseTagsParam`: parses tags param
- `parseFolderParam`: parses folder param
- `parseDateParam`: parses date param
- `splitSpecialTags`: helper for split special tags
- `taskCheckboxID`: helper for task checkbox id
- `taskCheckboxHTML`: helper for task checkbox html
- `parseTaskID`: parses task id
- `decorateTaskCheckboxes`: helper for decorate task checkboxes
- `buildTagLinks`: builds tag links
- `buildTagsQuery`: builds tags query
- `buildDateQuery`: builds date query
- `buildSearchQuery`: builds search query
- `buildTagsURL`: builds tags url
- `buildFolderQuery`: builds folder query
- `buildFolderURL`: builds folder url
- `buildFilterQuery`: builds filter query
- `folderOptions`: helper for folder options
- `buildFolderTree`: builds folder tree
- `loadSpecialTagCounts`: loads special tag counts
- `loadFilteredTags`: loads filtered tags
- `applyRenderReplacements`: applies render replacements
- `replaceDueTokens`: replaces due tokens with formatted badges
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Extend`: helper for extend
- `Transform`: helper for transform
- `headingPlainText`: helper for heading plain text
- `headingLineInfo`: helper for heading line info
- `newCollapsibleSectionHTMLRenderer`: helper for new collapsible section htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderCollapsibleSection`: renders collapsible section
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Extend`: helper for extend
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Extend`: helper for extend
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Extend`: helper for extend
- `Kind`: helper for kind
- `Dump`: helper for dump
- `Extend`: helper for extend
- `Extend`: helper for extend
- `Transform`: helper for transform
- `Transform`: helper for transform
- `Transform`: helper for transform
- `Transform`: helper for transform
- `Transform`: helper for transform
- `paragraphHasOnlyLink`: helper for paragraph has only link
- `textMatchesURL`: helper for text matches url
- `paragraphOnlyURL`: helper for paragraph only url
- `paragraphOnlyLink`: helper for paragraph only link
- `extractTextFromNode`: helper for extract text from node
- `newMapsEmbedHTMLRenderer`: helper for new maps embed htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderMapsEmbed`: renders maps embed
- `newYouTubeEmbedHTMLRenderer`: helper for new you tube embed htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderYouTubeEmbed`: renders you tube embed
- `newTikTokEmbedHTMLRenderer`: helper for new tik tok embed htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderTikTokEmbed`: renders tik tok embed
- `newInstagramEmbedHTMLRenderer`: helper for new instagram embed htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderInstagramEmbed`: renders instagram embed
- `newAttachmentVideoEmbedHTMLRenderer`: helper for new attachment video embed htmlrenderer
- `RegisterFuncs`: helper for register funcs
- `renderAttachmentVideoEmbed`: renders attachment video embed
- `isMapsAppShortLink`: predicate for maps app short link
- `mapsEmbedContext`: helper for maps embed context
- `youtubeEmbedContext`: helper for youtube embed context
- `tiktokEmbedContext`: helper for tiktok embed context
- `instagramEmbedContext`: helper for instagram embed context
- `attachmentVideoEmbedContext`: helper for attachment video embed context
- `isYouTubeURL`: predicate for you tube url
- `isTikTokURL`: predicate for tik tok url
- `isInstagramURL`: predicate for nstagram url
- `attachmentVideoFromURL`: helper for attachment video from url
- `youtubeVideoID`: helper for youtube video id
- `lookupTikTokEmbed`: helper for lookup tik tok embed
- `lookupInstagramEmbed`: helper for lookup instagram embed
- `lookupYouTubeEmbed`: helper for lookup you tube embed
- `resolveTikTokEmbedNow`: resolves tik tok embed now
- `resolveTikTokEmbedAsync`: resolves tik tok embed async
- `resolveTikTokEmbedWithClient`: resolves tik tok embed with client
- `resolveInstagramEmbedNow`: resolves instagram embed now
- `resolveInstagramEmbedAsync`: resolves instagram embed async
- `resolveInstagramEmbedWithClient`: resolves instagram embed with client
- `resolveYouTubeEmbedNow`: resolves you tube embed now
- `resolveYouTubeEmbedAsync`: resolves you tube embed async
- `resolveYouTubeEmbedWithClient`: resolves you tube embed with client
- `tiktokEmbedIsInFlight`: helper for tiktok embed is in flight
- `tiktokEmbedMarkInFlight`: helper for tiktok embed mark in flight
- `tiktokEmbedClearInFlight`: helper for tiktok embed clear in flight
- `tiktokEmbedStoreFound`: helper for tiktok embed store found
- `tiktokEmbedStoreFailure`: helper for tiktok embed store failure
- `instagramEmbedIsInFlight`: helper for instagram embed is in flight
- `instagramEmbedMarkInFlight`: helper for instagram embed mark in flight
- `instagramEmbedClearInFlight`: helper for instagram embed clear in flight
- `instagramEmbedStoreFound`: helper for instagram embed store found
- `instagramEmbedStoreFailure`: helper for instagram embed store failure
- `youtubeEmbedIsInFlight`: helper for youtube embed is in flight
- `youtubeEmbedMarkInFlight`: helper for youtube embed mark in flight
- `youtubeEmbedClearInFlight`: helper for youtube embed clear in flight
- `youtubeEmbedStoreFound`: helper for youtube embed store found
- `youtubeEmbedStoreFailure`: helper for youtube embed store failure
- `lookupMapsEmbed`: helper for lookup maps embed
- `resolveMapsEmbedNow`: resolves maps embed now
- `resolveMapsEmbedAsync`: resolves maps embed async
- `resolveMapsEmbedWithClient`: resolves maps embed with client
- `mapsEmbedIsInFlight`: helper for maps embed is in flight
- `mapsEmbedMarkInFlight`: helper for maps embed mark in flight
- `mapsEmbedClearInFlight`: helper for maps embed clear in flight
- `mapsEmbedStoreFound`: helper for maps embed store found
- `mapsEmbedStoreFailure`: helper for maps embed store failure
- `newTTLCache`: helper for new ttlcache
- `IsActive`: predicate for active
- `Upsert`: helper for upsert
- `Delete`: helper for delete
- `evictOldest`: helper for evict oldest
- `buildMapsEmbedURL`: builds maps embed url
- `mapsEmbedQueryURL`: helper for maps embed query url
- `handleHome`: HTTP handler for home
- `handleDaily`: HTTP handler for daily
- `handleLogin`: HTTP handler for login
- `handleLogout`: HTTP handler for logout
- `handleSearch`: HTTP handler for search
- `handleTagSuggest`: HTTP handler for tag suggest
- `handleJournalYear`: HTTP handler for journal year
- `handleJournalMonth`: HTTP handler for journal month
- `handleHomeNotesPage`: HTTP handler for home notes page
- `handleTasks`: HTTP handler for tasks
- `handleTodo`: HTTP handler for todo
- `handleToggleTask`: HTTP handler for toggle task
- `loadHomeNotes`: loads home notes
- `handleNewNote`: HTTP handler for new note
- `handleNotes`: HTTP handler for notes
- `handleViewNote`: HTTP handler for view note
- `handleNoteDetailFragment`: HTTP handler for note detail fragment
- `handleNoteCardFragment`: HTTP handler for note card fragment
- `buildNoteCard`: builds note card
- `buildNoteViewData`: builds note view data
- `buildNoteCardData`: builds note card data
- `resolveNotePath`: resolves note path
- `handleEditNote`: HTTP handler for edit note
- `handleDeleteNote`: HTTP handler for delete note
- `handleUploadAttachment`: HTTP handler for upload attachment
- `handleUploadTempAttachment`: HTTP handler for upload temp attachment
- `handleDeleteTempAttachment`: HTTP handler for delete temp attachment
- `handleDeleteAttachment`: HTTP handler for delete attachment
- `handleAttachmentFile`: HTTP handler for attachment file
- `handleAssetFile`: HTTP handler for asset file
- `firstPathSegment`: helper for first path segment
- `noteIDAccessible`: helper for note idaccessible
- `ensureVideoThumbnail`: ensures video thumbnail
- `generateVideoThumbnail`: helper for generate video thumbnail
- `promoteTempAttachments`: helper for promote temp attachments
- `handleSaveNote`: HTTP handler for save note
- `handleCollapsedSections`: HTTP handler for collapsed sections
- `renderEditError`: renders edit error
- `handlePreview`: HTTP handler for preview
- `renderMarkdown`: renders markdown
- `renderNoteBody`: renders note body
- `renderLineMarkdown`: renders line markdown
- `expandWikiLinks`: helper for expand wiki links
- `stripFirstHeading`: helper for strip first heading
- `resolveWikiLink`: resolves wiki link
- `slugify`: helper for slugify
- `uniqueNotePath`: helper for unique note path
- `isHTMX`: predicate for htmx
- `sanitizeReturnURL`: helper for sanitize return url

## `internal/web/integration_test.go`
Web integration tests.

- `TestIntegrationFlow`: test case for integration flow
- `TestCollapsedSectionsRenderFromStore`: test case for collapsed sections render from store
- `detailsTagForLine`: helper for details tag for line

## `internal/web/log_test.go`
Logging configuration tests.

- `TestMain`: test case for main
- `setupTestLogger`: sets up test logger
- `selectTestLogWriter`: helper for select test log writer

## `internal/web/server.go`
HTTP server wiring and routes.

- `NewServer`: constructs server
- `Handler`: helper for handler
- `routes`: helper for routes

## `internal/web/templates.go`
HTML template parsing and rendering.

- `MustParseTemplates`: helper for must parse templates
- `resolveTemplateGlob`: resolves template glob
- `RenderPage`: renders page
- `RenderTemplate`: renders template

## `internal/web/types.go`
View models and UI types.

- `QuickLauncherEntry`: quick launcher item model

## UI E2E tests (Playwright Go)

E2E tests run in Docker using the Playwright image (browsers bundled). The test runner installs Go and the Playwright driver inside the container.

- `make e2e` starts a separate gwiki container on port `8082` and runs `go test` in `tests/e2e`.
- Base URL is configured via `E2E_BASE_URL` (default `http://gwiki-e2e:8080` inside Docker).

Smoke test checks the home page, sidebar, and calendar rendering.
