package web

import (
	"html/template"
	"time"

	"gwiki/internal/index"
)

type ViewData struct {
	Title                  string
	ContentTemplate        string
	ContentHTML            template.HTML
	AuthEnabled            bool
	IsAuthenticated        bool
	IsAdmin                bool
	CurrentUser            User
	NotePath               string
	DevNotePath            string
	DevNoteBlocks          []index.NoteBlock
	DevTagQuery            string
	DevTagNotes            []DevTagNote
	NoteTitle              string
	NoteFileName           string
	RawContent             string
	FrontmatterBlock       string
	SaveAction             string
	UploadToken            string
	ErrorMessage           string
	ErrorReturnURL         string
	RenamePrompt           bool
	RenameFromPath         string
	RenameToPath           string
	DuplicateNotePrompt    bool
	DuplicateFromPath      string
	DuplicateFolder        string
	DuplicateFilename      string
	DuplicateBody          string
	RenderedHTML           template.HTML
	SearchQuery            string
	NoteMeta               index.FrontmatterAttrs
	NoteVisibilityDisplay  string
	NoteHash               string
	NoteEtagTime           int64
	SearchResults          []index.SearchResult
	SearchTagsOnly         bool
	SearchTagResults       []TagLink
	RecentNotes            []index.NoteSummary
	HomeNotes              []NoteCard
	HomePriorityNotes      []NoteCard
	HomeTodayNotes         []NoteCard
	HomePlannedNotes       []NoteCard
	HomePlannedHasMore     bool
	HomePlannedNextOffset  int
	HomeWeekNotes          []NoteCard
	HomeWeekHasMore        bool
	HomeWeekNextOffset     int
	HomeMonthNotes         []NoteCard
	HomeMonthHasMore       bool
	HomeMonthNextOffset    int
	HomeYearNotes          []NoteCard
	HomeYearHasMore        bool
	HomeYearNextOffset     int
	HomeLastYearNotes      []NoteCard
	HomeLastYearHasMore    bool
	HomeLastYearNextOffset int
	HomeOtherNotes         []NoteCard
	HomeOtherHasMore       bool
	HomeOtherNextOffset    int
	HomeHasMore            bool
	NextHomeOffset         int
	HomeOffset             int
	HomeOwner              string
	Tags                   []index.TagSummary
	UpdateDays             []index.UpdateDaySummary
	CalendarMonth          CalendarMonth
	CalendarPrevURL        string
	CalendarNextURL        string
	CalendarTodayURL       string
	OpenTasks              []index.TaskItem
	TodoTasks              []TaskView
	TodoNotes              []NoteCard
	TodoHasMore            bool
	TodoNextOffset         int
	TodoOffset             int
	TodoCount              int
	DueCount               int
	TagLinks               []TagLink
	ActiveTags             []string
	TagQuery               string
	ActiveDate             string
	DateQuery              string
	Backlinks              []BacklinkView
	NoteGitHistory         []NoteGitHistoryEntry
	NoteGitHistoryError    string
	SearchQueryParam       string
	Attachments            []string
	AttachmentGroups       []AttachmentGroup
	AttachmentBase         string
	FolderTree             []FolderNode
	ActiveFolder           string
	FolderQuery            string
	FilterQuery            string
	TodoURL                string
	InboxURL               string
	InboxCount             int
	RawQuery               string
	HomeURL                string
	NoteURL                string
	ReturnURL              string
	FolderOptions          []string
	FolderOptionsByOwner   map[string][]string
	FolderLabel            string
	OwnerOptions           []OwnerOption
	SelectedOwner          string
	TagSuggestions         []string
	TagSuggestionsByOwner  map[string][]string
	SuggestPrefix          string
	DailyDate              string
	DailyJournal           *NoteCard
	DailyNotes             []NoteCard
	JournalSidebar         JournalSidebar
	JournalYear            JournalYearNode
	JournalMonth           JournalMonthNode
	HiddenBlocks           []HiddenRenderBlock
	HiddenCount            int
	ShowHiding             bool
	DueByPath              map[string]string
	CompletedTaskCount     int
	ShowCompletedSummary   bool
	RebuildScanned         int
	RebuildUpdated         int
	RebuildCleaned         int
	RebuildDuration        string
	RebuildError           string
	SyncOutput             string
	SyncError              string
	SyncDuration           string
	SyncPending            bool
	SyncOwner              string
	BrokenLinks            []BrokenLinkGroup
	BuildVersion           string
	EditCommandTrigger     string
	EditCommandTodo        string
	EditCommandToday       string
	EditCommandTime        string
	EditCommandDateBase    string
	ToastItems             []Toast
	SettingsUsers          []UserSummary
	QuickEntries           []QuickLauncherEntry
	GitRemoteCreds         []GitRemoteCred
	Users                  []UserLink
}

type AttachmentGroup struct {
	Label string
	Items []AttachmentListItem
}

type AttachmentListItem struct {
	Name      string
	DateLabel string
}

type OwnerOption struct {
	Name  string
	Label string
}

type UserLink struct {
	Name            string
	Count           int
	LastCommitAt    string
	LastSuccessSync string
}

type QuickLauncherEntry struct {
	ID        string
	Kind      string
	Label     string
	Hint      string
	Icon      string
	Href      string
	Action    string
	Tag       string
	NotePath  string
	NoteTitle string
	Hidden    bool
}

type UserSummary struct {
	Name            string
	Roles           []string
	GitOrigin       string
	LastSync        string
	LastSuccessSync string
	LastSyncStatus  string
}

type GitRemoteCred struct {
	Alias    string
	URL      string
	Host     string
	User     string
	HasToken bool
}

type BacklinkView struct {
	FromPath  string
	FromTitle string
	LineNo    int
	LineHTML  template.HTML
}

type DevTagNote struct {
	NotePath              string
	NoteTitle             string
	NoteURL               string
	NoteMeta              index.FrontmatterAttrs
	NoteVisibilityDisplay string
	FolderLabel           string
	SelectedLines         []int
	SelectedMarkdown      string
	SelectedHTML          template.HTML
}

type DevTagBlock struct {
	BlockID   int
	ParentID  int
	Level     int
	StartLine int
	EndLine   int
	Kind      string
	Markdown  string
}

type NoteGitHistoryEntry struct {
	CommitUnix int64
	CommitAt   time.Time
	ShortHash  string
}

type BrokenLinkGroup struct {
	Ref   string
	Items []BrokenLinkItem
}

type BrokenLinkItem struct {
	FromPath  string
	FromTitle string
	LineNo    int
	LineHTML  template.HTML
}

type TagLink struct {
	Name     string
	Count    int
	URL      string
	Active   bool
	Disabled bool
}

type TaskView struct {
	CheckboxHTML template.HTML
	TextHTML     template.HTML
	RenderedHTML template.HTML
	Path         string
	LineNo       int
	Title        string
	DueDate      string
	UpdatedAt    string
}

type FolderLink struct {
	Name   string
	Path   string
	URL    string
	Active bool
	Depth  int
}

type FolderNode struct {
	Name     string
	Path     string
	URL      string
	Active   bool
	Children []FolderNode
}

type NoteCard struct {
	Path         string
	Title        string
	FileName     string
	RenderedHTML template.HTML
	Meta         index.FrontmatterAttrs
	FolderLabel  string
	SectionRank  int
}

type HiddenRenderBlock struct {
	StartLine    int
	EndLine      int
	Kind         string
	RenderedHTML template.HTML
}

type JournalDay struct {
	Label string
	Date  string
	URL   string
}

type JournalMonthNode struct {
	Label    string
	Year     int
	Month    int
	Expanded bool
	Days     []JournalDay
}

type JournalYearNode struct {
	Label    string
	Year     int
	Expanded bool
	Months   []JournalMonthNode
}

type JournalSidebar struct {
	Years []JournalYearNode
}
