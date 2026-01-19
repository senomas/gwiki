package web

import (
	"html/template"

	"gwiki/internal/index"
)

type ViewData struct {
	Title            string
	ContentTemplate  string
	ContentHTML      template.HTML
	AuthEnabled      bool
	IsAuthenticated  bool
	CurrentUser      User
	NotePath         string
	NoteTitle        string
	NoteFileName     string
	RawContent       string
	FrontmatterBlock string
	SaveAction       string
	UploadToken      string
	ErrorMessage     string
	ErrorReturnURL   string
	RenamePrompt     bool
	RenameFromPath   string
	RenameToPath     string
	RenderedHTML     template.HTML
	SearchQuery      string
	NoteMeta         index.FrontmatterAttrs
	SearchResults    []index.SearchResult
	RecentNotes      []index.NoteSummary
	HomeNotes        []NoteCard
	HomeHasMore      bool
	NextHomeOffset   int
	Tags             []index.TagSummary
	UpdateDays       []index.UpdateDaySummary
	CalendarMonth    CalendarMonth
	OpenTasks        []index.TaskItem
	TodoTasks        []TaskView
	TodoNotes        []NoteCard
	TodoCount        int
	DueCount         int
	TagLinks         []TagLink
	ActiveTags       []string
	TagQuery         string
	ActiveDate       string
	DateQuery        string
	Backlinks        []BacklinkView
	SearchQueryParam string
	Attachments      []string
	AttachmentBase   string
	FolderTree       []FolderNode
	ActiveFolder     string
	FolderQuery      string
	FilterQuery      string
	HomeURL          string
	NoteURL          string
	ReturnURL        string
	FolderOptions    []string
	TagSuggestions   []string
	DailyDate        string
	DailyJournal     *NoteCard
	DailyNotes       []NoteCard
	JournalSidebar   JournalSidebar
	JournalYear      JournalYearNode
	JournalMonth     JournalMonthNode
	DueByPath        map[string]string
}

type BacklinkView struct {
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
