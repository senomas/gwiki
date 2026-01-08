package web

import (
	"html/template"

	"gwiki/internal/index"
)

type ViewData struct {
	Title            string
	ContentTemplate  string
	ContentHTML      template.HTML
	NotePath         string
	NoteTitle        string
	RawContent       string
	FrontmatterBlock string
	SaveAction       string
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
	TagLinks         []TagLink
	ActiveTags       []string
	TagQuery         string
	ActiveDate       string
	DateQuery        string
	Backlinks        []BacklinkView
	SearchQueryParam string
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

type NoteCard struct {
	Path         string
	Title        string
	RenderedHTML template.HTML
	UpdatedLabel string
	Meta         index.FrontmatterAttrs
}
