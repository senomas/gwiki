package web

import (
	"html/template"

	"gwiki/internal/index"
)

type ViewData struct {
	Title           string
	ContentTemplate string
	ContentHTML     template.HTML
	NotePath        string
	NoteTitle       string
	RawContent      string
	SaveAction      string
	ErrorMessage    string
	ErrorReturnURL  string
	RenderedHTML    template.HTML
	SearchQuery     string
	SearchResults   []index.SearchResult
	RecentNotes     []index.NoteSummary
	HomeNotes       []NoteCard
	HomeHasMore     bool
	NextHomeOffset  int
	Tags            []index.TagSummary
	UpdateDays      []index.UpdateDaySummary
	CalendarMonth   CalendarMonth
	OpenTasks       []index.TaskItem
	TagLinks        []TagLink
	ActiveTags      []string
	TagQuery        string
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
}
