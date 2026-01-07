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
	RenderedHTML    template.HTML
	SearchQuery     string
	SearchResults   []index.SearchResult
	RecentNotes     []index.NoteSummary
	Tags            []index.TagSummary
	UpdateDays      []index.UpdateDaySummary
	CalendarMonth   CalendarMonth
}
