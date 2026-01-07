package web

import (
	"html/template"

	"gwiki/internal/index"
)

type ViewData struct {
	Title              string
	ContentTemplate    string
	ContentHTML        template.HTML
	NotePath           string
	NoteTitle          string
	RawContent         string
	RenderedHTML       template.HTML
	SearchQuery        string
	SearchResults      []index.SearchResult
	Tags               []index.TagSummary
	UpdateDays         []index.UpdateDaySummary
	CalendarMonth      CalendarMonth
	NoteFeed           []NoteFeedItem
	NoteFeedHasMore    bool
	NoteFeedNextOffset int
}

type NoteFeedItem struct {
	Path         string
	Title        string
	RenderedHTML template.HTML
}
