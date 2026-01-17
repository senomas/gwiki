package web

import (
	"net/url"
	"strings"
	"time"

	"gwiki/internal/index"
)

type CalendarMonth struct {
	Label string
	Weeks []CalendarWeek
}

type CalendarWeek struct {
	Days []CalendarDay
}

type CalendarDay struct {
	Date        string
	Day         int
	InMonth     bool
	HasUpdates  bool
	UpdateCount int
	URL         string
	Active      bool
}

func buildCalendarMonth(now time.Time, updates []index.UpdateDaySummary, basePath string, tagQuery string, activeDate string, activeSearch string, folderQuery string) CalendarMonth {
	now = now.UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, -1)
	updateMap := map[string]int{}
	for _, update := range updates {
		updateMap[update.Day] = update.Count
	}

	offset := int(monthStart.Weekday())
	gridStart := monthStart.AddDate(0, 0, -offset)

	var weeks []CalendarWeek
	var days []CalendarDay
	for day := gridStart; ; day = day.AddDate(0, 0, 1) {
		dateKey := day.Format("2006-01-02")
		count := updateMap[dateKey]
		url := ""
		isActive := activeDate == dateKey && count > 0
		if count > 0 {
			url = buildDailyURL(dateKey, tagQuery, folderQuery)
		}
		days = append(days, CalendarDay{
			Date:        dateKey,
			Day:         day.Day(),
			InMonth:     day.Month() == monthStart.Month(),
			HasUpdates:  count > 0,
			UpdateCount: count,
			URL:         url,
			Active:      isActive,
		})

		if len(days) == 7 {
			weeks = append(weeks, CalendarWeek{Days: days})
			days = nil
			if !day.Before(monthEnd) && day.Weekday() == time.Saturday {
				break
			}
		}
	}

	return CalendarMonth{
		Label: monthStart.Format("January 2006"),
		Weeks: weeks,
	}
}

func buildDailyURL(date string, tagQuery string, folderQuery string) string {
	if date == "" {
		return "/"
	}
	params := make([]string, 0, 2)
	if tagQuery != "" {
		params = append(params, "t="+tagQuery)
	}
	if folderQuery != "" {
		params = append(params, "f="+url.QueryEscape(folderQuery))
	}
	target := "/daily/" + date
	if len(params) == 0 {
		return target
	}
	return target + "?" + strings.Join(params, "&")
}
