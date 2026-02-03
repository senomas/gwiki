package web

import (
	"net/url"
	"time"

	"gwiki/internal/index"
)

type CalendarMonth struct {
	Label        string
	PrevMonth    string
	NextMonth    string
	CurrentMonth string
	IsCurrent    bool
	Weeks        []CalendarWeek
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
	Today       bool
}

func buildCalendarMonth(now time.Time, updates []index.UpdateDaySummary, baseURL string, activeDate string) CalendarMonth {
	now = now.In(time.Local)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	monthEnd := monthStart.AddDate(0, 1, -1)
	current := time.Now().In(now.Location())
	currentMonthKey := current.Format("2006-01")
	todayKey := current.Format("2006-01-02")
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
			url = buildDailyURL(baseURL, dateKey)
		}
		days = append(days, CalendarDay{
			Date:        dateKey,
			Day:         day.Day(),
			InMonth:     day.Month() == monthStart.Month(),
			HasUpdates:  count > 0,
			UpdateCount: count,
			URL:         url,
			Active:      isActive,
			Today:       dateKey == todayKey,
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
		Label:        monthStart.Format("January 2006"),
		PrevMonth:    monthStart.AddDate(0, -1, 0).Format("2006-01"),
		NextMonth:    monthStart.AddDate(0, 1, 0).Format("2006-01"),
		CurrentMonth: currentMonthKey,
		IsCurrent:    monthStart.Format("2006-01") == currentMonthKey,
		Weeks:        weeks,
	}
}

func buildDailyURL(baseURL string, date string) string {
	if date == "" {
		return "/"
	}
	u, err := url.Parse(baseURL)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	u.Path = "/daily/" + date
	u.RawPath = ""
	return u.String()
}
