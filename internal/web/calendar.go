package web

import (
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
}

func buildCalendarMonth(now time.Time, updates []index.UpdateDaySummary) CalendarMonth {
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
		days = append(days, CalendarDay{
			Date:        dateKey,
			Day:         day.Day(),
			InMonth:     day.Month() == monthStart.Month(),
			HasUpdates:  count > 0,
			UpdateCount: count,
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
