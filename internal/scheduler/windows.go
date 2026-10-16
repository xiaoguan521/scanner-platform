package scheduler

import (
	"fmt"
	"time"
	_ "time/tzdata"
)

type Window struct {
	Weekdays []int  `json:"weekdays"`
	Start    string `json:"start"`
	End      string `json:"end"`
	TimeZone string `json:"timeZone"`
}

func minute(value string, end bool) (int, error) {
	if end && value == "24:00" {
		return 1440, nil
	}
	t, err := time.Parse("15:04", value)
	if err != nil || len(value) != 5 {
		return 0, fmt.Errorf("invalid window time")
	}
	return t.Hour()*60 + t.Minute(), nil
}

func ValidateWindows(windows []Window) error {
	if len(windows) > 8 {
		return fmt.Errorf("at most eight time windows")
	}
	for _, w := range windows {
		start, e1 := minute(w.Start, false)
		end, e2 := minute(w.End, true)
		if e1 != nil || e2 != nil || start == end || len(w.Weekdays) == 0 || len(w.Weekdays) > 7 || len(w.TimeZone) > 64 || w.TimeZone == "" {
			return fmt.Errorf("invalid time window")
		}
		if _, err := time.LoadLocation(w.TimeZone); err != nil {
			return fmt.Errorf("invalid time zone: %w", err)
		}
		seen := map[int]bool{}
		for _, d := range w.Weekdays {
			if d < 0 || d > 6 || seen[d] {
				return fmt.Errorf("invalid weekday")
			}
			seen[d] = true
		}
	}
	return nil
}

// AllowedUntil uses the starting weekday for overnight windows. The end is exclusive.
func AllowedUntil(windows []Window, now time.Time) (time.Time, bool, error) {
	if err := ValidateWindows(windows); err != nil {
		return time.Time{}, false, err
	}
	if len(windows) == 0 {
		return now.Add(15 * time.Minute), true, nil
	}
	var deadline time.Time
	for _, w := range windows {
		loc, _ := time.LoadLocation(w.TimeZone)
		local := now.In(loc)
		start, _ := minute(w.Start, false)
		end, _ := minute(w.End, true)
		for _, offset := range []int{-1, 0} {
			day := time.Date(local.Year(), local.Month(), local.Day()+offset, 0, 0, 0, 0, loc)
			matched := false
			for _, d := range w.Weekdays {
				matched = matched || d == int(day.Weekday())
			}
			if !matched {
				continue
			}
			from := time.Date(day.Year(), day.Month(), day.Day(), start/60, start%60, 0, 0, loc)
			endDay := day.Day()
			if end <= start {
				endDay++
			}
			to := time.Date(day.Year(), day.Month(), endDay, end/60, end%60, 0, 0, loc)
			if !now.Before(from) && now.Before(to) && to.After(deadline) {
				deadline = to
			}
		}
	}
	return deadline, !deadline.IsZero(), nil
}
