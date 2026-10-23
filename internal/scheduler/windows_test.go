package scheduler

import (
	"testing"
	"time"
)

func TestWindowBoundariesAndOvernight(t *testing.T) {
	for _, tc := range []struct {
		at, start, end, zone string
		days                 []int
		allowed              bool
		deadline             string
	}{
		{"2026-10-16T09:00:00+08:00", "09:00", "18:00", "Asia/Shanghai", []int{5}, true, "2026-10-16T18:00:00+08:00"},
		{"2026-10-16T18:00:00+08:00", "09:00", "18:00", "Asia/Shanghai", []int{5}, false, ""},
		{"2026-10-17T01:00:00+08:00", "23:00", "05:00", "Asia/Shanghai", []int{5}, true, "2026-10-17T05:00:00+08:00"},
		{"2026-10-17T05:00:00+08:00", "23:00", "05:00", "Asia/Shanghai", []int{5}, false, ""},
		{"2026-10-18T01:00:00+08:00", "23:00", "05:00", "Asia/Shanghai", []int{5}, false, ""},
		{"2026-10-16T23:59:59Z", "00:00", "24:00", "UTC", []int{5}, true, "2026-10-17T00:00:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, tc.at)
		end, allowed, err := AllowedUntil([]Window{{Weekdays: tc.days, Start: tc.start, End: tc.end, TimeZone: tc.zone}}, now)
		if err != nil || allowed != tc.allowed {
			t.Fatalf("%s allowed=%v err=%v", tc.at, allowed, err)
		}
		if allowed {
			want, _ := time.Parse(time.RFC3339, tc.deadline)
			if !end.Equal(want) {
				t.Fatalf("deadline %v want %v", end, want)
			}
		}
	}
	for _, window := range []Window{
		{Weekdays: []int{1}, Start: "09:00", End: "09:00", TimeZone: "UTC"},
		{Weekdays: []int{1, 1}, Start: "09:00", End: "10:00", TimeZone: "UTC"},
		{Weekdays: []int{7}, Start: "09:00", End: "10:00", TimeZone: "UTC"},
		{Weekdays: []int{1}, Start: "09:00", End: "10:00", TimeZone: "Invalid/Zone"},
	} {
		if _, ok, err := AllowedUntil([]Window{window}, time.Now()); err == nil || ok {
			t.Fatalf("invalid window allowed: %+v", window)
		}
	}
}

func TestAllowedUntilWithoutWindowAllowsLongScans(t *testing.T) {
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	end, allowed, err := AllowedUntil(nil, now)
	if err != nil || !allowed {
		t.Fatalf("no window must always allow: allowed=%v err=%v", allowed, err)
	}
	if got := end.Sub(now); got != MaxTaskDuration || got < 2*time.Hour {
		t.Fatalf("hard deadline without a window = %s, want the generous max run time", got)
	}
}
