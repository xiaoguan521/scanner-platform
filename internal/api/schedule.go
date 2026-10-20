package api

import (
	"net/http"
	"strconv"
)

func parseScheduleRunPagination(r *http.Request) (int, int, error) {
	values := r.URL.Query()
	parse := func(name string, fallback, min, max int) (int, error) {
		items, ok := values[name]
		if !ok {
			return fallback, nil
		}
		if len(items) != 1 {
			return 0, errInvalidScheduleRunPagination
		}
		value, err := strconv.Atoi(items[0])
		if err != nil || value < min || value > max {
			return 0, errInvalidScheduleRunPagination
		}
		return value, nil
	}
	limit, err := parse("limit", 50, 1, 200)
	if err != nil {
		return 0, 0, err
	}
	offset, err := parse("offset", 0, 0, 100000)
	if err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

var errInvalidScheduleRunPagination = scheduleRunPaginationError{}

type scheduleRunPaginationError struct{}

func (scheduleRunPaginationError) Error() string { return "invalid schedule run pagination" }
