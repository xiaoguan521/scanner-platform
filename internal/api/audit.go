package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanner-platform/internal/repo"
)

func parseAuditLogQuery(r *http.Request) (repo.AuditLogQuery, error) {
	values := r.URL.Query()
	readText := func(name string, max int) (string, error) {
		items, ok := values[name]
		if !ok {
			return "", nil
		}
		if len(items) != 1 {
			return "", errInvalidAuditFilter
		}
		value := strings.TrimSpace(items[0])
		if len(value) > max || strings.IndexByte(value, 0) >= 0 {
			return "", errInvalidAuditFilter
		}
		return value, nil
	}
	actor, err := readText("actor", 128)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	action, err := readText("action", 128)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	objectType, err := readText("objectType", 64)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	objectID, err := readText("objectId", 200)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	from, err := auditTime(values, "from")
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	to, err := auditTime(values, "to")
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	if from != "" && to != "" && from > to {
		return repo.AuditLogQuery{}, errInvalidAuditFilter
	}
	limit, err := auditInt(values, "limit", 50, 1, 200)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	offset, err := auditInt(values, "offset", 0, 0, 100000)
	if err != nil {
		return repo.AuditLogQuery{}, err
	}
	return repo.AuditLogQuery{Actor: actor, Action: action, ObjectType: objectType, ObjectID: objectID, From: from, To: to, Limit: limit, Offset: offset}, nil
}

var errInvalidAuditFilter = &auditFilterError{}

type auditFilterError struct{}

func (*auditFilterError) Error() string { return "invalid audit filter" }

func auditTime(values map[string][]string, name string) (string, error) {
	items, ok := values[name]
	if !ok {
		return "", nil
	}
	if len(items) != 1 || items[0] == "" {
		return "", errInvalidAuditFilter
	}
	parsed, err := time.Parse(time.RFC3339Nano, items[0])
	if err != nil {
		return "", errInvalidAuditFilter
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}

func auditInt(values map[string][]string, name string, fallback, min, max int) (int, error) {
	items, ok := values[name]
	if !ok {
		return fallback, nil
	}
	if len(items) != 1 {
		return 0, errInvalidAuditFilter
	}
	n, err := strconv.Atoi(items[0])
	if err != nil || n < min || n > max {
		return 0, errInvalidAuditFilter
	}
	return n, nil
}
