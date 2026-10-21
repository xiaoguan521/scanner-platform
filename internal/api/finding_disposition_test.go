package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanner-platform/internal/account"
	"scanner-platform/internal/assets"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/taskflow"
)

func TestFindingDispositionAPIAuthValidationAndEvents(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "finding.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := accounts.InitAdmin(ctx, "findingadmin", "Safe-Example-Password-14"); err != nil {
		t.Fatal(err)
	}
	admin, _, err := accounts.Authenticate(ctx, "findingadmin", "Safe-Example-Password-14")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assets.New(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.CreateSyntheticTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimRuntimeTask(ctx, "fixture-worker")
	if err != nil || claim == nil {
		t.Fatal(claim, err)
	}
	if err := store.CompleteRuntimeTask(ctx, taskflow.Report{TaskID: task.ID, WorkerID: "fixture-worker", Target: claim.Chunks[0].Targets[0], Title: taskflow.SyntheticTitle}); err != nil {
		t.Fatal(err)
	}
	findings, err := store.ListRuntimeFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatal(findings, err)
	}
	id := findings[0].ID
	handler := NewRuntimeHandler(store, NewDevelopmentHandler(accounts, registry), "", accounts)
	send := func(method, path, body string, cookie *http.Cookie, guard bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if guard {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	cookies := map[string]*http.Cookie{}
	for _, role := range []string{"admin", "security_engineer", "viewer", "ops_approver"} {
		name := "findingadmin"
		if role != "admin" {
			name = "finding_" + role
			if _, err := accounts.Create(ctx, admin, name, "Safe-Example-Password-14", role); err != nil {
				t.Fatal(err)
			}
		}
		login := send("POST", "/api/v1/auth/login", `{"username":"`+name+`","password":"Safe-Example-Password-14"}`, nil, true)
		if login.Code != 200 {
			t.Fatal(login.Code, login.Body.String())
		}
		cookies[role] = login.Result().Cookies()[0]
	}
	path := "/api/v1/findings/" + id
	for _, tc := range []struct {
		method, suffix, body, role string
		guard                      bool
		want                       int
	}{
		{"PATCH", "", `{"status":"IN_PROGRESS"}`, "", true, 401},
		{"PATCH", "", `{"status":"IN_PROGRESS"}`, "viewer", true, 403},
		{"PATCH", "", `{"status":"IN_PROGRESS"}`, "ops_approver", true, 403},
		{"PATCH", "", `{"status":"IN_PROGRESS"}`, "admin", false, 403},
		{"PATCH", "", `{"status":"FIXED"}`, "admin", true, 400},
		{"PATCH", "", `{"status":"ACCEPTED_RISK"}`, "admin", true, 400},
		{"GET", "/events", "", "", false, 401},
		{"GET", "/events", "", "viewer", false, 200},
		{"POST", "/retest", `{}`, "", true, 401},
		{"POST", "/retest", `{}`, "viewer", true, 403},
		{"POST", "/retest", `{}`, "admin", false, 403},
		{"POST", "/retest", `{"extra":true}`, "admin", true, 400},
		{"POST", "/retest", `{}`, "admin", true, 400},
		{"GET", "/retests", "", "", false, 401},
		{"GET", "/retests", "", "viewer", false, 200},
	} {
		res := send(tc.method, path+tc.suffix, tc.body, cookies[tc.role], tc.guard)
		if res.Code != tc.want {
			t.Fatalf("%s %s %s = %d %s", tc.method, tc.suffix, tc.role, res.Code, res.Body.String())
		}
	}
	input := map[string]string{"status": "ACCEPTED_RISK", "reason": "等待例行维护", "acceptedUntil": time.Now().Add(time.Hour).Format(time.RFC3339)}
	body, _ := json.Marshal(input)
	res := send("PATCH", path, string(body), cookies["security_engineer"], true)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	var accepted taskflow.Finding
	if err := json.Unmarshal(res.Body.Bytes(), &accepted); err != nil || accepted.AcceptedUntil == nil || accepted.AcceptedReason != input["reason"] {
		t.Fatal(accepted, err)
	}
	res = send("GET", path+"/events", "", cookies["viewer"], false)
	var events ListResponse[repo.FindingEvent]
	if err := json.Unmarshal(res.Body.Bytes(), &events); err != nil || events.Total != 1 || events.Items[0].ToStatus != "ACCEPTED_RISK" || events.Items[0].Actor == "" {
		t.Fatal(events, err)
	}
	res = send("PATCH", path, `{"status":"OPEN"}`, cookies["admin"], true)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	res = send("PATCH", path, `{"status":"OPEN"}`, cookies["admin"], true)
	if res.Code != 400 {
		t.Fatal("noop", res.Code)
	}
	// Batch mutations share role/CSRF checks and reject unknown or stale input.
	batchPath := "/api/v1/findings/batch-disposition"
	batchBody := `{"items":[{"id":"` + id + `","expectedStatus":"OPEN"}],"status":"IN_PROGRESS"}`
	for _, tc := range []struct {
		body, role string
		guard      bool
		want       int
	}{
		{batchBody, "", true, 401}, {batchBody, "viewer", true, 403}, {batchBody, "ops_approver", true, 403}, {batchBody, "admin", false, 403},
		{`{"items":[],"status":"OPEN"}`, "admin", true, 400},
		{`{"items":[{"id":"` + id + `","expectedStatus":"OPEN","extra":true}],"status":"IN_PROGRESS"}`, "admin", true, 400},
		{`{"items":[{"id":"` + id + `","expectedStatus":"OPEN"}],"status":"IN_PROGRESS","extra":true}`, "admin", true, 400},
		{`{"items":[{"id":"` + id + `","expectedStatus":"FIXED"}],"status":"IN_PROGRESS"}`, "admin", true, 409},
	} {
		res := send("POST", batchPath, tc.body, cookies[tc.role], tc.guard)
		if res.Code != tc.want {
			t.Fatalf("batch %s %d: %d %s", tc.role, tc.want, res.Code, res.Body.String())
		}
	}
	batchRes := send("POST", batchPath, batchBody, cookies["security_engineer"], true)
	var batchResult struct {
		Updated int                `json:"updated"`
		Items   []taskflow.Finding `json:"items"`
	}
	if err := json.Unmarshal(batchRes.Body.Bytes(), &batchResult); batchRes.Code != 200 || err != nil || batchResult.Updated != 1 || len(batchResult.Items) != 1 || batchResult.Items[0].Status != "IN_PROGRESS" {
		t.Fatal(batchRes.Code, batchRes.Body.String(), err)
	}
	if res := send("POST", batchPath, batchBody, cookies["admin"], true); res.Code != 409 {
		t.Fatal("stale batch", res.Code)
	}
	// Finding work routes share authenticated reads and writer/CSRF protections.
	for _, tc := range []struct {
		method, suffix, body, role string
		guard                      bool
		want                       int
	}{
		{"GET", "/notes", "", "", false, 401},
		{"GET", "/notes", "", "viewer", false, 200},
		{"POST", "/notes", `{"body":"note"}`, "viewer", true, 403},
		{"POST", "/notes", `{"body":"note"}`, "ops_approver", true, 403},
		{"POST", "/notes", `{"body":"note"}`, "admin", false, 403},
		{"POST", "/notes", `{"body":""}`, "admin", true, 400},
		{"POST", "/notes", `{"body":"a\u2028b"}`, "admin", true, 400},
		{"POST", "/notes", `{"body":"a\u2029b"}`, "admin", true, 400},
		{"PUT", "/assignee", `{}`, "admin", true, 400},
		{"PUT", "/assignee", `{"assigneeId":null}`, "admin", true, 400},
		{"PUT", "/assignee", `{"assigneeId":"missing"}`, "admin", true, 400},
		{"PUT", "/assignee", `{"assigneeId":""}`, "viewer", true, 403},
	} {
		res := send(tc.method, path+tc.suffix, tc.body, cookies[tc.role], tc.guard)
		if res.Code != tc.want {
			t.Fatalf("work %s %s %s: %d %s", tc.method, tc.suffix, tc.role, res.Code, res.Body.String())
		}
	}
	assignmentBatchPath := "/api/v1/findings/batch-assignment"
	assignmentBatchBody := `{"items":[{"id":"` + id + `","expectedAssigneeId":""}],"assigneeId":"` + admin.ID + `"}`
	for _, tc := range []struct {
		body, role string
		guard      bool
		want       int
	}{
		{assignmentBatchBody, "", true, 401},
		{assignmentBatchBody, "viewer", true, 403},
		{assignmentBatchBody, "admin", false, 403},
		{`{"items":[],"assigneeId":"` + admin.ID + `"}`, "admin", true, 400},
		{`{"items":[{"id":"` + id + `","expectedAssigneeId":"","extra":true}],"assigneeId":"` + admin.ID + `"}`, "admin", true, 400},
	} {
		res := send("POST", assignmentBatchPath, tc.body, cookies[tc.role], tc.guard)
		if res.Code != tc.want {
			t.Fatalf("batch assignment %s: %d %s", tc.role, res.Code, res.Body.String())
		}
	}
	if res := send("POST", assignmentBatchPath, assignmentBatchBody, cookies["security_engineer"], true); res.Code != 200 {
		t.Fatalf("batch assignment: %d %s", res.Code, res.Body.String())
	}
	assignmentHistory := send("GET", path+"/assignments", "", cookies["viewer"], false)
	var assignmentEvents ListResponse[repo.FindingAssignmentEvent]
	if err := json.Unmarshal(assignmentHistory.Body.Bytes(), &assignmentEvents); assignmentHistory.Code != 200 || err != nil || assignmentEvents.Total != 1 || assignmentEvents.Items[0].ToAssigneeID != admin.ID {
		t.Fatalf("assignment history: %d %+v %v", assignmentHistory.Code, assignmentEvents, err)
	}
	if res := send("GET", "/api/v1/findings/assignees", "", nil, false); res.Code != 401 {
		t.Fatal(res.Code)
	}
	for _, role := range []string{"viewer", "ops_approver"} {
		if res := send("GET", "/api/v1/findings/assignees", "", cookies[role], false); res.Code != 403 {
			t.Fatalf("candidate access %s: %d", role, res.Code)
		}
	}
	candidatesResponse := send("GET", "/api/v1/findings/assignees", "", cookies["security_engineer"], false)
	var candidates ListResponse[repo.FindingAssignee]
	if err := json.Unmarshal(candidatesResponse.Body.Bytes(), &candidates); err != nil || candidates.Total != 2 {
		t.Fatal(candidatesResponse.Code, candidates, err)
	}
	if strings.Contains(candidatesResponse.Body.String(), "password") || strings.Contains(candidatesResponse.Body.String(), "isActive") {
		t.Fatal("account metadata exposed")
	}
	if res := send("PUT", path+"/assignee", `{"assigneeId":""}`, cookies["admin"], true); res.Code != 200 {
		t.Fatal("clear batch assignment", res.Code, res.Body.String())
	}
	assignment, _ := json.Marshal(map[string]string{"assigneeId": admin.ID})
	if res := send("PUT", path+"/assignee", string(assignment), cookies["security_engineer"], true); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	noteResponse := send("POST", path+"/notes", `{"body":"处理前需要复核补丁"}`, cookies["security_engineer"], true)
	if noteResponse.Code != 201 {
		t.Fatal(noteResponse.Code, noteResponse.Body.String())
	}
	notesResponse := send("GET", path+"/notes", "", cookies["viewer"], false)
	var notes ListResponse[repo.FindingNote]
	if err := json.Unmarshal(notesResponse.Body.Bytes(), &notes); err != nil || notes.Total != 1 || notes.Items[0].Body != "处理前需要复核补丁" {
		t.Fatal(notes, err)
	}
	if res := send("PUT", path+"/assignee", `{"assigneeId":""}`, cookies["admin"], true); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}

	// Standalone local mode matches the existing single-item disposition route.
	localHandler := NewRuntimeHandler(store, nil, "")
	localRequest := httptest.NewRequest("POST", batchPath, strings.NewReader(`{"items":[{"id":"`+id+`","expectedStatus":"IN_PROGRESS"}],"status":"OPEN"}`))
	localResponse := httptest.NewRecorder()
	localHandler.ServeHTTP(localResponse, localRequest)
	if localResponse.Code != 200 {
		t.Fatal("local batch semantics", localResponse.Code, localResponse.Body.String())
	}

}
