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
}
