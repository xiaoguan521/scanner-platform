package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"scanner-platform/internal/account"
	"scanner-platform/internal/repo"
	"scanner-platform/internal/reporting"
)

func TestReportAPIAuthenticationWriteGuardsAndDownloads(t *testing.T) {
	ctx := context.Background()
	accounts, err := account.New(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	password := "Example-" + rand.Text()
	if err := accounts.InitAdmin(ctx, "reportadmin", password); err != nil {
		t.Fatal(err)
	}
	admin, adminToken, err := accounts.Authenticate(ctx, "reportadmin", password)
	if err != nil {
		t.Fatal(err)
	}
	viewerPassword := "Example-" + rand.Text()
	if _, err := accounts.Create(ctx, admin, "reportviewer", viewerPassword, "viewer"); err != nil {
		t.Fatal(err)
	}
	_, viewerToken, err := accounts.Authenticate(ctx, "reportviewer", viewerPassword)
	if err != nil {
		t.Fatal(err)
	}
	store, err := repo.NewRuntime(accounts.SQLDB())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewRuntimeHandler(store, nil, "", accounts)
	send := func(method, path, body, token string, guard bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		}
		if guard {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	for _, path := range []string{"/api/v1/reports", "/api/v1/reports/missing/download", "/api/v1/report-templates"} {
		if got := send("GET", path, "", "", false); got.Code != 401 {
			t.Fatalf("anonymous %s: %d", path, got.Code)
		}
	}
	if got := send("POST", "/api/v1/reports", `{"format":"html"}`, viewerToken, true); got.Code != 403 {
		t.Fatalf("viewer write: %d", got.Code)
	}
	if got := send("POST", "/api/v1/reports", `{"format":"html"}`, adminToken, false); got.Code != 403 {
		t.Fatalf("missing CSRF guard: %d", got.Code)
	}
	pdfCreated := send("POST", "/api/v1/reports", `{"format":"pdf"}`, adminToken, true)
	if pdfCreated.Code != 202 {
		t.Fatalf("pdf create: %d %s", pdfCreated.Code, pdfCreated.Body.String())
	}
	var pdfJob reporting.Job
	if err := json.Unmarshal(pdfCreated.Body.Bytes(), &pdfJob); err != nil {
		t.Fatal(err)
	}
	if done, err := store.ProcessNextReport(ctx, t.TempDir()); err != nil || !done {
		t.Fatalf("generate pdf: %v %v", done, err)
	}
	if got := send("GET", "/api/v1/reports/"+pdfJob.ID+"/download", "", viewerToken, false); got.Code != http.StatusOK || got.Header().Get("Content-Type") != "application/pdf" || !strings.HasPrefix(got.Body.String(), "%PDF-1.4") {
		t.Fatalf("pdf download: %d %s", got.Code, got.Header().Get("Content-Type"))
	}
	created := send("POST", "/api/v1/reports", `{"format":"html"}`, adminToken, true)
	if created.Code != 202 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var job reporting.Job
	if err := json.Unmarshal(created.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	download := "/api/v1/reports/" + job.ID + "/download"
	if got := send("GET", download, "", adminToken, false); got.Code != 409 {
		t.Fatalf("unready download: %d", got.Code)
	}
	if done, err := store.ProcessNextReport(ctx, t.TempDir()); err != nil || !done {
		t.Fatalf("generate: %v %v", done, err)
	}
	if got := send("GET", download, "", viewerToken, false); got.Code != 200 || !strings.Contains(got.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(got.Body.String(), job.SnapshotID) || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authenticated download: %d", got.Code)
	}
	if got := send("POST", "/api/v1/reports/"+job.ID+"/formats", `{"format":"xlsx"}`, viewerToken, true); got.Code != 403 {
		t.Fatalf("viewer format export: %d", got.Code)
	}
	pdfDerived := send("POST", "/api/v1/reports/"+job.ID+"/formats", `{"format":"pdf"}`, adminToken, true)
	if pdfDerived.Code != 202 {
		t.Fatalf("pdf format export: %d %s", pdfDerived.Code, pdfDerived.Body.String())
	}
	derivative := send("POST", "/api/v1/reports/"+job.ID+"/formats", `{"format":"docx"}`, adminToken, true)
	if derivative.Code != 202 {
		t.Fatalf("format export: %d %s", derivative.Code, derivative.Body.String())
	}
	var other reporting.Job
	if err := json.Unmarshal(derivative.Body.Bytes(), &other); err != nil || other.SnapshotID != job.SnapshotID {
		t.Fatal("format export changed snapshot")
	}
	for _, format := range []string{"csv", "json"} {
		queued := send("POST", "/api/v1/reports/"+job.ID+"/formats", `{"format":"`+format+`"}`, adminToken, true)
		if queued.Code != 202 {
			t.Fatalf("%s format export: %d %s", format, queued.Code, queued.Body.String())
		}
		var derived reporting.Job
		if err := json.Unmarshal(queued.Body.Bytes(), &derived); err != nil {
			t.Fatal(err)
		}
		for attempts := 0; attempts < 10; attempts++ {
			current, err := store.GetReport(ctx, derived.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Status == "READY" {
				break
			}
			done, err := store.ProcessNextReport(ctx, t.TempDir())
			if err != nil || !done {
				t.Fatalf("generate %s: %v %v", format, done, err)
			}
			if attempts == 9 {
				t.Fatalf("%s report did not become ready", format)
			}
		}
		downloaded := send("GET", "/api/v1/reports/"+derived.ID+"/download", "", viewerToken, false)
		if downloaded.Code != 200 || !strings.Contains(downloaded.Header().Get("Content-Type"), map[string]string{"csv": "text/csv", "json": "application/json"}[format]) {
			t.Fatalf("download %s: %d %s", format, downloaded.Code, downloaded.Header().Get("Content-Type"))
		}
	}
	list := send("GET", "/api/v1/reports", "", viewerToken, false)
	if list.Code != 200 || strings.Contains(list.Body.String(), "filePath") {
		t.Fatal("report listing failed or exposed disk path")
	}
	template := reporting.DefaultTemplate()
	template.Logo = "https://example.com/logo.png"
	raw, _ := json.Marshal(template)
	if got := send("PUT", "/api/v1/report-templates/default", string(raw), adminToken, true); got.Code != 400 {
		t.Fatalf("remote logo accepted: %d", got.Code)
	}
	if got := send("POST", "/api/v1/reports/"+job.ID+"/retry", "", adminToken, true); got.Code != 409 {
		t.Fatalf("ready job retried: %d", got.Code)
	}
}
