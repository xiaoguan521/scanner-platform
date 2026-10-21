package taskflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkerPostAddsNodeAuthenticationHeaders(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Node-ID"); got != "worker-a" {
			t.Errorf("node id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	worker := Worker{ServerURL: server.URL, ID: "worker-a", NodeToken: token, Client: server.Client()}
	if code, err := worker.post(context.Background(), "/api/v1/worker/claim", map[string]string{"workerId": "worker-a"}, nil); err != nil || code != http.StatusNoContent {
		t.Fatalf("post() = %d, %v", code, err)
	}
}
