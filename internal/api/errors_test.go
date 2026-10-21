package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIErrorIncludesStableContractAndRequestID(t *testing.T) {
	response := httptest.NewRecorder()
	runtimeJSON(response, http.StatusBadRequest, APIError{Error: "invalid_input", Message: "输入无效"})
	var body APIError
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if body.Code != "invalid_input" || body.Error != body.Code {
		t.Fatalf("code compatibility fields = %#v", body)
	}
	if body.Message != "输入无效" || body.Hint == "" {
		t.Fatalf("message/hint = %#v", body)
	}
	if body.RequestID == "" || response.Header().Get("X-Request-ID") != body.RequestID {
		t.Fatalf("request id body=%q header=%q", body.RequestID, response.Header().Get("X-Request-ID"))
	}
}

func TestRequestIDIsReusedByNestedHandlers(t *testing.T) {
	handler := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		runtimeJSON(w, http.StatusUnauthorized, APIError{Code: "unauthorized", Message: "未登录"})
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/api/v1/auth/me", nil))
	var body APIError
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got, want := body.RequestID, response.Header().Get("X-Request-ID"); got == "" || got != want {
		t.Fatalf("nested request id body=%q header=%q", got, want)
	}
}
