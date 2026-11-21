package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetiredBrowserCompletionRouteAbsent(t *testing.T) {
	mux := http.NewServeMux()
	registerBrowserWorkflowRoutes(mux, nil, nil, strings.Repeat("k", 32))
	for _, path := range []string{"/internal/browser/email/v2/complete", "/internal/browser/email/issue", "/internal/browser/email/consume"} {
		r := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("k", 32))
		mux.ServeHTTP(r, req)
		if r.Code != http.StatusNotFound {
			t.Fatalf("retired completion %s returned %d", path, r.Code)
		}
	}
}
