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
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/internal/browser/email/v2/complete", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("k", 32))
	mux.ServeHTTP(r, req)
	if r.Code != http.StatusNotFound {
		t.Fatalf("retired completion returned %d", r.Code)
	}
}
