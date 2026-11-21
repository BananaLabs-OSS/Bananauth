package main

import (
	"bytes"
	"context"
	"github.com/bananalabs-oss/bananauth/internal/identity"
	"github.com/bananalabs-oss/bananauth/pkg/otpsecure"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateIdentityUsesOneStrictJSONContract(t *testing.T) {
	keys, _ := otpsecure.Parse(strings.Repeat("k", 32), "")
	service, closeDB, err := identity.Open(context.Background(), filepath.Join(t.TempDir(), "identity.db"), keys)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB.Close()
	token := strings.Repeat("s", 32)
	mux := http.NewServeMux()
	registerIdentityRoutes(mux, service, token)
	for _, body := range []string{`null`, `{"account_id":"one","account_id":"two"}`, `{"account_id":"one","unknown":true}`, `{"account_id":"one"} {}`, string([]byte{0x81, 0xa1, 'x', 0x01}), strings.Repeat(" ", 16385)} {
		request := httptest.NewRequest("POST", "/internal/identity/accounts/lookup", bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, request)
		if out.Code != 400 {
			t.Fatalf("malformed request returned %d", out.Code)
		}
		if strings.Contains(out.Body.String(), "account_id") || strings.Contains(out.Body.String(), "version") {
			t.Fatal("invalid request leaked identity or retired protocol envelope")
		}
	}
}
