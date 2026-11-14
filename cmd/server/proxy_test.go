package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardedAddressesRequireTrustedPeers(t *testing.T) {
	proxies, err := parseTrustedProxies("192.0.2.10/32, 192.0.2.11/32")
	if err != nil {
		t.Fatal(err)
	}
	handler := trustForwardedAddresses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, clientIP(r))
	}), proxies)
	for _, tc := range []struct{ name, peer, header, want string }{
		{"direct spoof", "198.51.100.4:1234", "203.0.113.95", "198.51.100.4"},
		{"gateway client 1", "192.0.2.10:1234", "198.51.100.4", "198.51.100.4"},
		{"gateway client 2", "192.0.2.10:1234", "198.51.100.5", "198.51.100.5"},
		{"untrusted leftmost hop", "192.0.2.10:1234", "203.0.113.95, 198.51.100.4, 192.0.2.11", "198.51.100.4"},
		{"malformed nearest hop", "192.0.2.10:1234", "203.0.113.95, malformed", "192.0.2.10"},
		{"no header", "192.0.2.10:1234", "", "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Forwarded-For", tc.header)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if got := w.Body.String(); got != tc.want {
				t.Fatalf("client IP = %q, want %q", got, tc.want)
			}
		})
	}
}
