package main

import (
	"net/url"
	"testing"
)

func TestOfflinePostgresURL(t *testing.T) {
	local := "postgresql:///source?host=" + url.QueryEscape(t.TempDir())
	if _, _, err := offlinePostgresURL(local); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"postgresql://remote/source",
		"postgresql:///source?host=127.0.0.1",
		local + "&dbname=another",
		local + "&host=remote",
	} {
		if _, _, err := offlinePostgresURL(invalid); err == nil {
			t.Fatalf("accepted invalid offline URL %q", invalid)
		}
	}
}
