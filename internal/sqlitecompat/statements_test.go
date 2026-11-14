package sqlitecompat

import (
	"reflect"
	"strings"
	"testing"
)

func TestStatementsPreserveOrdinarySQL(t *testing.T) {
	cases := []struct {
		query string
		want  []string
	}{
		{"CREATE TABLE demo (id INTEGER); INSERT INTO demo VALUES (1);", []string{"CREATE TABLE demo (id INTEGER)", " INSERT INTO demo VALUES (1)"}},
		{"SELECT ';' AS value; -- next\nSELECT 2", []string{"SELECT ';' AS value", " -- next\nSELECT 2"}},
		{"SELECT $$a;b$$; SELECT \"a;b\"", []string{"SELECT $$a;b$$", " SELECT \"a;b\""}},
		{"/* metadata; */ SELECT 1; -- done", []string{"/* metadata; */ SELECT 1"}},
		{"; /* metadata only */ ;", nil},
	}
	for _, c := range cases {
		got, err := Statements(c.query)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Fatalf("Statements(%q) = %#v, %v; want %#v", c.query, got, err, c.want)
		}
	}
}

func BenchmarkRewriteLargeQuotedValue(b *testing.B) {
	query := "INSERT INTO demo (value) VALUES ('" + strings.Repeat("x", 1<<20) + "')"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Rewrite(query, 0); err != nil {
			b.Fatal(err)
		}
	}
}
