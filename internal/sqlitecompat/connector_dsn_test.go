package sqlitecompat

import (
	"net/url"
	"testing"
)

func TestNativeConnectorURLPreservesSettingsAndForcesSingleExchange(t *testing.T) {
	raw := "postgresql://ordinary:p%40ss@127.0.0.1:5432/fixture?application_name=ordinary+name&sslmode=disable&binary_parameters=no&custom_setting=a%2Bb"
	normalized, err := nativeConnectorDSN(raw)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := url.Parse(raw)
	after, err := url.Parse(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if before.Scheme != after.Scheme || before.User.String() != after.User.String() || before.Host != after.Host || before.Path != after.Path {
		t.Fatal("connection address changed")
	}
	q := after.Query()
	if q.Get("binary_parameters") != "yes" || len(q["binary_parameters"]) != 1 {
		t.Fatal("single-exchange mode not enforced")
	}
	for name, values := range before.Query() {
		if name != "binary_parameters" {
			if len(values) != 1 || q.Get(name) != values[0] {
				t.Fatalf("setting %s changed", name)
			}
		}
	}
}
