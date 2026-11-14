package sqlitecompat

import (
	"errors"
	"net/url"
	"strings"
)

// Native one-shot Exec/Query must use lib/pq's single-exchange parameter path.
// A transaction pooler can release the backend after the intermediate Sync in
// its default unnamed Prepare path. Parameter values remain bound; []byte uses
// lib/pq's documented binary parameter representation. Explicit Prepare still
// requires backend affinity (for example an explicit transaction).
func nativeConnectorDSN(dsn string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid PostgreSQL URL")
		}
		q := u.Query()
		q.Set("binary_parameters", "yes")
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	// lib/pq's own keyword parser handles quoting/escaping and applies later
	// settings last. Append a separate setting; never tokenize DSNs ourselves.
	return dsn + " binary_parameters=yes", nil
}
