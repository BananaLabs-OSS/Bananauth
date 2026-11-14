package sqlitecompat

import "strings"

// Statements preserves the text of each nonempty SQL statement. This is a
// compatibility split, not a replacement for PostgreSQL parsing: callers must
// prepare each returned statement on the server before executing it.
func Statements(query string) ([]string, error) {
	pieces, err := lexSQL(query)
	if err != nil {
		return nil, err
	}
	var statements []string
	var text strings.Builder
	significant := false
	flush := func() {
		if significant {
			statements = append(statements, text.String())
		}
		text.Reset()
		significant = false
	}
	for _, piece := range pieces {
		if piece.kind == sqlSymbol && piece.text == ";" {
			flush()
			continue
		}
		text.WriteString(piece.text)
		if piece.kind != sqlSpace && piece.kind != sqlComment {
			significant = true
		}
	}
	flush()
	return statements, nil
}
