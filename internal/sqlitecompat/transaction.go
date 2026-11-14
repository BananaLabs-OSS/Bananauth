package sqlitecompat

import (
	"fmt"
	"strings"
)

// TransactionControl identifies the exact transaction boundary operations used
// by the storage ABI. It uses the same SQL lexer as Rewrite, so quoted text,
// dollar-quoted bodies and comments cannot hide or invent control statements.
// Ordinary multi-statement SQL remains supported; transaction boundaries must
// be standalone. Savepoint operations do not end the host-owned transaction.
func TransactionControl(query string) (string, error) {
	pieces, err := lexSQL(query)
	if err != nil {
		return "", err
	}
	var statements [][]sqlPiece
	var current []sqlPiece
	for _, p := range pieces {
		if p.kind == sqlSpace || p.kind == sqlComment {
			continue
		}
		if p.kind == sqlSymbol && p.text == ";" {
			if len(current) > 0 {
				statements = append(statements, current)
				current = nil
			}
			continue
		}
		current = append(current, p)
	}
	if len(current) > 0 {
		statements = append(statements, current)
	}
	control := ""
	for _, statement := range statements {
		first := statement[0]
		if first.kind != sqlWord {
			continue
		}
		word := strings.ToUpper(first.text)
		switch word {
		case "BEGIN", "COMMIT", "ROLLBACK", "START", "END", "ABORT", "PREPARE":
			if word == "PREPARE" && (len(statement) < 2 || !equalWord(statement[1], "TRANSACTION")) {
				continue
			}
			if word == "ROLLBACK" && len(statement) > 1 && equalWord(statement[1], "TO") {
				continue
			}
			if len(statements) != 1 || len(statement) != 1 || (word != "BEGIN" && word != "COMMIT" && word != "ROLLBACK") {
				return "", fmt.Errorf("storage.postgres: unsupported transaction boundary; use standalone BEGIN, COMMIT or ROLLBACK")
			}
			control = strings.ToLower(word)
		}
	}
	return control, nil
}
