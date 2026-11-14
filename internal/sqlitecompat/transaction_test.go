package sqlitecompat

import "testing"

func TestTransactionControlUsesSQLTokens(t *testing.T) {
	for _, tc := range []struct{ query, control string }{
		{`SELECT E'it\'s; COMMIT; BEGIN', E'\\'; SELECT 1`, ""},
		{"BEGIN", "begin"}, {" /* outer /* nested */ */ BeGiN ; -- tail", "begin"}, {"COMMIT;", "commit"}, {"ROLLBACK", "rollback"},
		{"SAVEPOINT point; ROLLBACK TO SAVEPOINT point; RELEASE point", ""},
		{"CREATE TABLE a (v text); CREATE TABLE b (v text)", ""},
		{"SELECT 'BEGIN; COMMIT', \"ROLLBACK\", $$BEGIN; END$$, $body$COMMIT;$body$", ""},
		{"CREATE FUNCTION x() RETURNS void AS $$ BEGIN RAISE NOTICE 'COMMIT'; END $$ LANGUAGE plpgsql; SELECT 1", ""},
	} {
		got, err := TransactionControl(tc.query)
		if err != nil || got != tc.control {
			t.Errorf("%q got(%q,%v),want%q", tc.query, got, err, tc.control)
		}
	}
	for _, query := range []string{"SELECT 1;/*hidden*/COMMIT;", "SELECT 1;-- hidden until carriage return\rCOMMIT", "BEGIN; INSERT INTO a VALUES (1)", "BEGIN IMMEDIATE", "BEGIN ISOLATION LEVEL SERIALIZABLE", "START TRANSACTION", "END", "ABORT", "PREPARE TRANSACTION 'x'", "COMMIT PREPARED 'x'", "ROLLBACK PREPARED 'x'", "ROLLBACK WORK", ";COMMIT;SELECT 1", "SELECT 1; START /*x*/ TRANSACTION", "BEGIN /*unterminated"} {
		if _, err := TransactionControl(query); err == nil {
			t.Errorf("accepted unsupported boundary%q", query)
		}
	}
}
