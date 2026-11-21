package session

import "database/sql"

// Open initializes the existing session schema on the application's database.
func Open(db *sql.DB) (*Service, error) {
	store, err := newSQLiteStore(db)
	if err != nil {
		return nil, err
	}
	return newOwner(store), nil
}
