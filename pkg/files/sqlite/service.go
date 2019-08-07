package sqlite

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sqlx.DB
}

func New(path string) (s Storage, err error) {
	db, err := sqlx.Connect("sqlite3", path)
	if err != nil {
		return
	}

	statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, md5 TEXT, obfuscated TEXT UNIQUE)")
	if err != nil {
		return
	}

	_, err = statement.Exec()
	if err != nil {
		return
	}

	return Storage{
		db: db,
	}, nil
}
