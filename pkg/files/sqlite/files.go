package sqlite

import (
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/ushtipak/disposition/pkg/files"
)

var _ files.Storage = Storage{}

func (s Storage) Files() (ff []files.File, err error) {
	rows, err := s.db.Queryx("SELECT * FROM state")
	if err != nil {
		return
	}

	var f files.File
	for rows.Next() {
		err = rows.StructScan(&f)
		if err != nil {
			return
		}
		ff = append(ff, f)
	}

	err = rows.Close()
	if err != nil {
		return
	}
	return
}

func (s Storage) Add(name, md5sum, obfuscated string) (err error) {
	stmt, err := s.db.Prepare("INSERT INTO state (name, md5, obfuscated) VALUES (?, ?, ?)")
	if err != nil {
		return
	}

	_, err = stmt.Exec(name, md5sum, obfuscated)
	return
}

func (s Storage) Update(name, md5sum string) (err error) {
	stmt, err := s.db.Prepare("UPDATE state SET md5 = ? WHERE name = ?")
	if err != nil {
		return
	}

	_, err = stmt.Exec(md5sum, name)
	return
}

func (s Storage) Close() (err error) {
	return s.db.Close()
}

func (s Storage) Obfuscated(name string) (obfuscated string, err error) {
	rows, err := s.db.Queryx(fmt.Sprintf("SELECT obfuscated FROM state WHERE name == \"%s\"", name))
	if err != nil {
		return
	}

	var f files.File
	for rows.Next() {
		err = rows.StructScan(&f)
		if err != nil {
			return
		}
	}

	return f.Obfuscated, nil
}

func (s Storage) Name(obfuscated string) (name string, err error) {
	rows, err := s.db.Queryx(fmt.Sprintf("SELECT name FROM state WHERE obfuscated == \"%s\"", obfuscated))
	if err != nil {
		return
	}

	var f files.File
	for rows.Next() {
		err = rows.StructScan(&f)
		if err != nil {
			return
		}
	}

	return f.Name, nil
}

func (s Storage) UUIDs() (UUIDs []string, err error) {
	rows, err := s.db.Queryx("SELECT obfuscated FROM state")
	if err != nil {
		return
	}

	var f files.File
	for rows.Next() {
		err = rows.StructScan(&f)
		if err != nil {
			return
		}
		UUIDs = append(UUIDs, f.Obfuscated)
	}

	err = rows.Close()
	return
}
