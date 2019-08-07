package files

type File struct {
	Name       string `db:"name"`
	MD5        string `db:"md5"`
	Obfuscated string `db:"obfuscated"`
}

type Storage interface {
	Files() ([]File, error)
	Add(name, md5sum, obfuscated string) error
	Update(name, md5sum string) error
	Obfuscated(name string) (string, error)
	Name(obfuscated string) (string, error)
	UUIDs() ([]string, error)
}
