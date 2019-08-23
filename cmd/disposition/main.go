package main

import (
	"flag"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"github.com/ushtipak/disposition/pkg/crypto"
	"github.com/ushtipak/disposition/pkg/files"
	"github.com/ushtipak/disposition/pkg/files/sqlite"
	"github.com/ushtipak/disposition/pkg/repo"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"time"
)

var (
	cfg     Config
	cfgFile = flag.String("conf", "/opt/disposition/disposition.yml", "path to config file")
	debug   = flag.Bool("debug", false, "show debug info")
	// amoeba speak
	poolingOption = flag.String("pooling-option", "push", "which method should be invoked (push / pull / restore)")
	restorePath   = flag.String("restore-to", "/tmp/disposition", "restoration dir")
)

type Config struct {
	Root struct {
		Plain     string `yaml:"plain"`
		Encrypted string `yaml:"encrypted"`
	} `yaml:"root"`
	Secret struct {
		Key        string `yaml:"key"`
		State      string `yaml:"state"`
		Obfuscated string `yaml:"obfuscated"`
	} `yaml:"secret"`
}

// enlist all files with configured root
func scanLocalFiles(root string) (ff []string) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			ff = append(ff, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("scanLocalFiles | filepath.Walk [%s]", err)
	}
	return
}

// does file need to be updated or added to tracked as new
func checkFile(f string, storedFiles []files.File) (tracked bool, updated bool) {
	for _, storedFile := range storedFiles {
		if storedFile.Name == f {
			tracked = true
			md5sum, err := crypto.MD5(f)
			if err != nil {
				log.Fatalf("checkFile | crypto.MD5 [%s]", err)
			}
			if storedFile.MD5 != md5sum {
				updated = true
				break
			}
		}
	}
	return
}

// ensure new uuid is indeed unique
func newUnique(UUIDs []string) (unique string) {
	var stored bool
	for {
		unique = uuid.New().String()
		for _, UUID := range UUIDs {
			if UUID == unique {
				stored = true
			}
		}
		if !stored {
			break
		}
	}
	return
}

// load config and check dirs if not in restore
func init() {
	flag.Parse()

	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = time.RFC3339
	Formatter.FullTimestamp = true
	log.SetFormatter(Formatter)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("pooling option [%v]", *poolingOption)

	f, err := os.Open(*cfgFile)
	if err != nil {
		log.Fatalf("init | os.Open [%s]", err)
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatalf("init | decoder.Decode [%s]", err)
	}

	if *poolingOption != "restore" {
		if _, err := os.Stat(cfg.Root.Plain); os.IsNotExist(err) {
			log.Fatalf("%s missing", cfg.Root.Plain)
		}

		if _, err := os.Stat(cfg.Root.Encrypted); os.IsNotExist(err) {
			err = os.Mkdir(cfg.Root.Encrypted, 0755)
			if err != nil {
				log.Fatalf("init | os.Mkdir [%s]", err)
			}
		}
	}
}

// if there are updated or new files - encrypt, update state and sync remote
func push() {
	log.Debug("state init")
	storage, err := sqlite.New(cfg.Secret.State)
	if err != nil {
		log.Fatalf("push | sqlite.New [%s]", err)
	}

	storedFiles, err := storage.Files()
	if err != nil {
		log.Fatalf("push | storage.Files [%s]", err)
	}

	scannedFiles := scanLocalFiles(cfg.Root.Plain)
	log.Infof("files tracked [%d]", len(storedFiles))
	log.Infof("files scanned [%d]", len(scannedFiles))

	var syncRequired bool
	for _, scannedFile := range scannedFiles {
		tracked, updated := checkFile(scannedFile, storedFiles)
		if !tracked {
			log.Infof("new file [%s]", scannedFile)

			UUIDs, err := storage.UUIDs()
			if err != nil {
				log.Fatalf("push | storage.UUIDs [%s]", err)
			}

			obfuscated := newUnique(UUIDs)
			err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
			if err != nil {
				log.Fatalf("push | crypto.Encrypt [%s]", err)
			}

			md5sum, err := crypto.MD5(scannedFile)
			if err != nil {
				log.Fatalf("push | crypto.MD5 [%s]", err)
			}

			err = storage.Add(scannedFile, md5sum, obfuscated)
			if err != nil {
				log.Fatalf("push | storage.Add [%s]", err)
			}

			syncRequired = true
		} else {
			if updated {
				log.Infof("updated [%s]", scannedFile)
				obfuscated, err := storage.Obfuscated(scannedFile)
				if err != nil {
					log.Fatalf("push | storage.Obfuscated [%s]", err)
				}

				err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
				if err != nil {
					log.Fatalf("push | crypto.Encrypt [%s]", err)
				}

				md5sum, err := crypto.MD5(scannedFile)
				if err != nil {
					log.Fatalf("push | crypto.MD5 [%s]", err)
				}

				err = storage.Update(scannedFile, md5sum)
				if err != nil {
					log.Fatalf("push | storage.Update [%s]", err)
				}
				syncRequired = true
			}
		}
	}

	log.Infof("sync required [%v]", syncRequired)
	if syncRequired {
		err := crypto.Encrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
		if err != nil {
			log.Fatalf("push | crypto.Encrypt [%s]", err)
		}

		err = repo.Push(cfg.Root.Encrypted, *debug)
		if err != nil {
			log.Fatalf("push | repo.Push [%s]", err)
		}
	}

	log.Debug("state close")
	err = storage.Close()
	if err != nil {
		log.Fatalf("push | storage.Close [%s]", err)
	}
}

// if there are changes on remote - decrypt and update state
func pull() {
	synced, err := repo.Pull(cfg.Root.Encrypted, *debug)
	if err != nil {
		log.Fatalf("pull | repo.Pull [%s]", err)
	}

	if !synced {
		log.Info("remote updated")

		err = crypto.Decrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
		if err != nil {
			log.Fatal("failed to decrypt state")
		}

		log.Debug("state init")
		storage, err := sqlite.New(cfg.Secret.State)
		if err != nil {
			log.Fatalf("pull | sqlite.New [%s]", err)
		}

		ff, err := storage.Files()
		if err != nil {
			log.Fatalf("pull | storage.Files [%s]", err)
		}

		for _, f := range ff {
			if _, err := os.Stat(f.Name); os.IsNotExist(err) {
				err = crypto.Decrypt([]byte(cfg.Secret.Key), f.Name, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, f.Obfuscated))
				if err != nil {
					log.Fatalf("pull | crypto.Decrypt [%s]", err)
				}
			}

			md5sum, err := crypto.MD5(f.Name)
			if err != nil {
				log.Fatalf("pull | crypto.MD5 [%s]", err)
			}
			if f.MD5 != md5sum {
				err = crypto.Decrypt([]byte(cfg.Secret.Key), f.Name, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, f.Obfuscated))
				if err != nil {
					log.Fatalf("pull | crypto.Decrypt [%s]", err)
				}
			}
		}

		log.Debug("state close")
		err = storage.Close()
		if err != nil {
			log.Fatalf("pull | storage.Close [%s]", err)
		}
	} else {
		log.Info("remote unchanged")
	}
}

// completely restore and decrypt repo and initialize state
// only secret.key and secret.obfuscated required
func restore() {
	for _, dir := range []string{
		*restorePath,
		fmt.Sprintf("%s/remote", *restorePath),
		fmt.Sprintf("%s/plain", *restorePath),
		fmt.Sprintf("%s/remote/.git", *restorePath),
	} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.Fatalf("restore req missing [%s]", dir)
		}
	}

	log.Info("store decrypt")
	store := fmt.Sprintf("%s/%s", *restorePath, "disposition-state.db")
	err := crypto.Decrypt(
		[]byte(cfg.Secret.Key),
		store,
		fmt.Sprintf("%s/%s/%s", *restorePath, "remote", cfg.Secret.Obfuscated),
	)
	if err != nil {
		log.Fatal("failed to decrypt state")
	}

	log.Debug("state init")
	storage, err := sqlite.New(store)
	if err != nil {
		log.Fatalf("restore | sqlite.New [%s]", err)
	}

	storedFiles, err := storage.Files()
	if err != nil {
		log.Fatalf("restore | storage.Files [%s]", err)
	}

	for _, storedFile := range storedFiles {
		err = crypto.Decrypt(
			[]byte(cfg.Secret.Key),
			fmt.Sprintf("%s/%s/%s", *restorePath, "plain", storedFile.Name[1:]),
			fmt.Sprintf("%s/%s/%s", *restorePath, "remote", storedFile.Obfuscated),
		)
		if err != nil {
			log.Infof("failed to decrypt [%s -> %s]", storedFile.Obfuscated, storedFile.Name)
		}
	}

	log.Debug("state close")
	err = storage.Close()
	if err != nil {
		log.Fatalf("restore | storage.Close [%s]", err)
	}
}

func main() {
	switch *poolingOption {
	case "restore":
		restore()
	case "pull":
		pull()
	default:
		push()
	}
}
