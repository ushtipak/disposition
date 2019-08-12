package main

import (
	"../../pkg/crypto"
	"../../pkg/files"
	"../../pkg/files/sqlite"
	"../../pkg/repo"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
)

var (
	cfg           Config
	cfgFile       = flag.String("conf", "/opt/disposition/disposition.yml", "path to config file")
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
		glog.Fatalf("scanLocalFiles | filepath.Walk [%s]", err)
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
				glog.Fatalf("checkFile | crypto.MD5 [%s]", err)
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

	glog.Infof("pooling option [%v]", *poolingOption)

	f, err := os.Open(*cfgFile)
	if err != nil {
		glog.Fatalf("init | os.Open [%s]", err)
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		glog.Fatalf("init | decoder.Decode [%s]", err)
	}

	if *poolingOption != "restore" {
		if _, err := os.Stat(cfg.Root.Plain); os.IsNotExist(err) {
			glog.Fatalf("%s missing", cfg.Root.Plain)
		}

		if _, err := os.Stat(cfg.Root.Encrypted); os.IsNotExist(err) {
			err = os.Mkdir(cfg.Root.Encrypted, 0755)
			if err != nil {
				glog.Fatalf("init | os.Mkdir [%s]", err)
			}
		}
	}
}

// if there are updated or new files - encrypt, update state and sync remote
func push() {
	glog.V(2).Infoln("state init")
	storage, err := sqlite.New(cfg.Secret.State)
	if err != nil {
		glog.Fatalf("push | sqlite.New [%s]", err)
	}

	storedFiles, err := storage.Files()
	if err != nil {
		glog.Fatalf("push | storage.Files [%s]", err)
	}

	scannedFiles := scanLocalFiles(cfg.Root.Plain)
	glog.Infof("files tracked [%d]", len(storedFiles))
	glog.Infof("files scanned [%d]", len(scannedFiles))

	var syncRequired bool
	for _, scannedFile := range scannedFiles {
		tracked, updated := checkFile(scannedFile, storedFiles)
		if !tracked {
			glog.Infof("new file [%s]", scannedFile)

			UUIDs, err := storage.UUIDs()
			if err != nil {
				glog.Fatalf("push | storage.UUIDs [%s]", err)
			}

			obfuscated := newUnique(UUIDs)
			err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
			if err != nil {
				glog.Fatalf("push | crypto.Encrypt [%s]", err)
			}

			md5sum, err := crypto.MD5(scannedFile)
			if err != nil {
				glog.Fatalf("push | crypto.MD5 [%s]", err)
			}

			err = storage.Add(scannedFile, md5sum, obfuscated)
			if err != nil {
				glog.Fatalf("push | storage.Add [%s]", err)
			}

			syncRequired = true
		} else {
			if updated {
				glog.Infof("updated [%s]", scannedFile)
				obfuscated, err := storage.Obfuscated(scannedFile)
				if err != nil {
					glog.Fatalf("push | storage.Obfuscated [%s]", err)
				}

				err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
				if err != nil {
					glog.Fatalf("push | crypto.Encrypt [%s]", err)
				}

				md5sum, err := crypto.MD5(scannedFile)
				if err != nil {
					glog.Fatalf("push | crypto.MD5 [%s]", err)
				}

				err = storage.Update(scannedFile, md5sum)
				if err != nil {
					glog.Fatalf("push | storage.Update [%s]", err)
				}
				syncRequired = true
			}
		}
	}

	glog.Infof("sync required [%v]", syncRequired)
	if syncRequired {
		err := crypto.Encrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
		if err != nil {
			glog.Fatalf("push | crypto.Encrypt [%s]", err)
		}

		err = repo.Push(cfg.Root.Encrypted)
		if err != nil {
			glog.Fatalf("push | repo.Push [%s]", err)
		}
	}

	glog.V(2).Infoln("state close")
	err = storage.Close()
	if err != nil {
		glog.Fatalf("push | storage.Close [%s]", err)
	}
}

// if there are changes on remote - decrypt and update state
func pull() {
	synced, err := repo.Pull(cfg.Root.Encrypted)
	if err != nil {
		glog.Fatalf("pull | repo.Pull [%s]", err)
	}

	if !synced {
		glog.Infoln("remote updated")

		err = crypto.Decrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
		if err != nil {
			glog.Fatalln("failed to decrypt state")
		}

		glog.V(2).Infoln("state init")
		storage, err := sqlite.New(cfg.Secret.State)
		if err != nil {
			glog.Fatalf("pull | sqlite.New [%s]", err)
		}

		ff, err := storage.Files()
		if err != nil {
			glog.Fatalf("pull | storage.Files [%s]", err)
		}

		for _, f := range ff {
			if _, err := os.Stat(f.Name); os.IsNotExist(err) {
				err = crypto.Decrypt([]byte(cfg.Secret.Key), f.Name, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, f.Obfuscated))
				if err != nil {
					glog.Fatalf("pull | crypto.Decrypt [%s]", err)
				}
			}

			md5sum, err := crypto.MD5(f.Name)
			if err != nil {
				glog.Fatalf("pull | crypto.MD5 [%s]", err)
			}
			if f.MD5 != md5sum {
				err = crypto.Decrypt([]byte(cfg.Secret.Key), f.Name, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, f.Obfuscated))
				if err != nil {
					glog.Fatalf("pull | crypto.Decrypt [%s]", err)
				}
			}
		}

		glog.V(2).Infoln("state close")
		err = storage.Close()
		if err != nil {
			glog.Fatalf("pull | storage.Close [%s]", err)
		}
	} else {
		glog.Infoln("remote unchanged")
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
			glog.Fatalf("restore req missing [%s]", dir)
		}
	}

	glog.Info("store decrypt")
	store := fmt.Sprintf("%s/%s", *restorePath, "disposition-state.db")
	err := crypto.Decrypt(
		[]byte(cfg.Secret.Key),
		store,
		fmt.Sprintf("%s/%s/%s", *restorePath, "remote", cfg.Secret.Obfuscated),
	)
	if err != nil {
		glog.Fatalln("failed to decrypt state")
	}

	glog.V(2).Infoln("state init")
	storage, err := sqlite.New(store)
	if err != nil {
		glog.Fatalf("restore | sqlite.New [%s]", err)
	}

	storedFiles, err := storage.Files()
	if err != nil {
		glog.Fatalf("restore | storage.Files [%s]", err)
	}

	for _, storedFile := range storedFiles {
		err = crypto.Decrypt(
			[]byte(cfg.Secret.Key),
			fmt.Sprintf("%s/%s/%s", *restorePath, "plain", storedFile.Name[1:]),
			fmt.Sprintf("%s/%s/%s", *restorePath, "remote", storedFile.Obfuscated),
		)
		if err != nil {
			glog.Infof("failed to decrypt [%s -> %s]", storedFile.Obfuscated, storedFile.Name)
		}
	}

	glog.V(2).Infoln("state close")
	err = storage.Close()
	if err != nil {
		glog.Fatalf("restore | storage.Close [%s]", err)
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
