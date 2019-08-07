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
	cfgFile       = "/opt/disposition/disposition.yml"
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

	f, err := os.Open(cfgFile)
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

func main() {
	if *poolingOption == "restore" {
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
			glog.Fatalf("main | sqlite.New [%s]", err)
		}

		storedFiles, err := storage.Files()
		if err != nil {
			glog.Fatalf("main | storage.Files [%s]", err)
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
			glog.Fatalf("main | storage.Close [%s]", err)
		}
	} else {
		glog.V(2).Infoln("state init")
		storage, err := sqlite.New(cfg.Secret.State)
		if err != nil {
			glog.Fatalf("main | sqlite.New [%s]", err)
		}

		if *poolingOption == "push" {
			storedFiles, err := storage.Files()
			if err != nil {
				glog.Fatalf("main | storage.Files [%s]", err)
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
						glog.Fatalf("main | storage.UUIDs [%s]", err)
					}

					obfuscated := newUnique(UUIDs)
					err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
					if err != nil {
						glog.Fatalf("main | crypto.Encrypt [%s]", err)
					}

					md5sum, err := crypto.MD5(scannedFile)
					if err != nil {
						glog.Fatalf("main | crypto.MD5 [%s]", err)
					}

					err = storage.Add(scannedFile, md5sum, obfuscated)
					if err != nil {
						glog.Fatalf("main | storage.Add [%s]", err)
					}

					syncRequired = true
				} else {
					if updated {
						glog.Infof("updated [%s]", scannedFile)
						obfuscated, err := storage.Obfuscated(scannedFile)
						if err != nil {
							glog.Fatalf("main | storage.Obfuscated [%s]", err)
						}

						err = crypto.Encrypt([]byte(cfg.Secret.Key), scannedFile, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscated))
						if err != nil {
							glog.Fatalf("main | crypto.Encrypt [%s]", err)
						}

						md5sum, err := crypto.MD5(scannedFile)
						if err != nil {
							glog.Fatalf("main | crypto.MD5 [%s]", err)
						}

						err = storage.Update(scannedFile, md5sum)
						if err != nil {
							glog.Fatalf("main | storage.Update [%s]", err)
						}
						syncRequired = true
					}
				}
			}

			glog.Infof("sync required [%v]", syncRequired)
			if syncRequired {
				err := crypto.Encrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
				if err != nil {
					glog.Fatalf("main | crypto.Encrypt [%s]", err)
				}

				err = repo.Push(cfg.Root.Encrypted)
				if err != nil {
					glog.Fatalf("main | repo.Push [%s]", err)
				}
			}
		}

		if *poolingOption == "pull" {
			obfuscatedFiles, stateChanged, err := repo.Pull(cfg.Root.Encrypted, cfg.Secret.Obfuscated)
			if err != nil {
				glog.Fatalf("main | repo.Pull [%s]", err)
			}
			fmt.Printf("obfuscatedFiles: %s\n", obfuscatedFiles)
			fmt.Printf("stateChanged: %v\n", stateChanged)

			if stateChanged {
				err = storage.Close()
				if err != nil {
					glog.Fatalf("main | storage.Close [%s]", err)
				}

				err = crypto.Decrypt([]byte(cfg.Secret.Key), cfg.Secret.State, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, cfg.Secret.Obfuscated))
				if err != nil {
					glog.Fatalf("main | crypto.Decrypt [%s]", err)
				}

				storage, err = sqlite.New(cfg.Secret.State)
				if err != nil {
					glog.Fatalf("main | sqlite.New [%s]", err)
				}
			}

			for _, obfuscatedFile := range obfuscatedFiles {
				filePlain, err := storage.Name(obfuscatedFile)
				if err != nil {
					glog.Fatalf("main | storage.Name [%s]", err)
				}

				err = crypto.Decrypt([]byte(cfg.Secret.Key), filePlain, fmt.Sprintf("%s/%s", cfg.Root.Encrypted, obfuscatedFile))
				if err != nil {
					glog.Fatalf("main | crypto.Decrypt [%s]", err)
				}
			}
		}

		glog.V(2).Infoln("state close")
		err = storage.Close()
		if err != nil {
			glog.Fatalf("main | storage.Close [%s]", err)
		}
	}
}
