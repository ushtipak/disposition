package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

func MD5(fileName string) (md5sum string, err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return
	}

	h := md5.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return
	}

	err = f.Close()
	if err != nil {
		return
	}

	md5sum = hex.EncodeToString(h.Sum(nil)[:16])
	return
}

func Encrypt(key []byte, filePlain, fileEncrypted string) (err error) {
	text, err := ioutil.ReadFile(filePlain)
	if err != nil {
		return
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}

	encryptedText := gcm.Seal(nonce, nonce, text, nil)
	err = ioutil.WriteFile(fileEncrypted, encryptedText, 0777)
	return
}

func Decrypt(key []byte, filePlain, fileEncrypted string) (err error) {
	fmt.Printf("    filePlain: %s\n", filePlain)
	fmt.Printf("fileEncrypted: %s\n", fileEncrypted)

	encryptedText, err := ioutil.ReadFile(fileEncrypted)
	if err != nil {
		return
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		return errors.New("len(encryptedText) < nonceSize")
	}

	nonce, encoded := encryptedText[:nonceSize], encryptedText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, encoded, nil)
	if err != nil {
		return
	}

	dir, file := filepath.Split(filePlain)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", dir, file), plainText, 0777)
	if err != nil {
		return
	}

	return
}
