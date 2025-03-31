package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
)

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// https://astaxie.gitbooks.io/build-web-application-with-golang/en/09.6.html
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("error; encryption.go: Encrypt() -> aes.NewCipher()")
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.New("error; encryption.go: Encrypt() -> cipher.NewGCM()")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("error; encryption.go: Encrypt() -> io.ReadFull()")
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println("error; encryption.go: Decrypt() -> aes.NewCipher()")
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("error; encryption.go: Decrypt() -> cipher.NewGCM()")
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short; encryption.go: Decrypt() -> gcm.NonceSize()")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func Encode64(data []byte) string {
	string64 := base64.StdEncoding.EncodeToString(data)
	return string64
}

func Decode64(string64 string) ([]byte, error) {
	byteArray, err := base64.StdEncoding.DecodeString(string64)
	if err != nil {
		log.Println("error; utils.go: Decode64() -> base64.StdEncoding.DecodeString()")
		return byteArray, err
	}
	return byteArray, nil
}
