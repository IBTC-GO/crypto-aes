package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AesCFBEncrypt
func AesCFBEncrypt(origData []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	return encrypted, nil
}

// AesCFBDecrypt
func AesCFBDecrypt(encrypted []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(encrypted) < aes.BlockSize {
		return nil, errors.New(CipherTextErr)
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted, nil
}

// AesCFBEncryptToBase64
func AesCFBEncryptToBase64(origData string, key string) (string, error) {
	bytes, err := AesCFBEncrypt([]byte(origData), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// AesCFBDecryptFromBase64
func AesCFBDecryptFromBase64(encrypted string, key string) (string, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	bytes, err := AesCFBDecrypt(decodeString, []byte(key))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
