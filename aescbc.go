package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/sha3"
)

const (
	HashSize  = 32
	BlockSize = aes.BlockSize
)

var (
	PasswordWrongErr = "wrong password"
	CipherTextErr    = "ciphertext too short"
	PasswordEmptyErr = "password cannot be empty"
)

// AesCBCEncrypt CBC模式加密
func AesCBCEncrypt(origData []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}

	key16 := make([]byte, 16)
	copy(key16, key)
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}

	hash := Keccak256(origData)
	blockSize := block.BlockSize()
	origData = pkcs5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key16[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	hash = append(hash, crypted...)
	return hash, nil
}

// AesCBCDecrypt CBC模式解密
func AesCBCDecrypt(encrypted []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}

	key16 := make([]byte, 16)
	copy(key16, key)

	hash := encrypted[:HashSize]
	encrypted = encrypted[HashSize:]

	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key16[:blockSize])
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = pkcs5UnPadding(origData)
	if bytes.Equal(hash, Keccak256(origData)) {
		return origData, nil
	}
	return nil, errors.New(PasswordWrongErr)
}

// AesCBCEncryptToBase64 加密成base64格式秘钥
func AesCBCEncryptToBase64(origData string, key string) (string, error) {
	bytes, err := AesCBCEncrypt([]byte(origData), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// AesCBCDecryptFromBase64 base64形式秘钥解密
func AesCBCDecryptFromBase64(encrypted string, key string) (string, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	bytes, err := AesCBCDecrypt(decodeString, []byte(key))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func Keccak256(data ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range data {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}
