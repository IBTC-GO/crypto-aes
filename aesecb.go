package aes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
)

// AesECBEncrypt
func AesECBEncrypt(origData []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}
	cipher, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return nil, err
	}
	hash := Keccak256(origData)
	padding := pkcs5Padding(origData, BlockSize)
	encrypted := make([]byte, len(padding))
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], padding[bs:be])
	}
	encrypted = append(hash, encrypted...)
	return encrypted, nil
}

// AesECBDecrypt
func AesECBDecrypt(encrypted []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New(PasswordEmptyErr)
	}
	cipher, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return nil, err
	}

	hash := encrypted[:HashSize]
	encrypted = encrypted[HashSize:]
	decrypted := make([]byte, len(encrypted))
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	origData := pkcs5UnPadding(decrypted)

	// 校验密码
	if bytes.Equal(hash, Keccak256(origData)) {
		return origData, nil
	}
	return nil, errors.New(PasswordWrongErr)
}

// AesECBEncryptToBase64
func AesECBEncryptToBase64(origData string, key string) (string, error) {
	bytes, err := AesECBEncrypt([]byte(origData), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// AesECBDecryptFromBase64
func AesECBDecryptFromBase64(encrypted string, key string) (string, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	bytes, err := AesECBDecrypt(decodeString, []byte(key))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// generateKey
func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}
