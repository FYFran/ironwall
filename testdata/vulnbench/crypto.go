package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
)

// WEAK CRYPTO — MD5 for passwords
func hashPasswordMD5(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// WEAK CRYPTO — SHA1 for passwords
func hashPasswordSHA1(password string) string {
	hash := sha1.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// WEAK CRYPTO — DES (broken cipher)
func encryptDES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

// WEAK CRYPTO — Hardcoded IV (should be random per encryption)
var HardcodedIV = []byte("1234567890123456")

func encryptAESBad(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Static IV — vulnerability
	mode := cipher.NewCBCEncrypter(block, HardcodedIV)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// WEAK RANDOM — math/rand for crypto
func generateTokenBad() string {
	b := make([]byte, 32)
	rand.Read(b) // math/rand, NOT crypto/rand
	return base64.StdEncoding.EncodeToString(b)
}

// HARDCODED CONSTANTS
const (
	EncryptionKey = "my-static-aes-key!!"
	AdminPassword = "admin123!"
)

func main() {
	fmt.Println(hashPasswordMD5("password123"))
	fmt.Println(generateTokenBad())
}
