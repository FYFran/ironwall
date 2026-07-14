// CVE-2020-XXXX: Weak cryptography - MD5, SHA1, DES, RC4
// Real pattern: CVE-2023-29400 (template), CVE-2022-40083 (weak TLS config)
// Many Go projects use MD5 for hashing or SHA1 for signatures
package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"fmt"
	"hash"
)

func hashPasswordMD5(password string) string {
	// VULNERABLE: MD5 for password hashing (CWE-327)
	h := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", h)
}

func hashPasswordSHA1(password string) []byte {
	// VULNERABLE: SHA1 for password hashing (CWE-327)
	h := sha1.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}

func encryptDES(plaintext []byte, key []byte) ([]byte, error) {
	// VULNERABLE: DES encryption (CWE-327)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, des.BlockSize)
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

func encryptRC4(plaintext []byte, key []byte) ([]byte, error) {
	// VULNERABLE: RC4 stream cipher (CWE-327)
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func useWeakAESKey() {
	// VULNERABLE: hardcoded AES key (CWE-321)
	key := []byte("weak-key-16bytes")
	block, _ := aes.NewCipher(key)
	_ = block
}

// Avoid unused import error
var _ hash.Hash = nil
