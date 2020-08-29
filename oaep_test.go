package oaep

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "crypto/sha256"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

func openSession(module p11.Module, userPin string, tokenLabel string) (p11.Session, error) {
	slots, err := module.Slots()
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %v", err)
	}
	for _, slot := range slots {
		tokenInfo, err := slot.TokenInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get slot %d token info: %v", slot.ID(), err)
		}
		if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			continue
		}
		if strings.TrimRight(tokenInfo.Label, "\x00") != tokenLabel {
			continue
		}
		session, err := slot.OpenSession()
		if err != nil {
			return nil, fmt.Errorf("failed to open session into slot %d token %s: %v", slot.ID(), tokenInfo.Label, err)
		}
		err = session.Login(userPin)
		if err != nil {
			session.Close()
			return nil, fmt.Errorf("failed to login into slot %d token %s: %v", slot.ID(), tokenInfo.Label, err)
		}
		return session, nil
	}
	return nil, fmt.Errorf("token %s not found", tokenLabel)
}

func TestEncrypt(t *testing.T) {
	random := rand.Reader
	key, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("hello world")

	ciphertext, err := Encrypt(crypto.SHA256.New(), random, &key.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(ciphertext) != key.Size() {
		t.Fatalf("Ciphext text length is invalid, expected %d but got %d", key.Size(), len(ciphertext))
	}

	result, err := decryptTest(crypto.SHA256.New(), random, key.Size(), key, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, result) {
		t.Fatalf("Resulting plaintext was unexpected, expected %s but got %s", plaintext, result)
	}
}

func TestDecrypt_EncryptedWithGoRSAEncryptOAEP(t *testing.T) {
	random := rand.Reader
	key, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("hello world")

	ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), random, &key.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(ciphertext) != key.Size() {
		t.Fatalf("Ciphext text length is invalid, expected %d but got %d", key.Size(), len(ciphertext))
	}

	result, err := decryptTest(crypto.SHA256.New(), random, key.Size(), key, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, result) {
		t.Fatalf("Resulting plaintext was unexpected, expected %s but got %s", plaintext, result)
	}
}

func TestDecrypt(t *testing.T) {
	userPin := ""
	if p := os.Getenv("TEST_PKCS11_USER_PIN"); p != "" {
		userPin = p
	}

	if userPin == "" {
		t.Log("Skipping because the environment variable TEST_PKCS11_USER_PIN is not defined.")
		t.SkipNow()
	}

	pkcs11LibraryPath := "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	if p := os.Getenv("TEST_PKCS11_LIBRARY_PATH"); p != "" {
		pkcs11LibraryPath = p
	}

	tokenLabel := "test"
	if p := os.Getenv("TEST_PKCS11_TOKEN_LABEL"); p != "" {
		tokenLabel = p
	}

	keyLabel := "test-rsa-2048"
	if p := os.Getenv("TEST_PKCS11_KEY_LABEL"); p != "" {
		keyLabel = p
	}

	module, err := p11.OpenModule(pkcs11LibraryPath)
	if err != nil {
		t.Fatalf("failed to open pkcs11 module %s: %v", pkcs11LibraryPath, err)
	}

	session, err := openSession(module, userPin, tokenLabel)
	if err != nil {
		t.Fatalf("failed to open session to token %s: %v", tokenLabel, err)
	}
	defer session.Close()

	publicKey, privateKey, err := GetKey(session, keyLabel)
	if err != nil {
		t.Fatalf("Key %s not found in HSM: %v", keyLabel, err)
	}

	random := rand.Reader

	plaintext := []byte("hello world")

	ciphertext, err := Encrypt(crypto.SHA256.New(), random, publicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(ciphertext) != publicKey.Size() {
		t.Fatalf("Ciphext text length is invalid, expected %d but got %d", publicKey.Size(), len(ciphertext))
	}

	result, err := Decrypt(crypto.SHA256.New(), random, publicKey.Size(), privateKey, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, result) {
		t.Fatalf("Resulting plaintext was unexpected, expected %s but got %s", plaintext, result)
	}
}
