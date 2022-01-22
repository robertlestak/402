package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"

	log "github.com/sirupsen/logrus"
)

var (
	// TokenSignKeys is a map of key IDs to private keys
	TokenSignKeys = make(map[string]*rsa.PrivateKey)
	// MessageSignKeys is a map of key IDs to private keys
	MessageSignKeys = make(map[string]*rsa.PrivateKey)
)

// GetMessageKey returns the key for the given key ID
func GetMessageKey(id string) (*rsa.PrivateKey, error) {
	l := log.WithFields(log.Fields{
		"func": "GetMessageKey",
	})
	l.Println("start")
	if key, ok := MessageSignKeys[id]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key not found: %s", id)
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, keyID string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"func":  "EncryptWithPublicKey",
		"keyID": keyID,
	})
	l.Debug("start")
	defer l.Debug("end")
	hash := sha512.New()
	priv, err := GetMessageKey(keyID)
	if err != nil {
		l.WithError(err).Error("Failed to get key")
		return nil, err
	}
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &priv.PublicKey, msg, nil)
	if err != nil {
		l.WithError(err).Error("Failed to encrypt")
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, keyID string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"func":  "DecryptWithPrivateKey",
		"keyID": keyID,
	})
	l.Debug("start")
	defer l.Debug("end")
	hash := sha512.New()
	priv, err := GetMessageKey(keyID)
	if err != nil {
		l.WithError(err).Error("Failed to get key")
		return nil, err
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return plaintext, nil
}
