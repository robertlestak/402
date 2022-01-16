package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"

	log "github.com/sirupsen/logrus"
)

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, keyID string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"func":  "EncryptWithPublicKey",
		"keyID": keyID,
	})
	l.Debug("start")
	defer l.Debug("end")
	hash := sha512.New()
	priv, err := GetKey(keyID)
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
	priv, err := GetKey(keyID)
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
