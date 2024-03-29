package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

var (
	// Client is the vault client
	Client *api.Client
)

// insertSliceString inserts a string into a slice at a given index
func insertSliceString(a []string, index int, value string) []string {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

// NewClient creates a new vault client
func NewClient() (*api.Client, error) {
	l := log.WithFields(log.Fields{
		"action": "NewClient",
	})
	l.Info("NewClient")
	cfg := &api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	Client = client
	return client, nil
}

// GetToken gets a new token
func GetToken() (string, error) {
	l := log.WithFields(log.Fields{
		"action": "getToken",
	})
	l.Info("GetToken")
	// the role ID given to you by your administrator
	roleID := os.Getenv("VAULT_ROLE_ID")
	if roleID == "" {
		return "", fmt.Errorf("no role ID was provided in VAULT_ROLE_ID env var")
	}

	secretID := os.Getenv("VAULT_SECRET_ID")
	if secretID == "" {
		return "", fmt.Errorf("no role ID was provided in VAULT_SECRET_ID env var")
	}

	params := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := Client.Logical().Write("auth/approle/login", params)
	if err != nil {
		return "", err
	}
	Client.SetToken(resp.Auth.ClientToken)
	return resp.Auth.ClientToken, nil
}

// GetSecretWithFreshToken gets a secret from vault with a fresh token
func GetSecretWithFreshToken(p string) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"action": "GetSecretWithFreshToken",
		"path":   p,
	})
	l.Info("GetSecretWithFreshToken")
	_, err := GetToken()
	if err != nil {
		return nil, err
	}
	var sec map[string]interface{}

	pp := strings.Split(p, "/")
	pp = insertSliceString(pp, 1, "data")
	secret, err := Client.Logical().Read(strings.Join(pp, "/"))
	if err != nil {
		return sec, err
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return sec, err
	}

	return data, nil
}

// GetSecretRawWithFreshToken gets a secret from vault with a fresh token
func GetSecretRawWithFreshToken(p string) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"action": "GetSecretRawWithFreshToken",
		"path":   p,
	})
	l.Info("GetSecretRawWithFreshToken")
	_, err := GetToken()
	if err != nil {
		return nil, err
	}
	var sec map[string]interface{}

	pp := strings.Split(p, "/")
	pp = insertSliceString(pp, 1, "data")
	rp := strings.Join(pp, "/")
	l = l.WithField("rp", rp)
	l.Info("GetSecretRawWithFreshToken")
	secret, err := Client.Logical().Read(rp)
	if err != nil {
		return sec, err
	}
	if secret == nil {
		return nil, nil
	}
	return secret.Data, nil
}

// WriteSecretWithFreshToken writes a secret to vault with a fresh token
func WriteSecretWithFreshToken(p string, sec map[string]interface{}) error {
	l := log.WithFields(log.Fields{
		"action": "WriteSecretWithFreshToken",
		"path":   p,
	})
	l.Info("WriteSecretWithFreshToken")
	_, err := GetToken()
	if err != nil {
		return err
	}

	pp := strings.Split(p, "/")
	pp = insertSliceString(pp, 1, "data")
	data := map[string]interface{}{
		"data": sec,
	}
	_, werr := Client.Logical().Write(strings.Join(pp, "/"), data)
	if werr != nil {
		return werr
	}

	return nil
}

// ListSecrets lists the secrets at a given path
func ListSecrets(p string) ([]string, error) {
	if Client == nil {
		return nil, errors.New("vault client not initialized")
	}
	log.Printf("vault.ListSecrets(%+v)\n", p)
	if p == "" {
		return nil, errors.New("secret path required")
	}
	pp := strings.Split(p, "/")
	pp = insertSliceString(pp, 1, "metadata")
	p = strings.Join(pp, "/")
	secret, err := Client.Logical().List(p)
	if err != nil {
		log.Printf("vault.ListSecrets(%+v) error: %v\n", p, err)
		return nil, err
	}
	log.Printf("vault.ListSecrets(%+v) returned %+v\n", p, secret)
	if secret == nil {
		log.Printf("vault.ListSecrets(%+v) error: secret is nil\n", p)
		return nil, nil
	}
	k := secret.Data["keys"].([]interface{})
	var keys []string
	for _, v := range k {
		keys = append(keys, v.(string))
	}
	return keys, nil
}

// ListSecretsRetry lists the secrets at a given path with retry
func ListSecretsRetry(p string) ([]string, error) {
	var keys []string
	var err error
	keys, err = ListSecrets(p)
	if err != nil {
		_, terr := GetToken()
		if terr != nil {
			return keys, terr
		}
		keys, err = ListSecrets(p)
		if err != nil {
			return keys, err
		}
	}
	return keys, err
}

// DeleteSecret deletes a secret from path p
func DeleteSecret(p string) error {
	l := log.WithFields(log.Fields{
		"path": p,
	})
	l.Printf("vault.DeleteSecret(%+v)", p)
	if p == "" {
		l.Printf("vault.DeleteSecret(%+v) error: %v", p, errors.New("secret path required"))
		return errors.New("secret path required")
	}
	pp := strings.Split(p, "/")
	if len(pp) < 2 {
		l.Printf("vault.DeleteSecret(%+v) error: %v", p, errors.New("secret path must be in kv/path/to/secret format"))
		return errors.New("secret path must be in kv/path/to/secret format")
	}
	pp = insertSliceString(pp, 1, "metadata")
	p = strings.Join(pp, "/")
	_, err := Client.Logical().Delete(p)
	if err != nil {
		l.Printf("vault.Delete(%+v) error: %v\n", p, err)
		return err
	}
	l.Printf("vault.Delete(%+v) success\n", p)
	return nil
}
