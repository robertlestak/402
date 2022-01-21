package vault

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/mux"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	log "github.com/sirupsen/logrus"
)

// Wallet is a struct for holding wallet data
type Wallet struct {
	Type       string `json:"type"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Txid       string `json:"txid"`
	Network    string `json:"network"`
	Tenant     string `json:"tenant"`
}

type walletJob struct {
	w     *Wallet
	Error error
}

// NewWallet creates a new wallet and stores it to Vault
func NewWallet() (*Wallet, error) {
	w, err := NewEphemeralWallet()
	if err != nil {
		return nil, err
	}
	w.Type = "address"
	werr := w.WriteVault()
	if werr != nil {
		return w, werr
	}
	return w, nil
}

// NewTenantWallet creates a new wallet for a tenant and stores it to Vault
func NewTenantWallet(tenant string, network string) (*Wallet, error) {
	if tenant == "" {
		return nil, errors.New("tenant is empty")
	}
	w, err := NewEphemeralWallet()
	if err != nil {
		return nil, err
	}
	w.Type = "address"
	w.Tenant = tenant
	w.Network = network
	werr := w.WriteVault()
	if werr != nil {
		return w, werr
	}
	return w, nil
}

// NewEphemeralWallet creates a new wallet but does not store it
func NewEphemeralWallet() (*Wallet, error) {
	w := &Wallet{}
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return w, err
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	w.PrivateKey = hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return w, errors.New("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	w.PublicKey = hexutil.Encode(publicKeyBytes)[4:]

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	w.Address = address
	w.Type = "address"
	return w, nil
}

// WriteVault writes wallet data to Vault
func (w *Wallet) WriteVault() error {
	l := log.WithFields(log.Fields{
		"action": "WriteVault",
		"type":   w.Type,
	})
	l.Info("WriteVault")
	if w.Tenant != "" {
		w.Tenant = os.Getenv("DEFAULT_TENANT")
		l.Info("WriteVault default tenant")
	}
	sec := map[string]interface{}{
		"type":        w.Type,
		"address":     w.Address,
		"public_key":  w.PublicKey,
		"private_key": w.PrivateKey,
		"txid":        w.Txid,
		"network":     w.Network,
		"tenant":      w.Tenant,
	}
	err := WriteSecretWithFreshToken(fmt.Sprintf("%s/%s/%s", os.Getenv("VAULT_KV_NAME"), w.Tenant, w.Address), sec)
	if err != nil {
		return err
	}
	return nil
}

func (w *Wallet) ParseMap(sec map[string]interface{}) error {
	l := log.WithFields(log.Fields{
		"action": "ParseMap",
		"type":   w.Type,
	})
	l.Info("ParseMap")
	w.Type = sec["type"].(string)
	w.Address = sec["address"].(string)
	w.PublicKey = sec["public_key"].(string)
	w.PrivateKey = sec["private_key"].(string)
	if txid, ok := sec["txid"]; ok {
		w.Txid = txid.(string)
	}
	if network, ok := sec["network"]; ok {
		w.Network = network.(string)
	}
	if tenant, ok := sec["tenant"]; ok {
		w.Tenant = tenant.(string)
	}
	l.Info("ParseMap parsed")
	return nil
}

// GetByAddress gets wallet data from Vault by address
// this should only be called by trusted code as it will return private keys in plain text
func (w *Wallet) GetByAddress() error {
	l := log.WithFields(log.Fields{
		"action":  "GetByAddress",
		"type":    w.Type,
		"address": w.Address,
		"tenant":  w.Tenant,
	})
	l.Info("GetByAddress")
	if w.Tenant == "" {
		w.Tenant = os.Getenv("DEFAULT_TENANT")
		l.Info("GetByAddress default tenant")
	}
	sec, err := GetSecretWithFreshToken(fmt.Sprintf("%s/%s/%s", os.Getenv("VAULT_KV_NAME"), w.Tenant, w.Address))
	if err != nil {
		l.Error(err)
		return err
	}
	if w.ParseMap(sec) != nil {
		l.Error(err)
		return err
	}
	l.Info("GetByAddress retrieved")
	return nil
}

// AddTxData retrieves a wallet from vault by address and adds txid and network
func (w *Wallet) AddTxData() error {
	l := log.WithFields(log.Fields{
		"action":  "AddTxData",
		"type":    w.Type,
		"address": w.Address,
		"txid":    w.Txid,
		"network": w.Network,
		"tenant":  w.Tenant,
	})
	l.Info("AddTxData")
	if w.Txid == "" {
		l.Error("txid is empty")
		return errors.New("txid is empty")
	}
	if w.Network == "" {
		l.Error("network is empty")
		return errors.New("network is empty")
	}
	tw := w
	if gerr := tw.GetByAddress(); gerr != nil {
		l.Error(gerr)
		return gerr
	}
	tw.Network = w.Network
	tw.Txid = w.Txid
	if werr := tw.WriteVault(); werr != nil {
		l.Error(werr)
		return werr
	}
	l.Info("AddTxData added")
	return nil
}

func getSecretWorker(jobs chan walletJob, res chan walletJob) {
	for j := range jobs {
		if err := j.w.GetByAddress(); err != nil {
			j.Error = err
			res <- j
			continue
		}
		res <- j
	}
}

func GetAllWalletsForTenant(t string) ([]Wallet, error) {
	l := log.WithFields(log.Fields{
		"action": "GetAllWalletsForTenant",
		"tenant": t,
	})
	l.Info("GetAllWalletsForTenant")
	wallets := []Wallet{}
	if t == "" {
		t = os.Getenv("DEFAULT_TENANT")
		l.Info("GetAllWalletsForTenant default tenant")
	}
	secs, err := ListSecretsRetry(fmt.Sprintf("%s/%s", os.Getenv("VAULT_KV_NAME"), t))
	if err != nil {
		l.Error(err)
		return wallets, err
	}
	jobs := make(chan walletJob, len(secs))
	res := make(chan walletJob, len(secs))
	for w := 1; w <= 10; w++ {
		go getSecretWorker(jobs, res)
	}
	for _, sec := range secs {
		w := Wallet{
			Address: sec,
			Tenant:  t,
		}
		jobs <- walletJob{
			w: &w,
		}
	}
	close(jobs)
	for a := 0; a < len(secs); a++ {
		r := <-res
		if r.Error != nil {
			l.Error(r.Error)
			return wallets, r.Error
		}
		wallets = append(wallets, *r.w)
	}
	l.Info("GetAllWalletsForTenant retrieved")
	return wallets, nil
}

func GetDesiredWalletsForTenant(t string, secs []string) ([]Wallet, error) {
	l := log.WithFields(log.Fields{
		"action":  "GetDesiredWalletsForTenant",
		"tenant":  t,
		"desired": secs,
	})
	l.Info("GetDesiredWalletsForTenant")
	wallets := []Wallet{}
	if t == "" {
		t = os.Getenv("DEFAULT_TENANT")
		l.Info("GetDesiredWalletsForTenant default tenant")
	}
	if len(secs) == 0 {
		l.Error("desired is empty")
		return wallets, errors.New("desired is empty")
	}
	jobs := make(chan walletJob, len(secs))
	res := make(chan walletJob, len(secs))
	for w := 1; w <= 10; w++ {
		go getSecretWorker(jobs, res)
	}
	for _, sec := range secs {
		w := Wallet{
			Address: sec,
			Tenant:  t,
		}
		jobs <- walletJob{
			w: &w,
		}
	}
	close(jobs)
	for a := 0; a < len(secs); a++ {
		r := <-res
		if r.Error != nil {
			l.Error(r.Error)
			return wallets, r.Error
		}
		wallets = append(wallets, *r.w)
	}
	l.Info("GetDesiredWalletsForTenant retrieved")
	return wallets, nil
}

func HandleGetWalletsForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleGetWalletsForTenant",
	})
	l.Info("HandleGetWalletsForTenant")
	if !auth.RequestAuthorized(r) {
		l.Error("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	tenant := r.Header.Get(utils.HeaderPrefix() + "tenant")
	var desiredAddresses []string
	if err := json.NewDecoder(r.Body).Decode(&desiredAddresses); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	wallets, err := GetDesiredWalletsForTenant(tenant, desiredAddresses)
	if err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if jerr := json.NewEncoder(w).Encode(wallets); jerr != nil {
		l.Error(jerr)
		http.Error(w, jerr.Error(), http.StatusInternalServerError)
		return
	}
}

func HandleListWalletsForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleListWalletsForTenant",
	})
	l.Info("HandleistWalletsForTenant")
	tenant := r.Header.Get(utils.HeaderPrefix() + "tenant")
	if tenant == "" {
		l.Error("HandleListWalletsForTenant no tenant")
		tenant = os.Getenv("DEFAULT_TENANT")
	}
	if !auth.RequestAuthorized(r) {
		l.Error("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	addresses, err := ListSecretsRetry(path.Join(os.Getenv("VAULT_KV_NAME"), tenant))
	if err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if jerr := json.NewEncoder(w).Encode(addresses); jerr != nil {
		l.Error(jerr)
		http.Error(w, jerr.Error(), http.StatusInternalServerError)
		return
	}
}

func DeleteSecretForTenant(tenant string, address string) error {
	l := log.WithFields(log.Fields{
		"action":  "DeleteSecretForTenant",
		"tenant":  tenant,
		"address": address,
	})
	l.Info("DeleteSecretForTenant")
	if tenant == "" {
		l.Error("tenant is empty")
		return errors.New("tenant is empty")
	}
	if address == "" {
		l.Error("address is empty")
		return errors.New("address is empty")
	}
	if err := DeleteSecret(fmt.Sprintf("%s/%s/%s", os.Getenv("VAULT_KV_NAME"), tenant, address)); err != nil {
		l.Error(err)
		return err
	}
	l.Info("DeleteSecretForTenant deleted")
	return nil
}

func HandleDeleteSecretForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleDeleteSecretForTenant",
	})
	l.Info("HandleDeleteSecretForTenant")
	tenant := r.Header.Get(utils.HeaderPrefix() + "tenant")
	if !auth.RequestAuthorized(r) {
		l.Error("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	address := vars["address"]
	if address == "" {
		l.Error("address is empty")
		http.Error(w, "address is empty", http.StatusBadRequest)
		return
	}
	if err := DeleteSecretForTenant(tenant, address); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
