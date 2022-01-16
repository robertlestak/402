package vault

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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
	sec := map[string]interface{}{
		"type":        w.Type,
		"address":     w.Address,
		"public_key":  w.PublicKey,
		"private_key": w.PrivateKey,
		"txid":        w.Txid,
		"network":     w.Network,
	}
	err := WriteSecretWithFreshToken(fmt.Sprintf("%s/%s", os.Getenv("VAULT_KV_NAME"), w.Address), sec)
	if err != nil {
		return err
	}
	return nil
}

// GetByAddress gets wallet data from Vault by address
// this should only be called by trusted code as it will return private keys in plain text
func (w *Wallet) GetByAddress() error {
	l := log.WithFields(log.Fields{
		"action":  "GetByAddress",
		"type":    w.Type,
		"address": w.Address,
	})
	l.Info("GetByAddress")
	sec, err := GetSecretWithFreshToken(fmt.Sprintf("%s/%s", os.Getenv("VAULT_KV_NAME"), w.Address))
	if err != nil {
		l.Error(err)
		return err
	}
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
