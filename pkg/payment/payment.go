package payment

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/pkg/vault"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// PaymentRequest contains a single network payment request
type PaymentRequest struct {
	gorm.Model
	PaymentID uint    `gorm:"index"`
	Amount    float64 `json:"amount"`
	Network   string  `json:"network"`
	Address   string  `json:"address"`
}

// Payment contains a payment for a request, including all the configured network payment requests
// when returned from a user, the txid and network will be filled, and these will then be validated
// on the chain before saving to the database
type Payment struct {
	gorm.Model
	Txid          string            `gorm:"uniqueIndex:idx_txid_network" json:"txid"`
	Network       string            `gorm:"uniqueIndex:idx_txid_network" json:"network"`
	Requests      []*PaymentRequest `json:"requests"`
	Token         string            `json:"token,omitempty" gorm:"-"`
	MetaHash      string            `json:"meta_hash,omitempty" gorm:"-"`
	EncryptedMeta string            `json:"encrypted_meta,omitempty" gorm:"-"`
	Tenant        string            `json:"tenant"`
}

// Tx is a generic representation of a transaction on the blockchain
type Tx struct {
	Status   int
	Hash     string
	ToAddr   string
	FromAddr string
	Value    float64
}

// CreateMetaHash creates a hash of the payment meta data
func (p *Payment) CreateMetaHash() error {
	jd, jerr := json.Marshal(p.Requests)
	if jerr != nil {
		return jerr
	}
	data := []byte(p.EncryptedMeta + string(jd) + os.Getenv("HASH_SECRET"))
	hash := sha256.Sum256(data)
	p.MetaHash = fmt.Sprintf("%x", hash[:])
	return nil
}

// ValidateMetaHash validates the meta hash with the payment meta data
func (p *Payment) ValidateMetaHash() error {
	l := log.WithFields(log.Fields{
		"action":  "Payment.ValidateMetaHash",
		"payment": p,
	})
	l.Debug("start")
	if p.MetaHash == "" {
		l.Error("meta hash is empty")
		return errors.New("meta hash is empty")
	}
	if p.EncryptedMeta == "" {
		l.Error("encrypted meta is empty")
		return errors.New("encrypted meta is empty")
	}
	tp := p
	terr := tp.CreateMetaHash()
	if terr != nil {
		l.WithError(terr).Error("Failed to create meta hash")
		return terr
	}
	if p.MetaHash != tp.MetaHash {
		l.Error("meta hash is not valid")
		return errors.New("meta hash is not valid")
	}
	l.Debug("meta hash is valid")
	return nil
}

// Save saves the payment to the database
func (p *Payment) Save() error {
	l := log.WithFields(log.Fields{
		"action":  "Payment.Save",
		"payment": p,
	})
	l.Debug("start")
	if err := db.DB.Create(p).Error; err != nil {
		l.WithError(err).Error("Failed to save payment")
		return err
	}
	return nil
}

// Get gets the payment from the database
func (p *Payment) Get() error {
	l := log.WithFields(log.Fields{
		"action":  "Payment.Get",
		"payment": p,
	})
	l.Debug("start")
	if p.Txid == "" {
		l.Error("txid is empty")
		return errors.New("txid is empty")
	}
	if p.Network == "" {
		l.Error("network is empty")
		return errors.New("network is empty")
	}
	if p.Tenant == "" {
		if err := db.DB.Where("txid = ? AND network = ?", p.Txid, p.Network).First(p).Error; err != nil {
			l.WithError(err).Error("Failed to get payment")
			return err
		}
	} else {
		if err := db.DB.Where("txid = ? AND network = ? AND tenant = ?", p.Txid, p.Network, p.Tenant).First(p).Error; err != nil {
			l.WithError(err).Error("Failed to get payment")
			return err
		}
	}
	return nil
}

// ValidateAPI validates the payment request against the blockchain through
// a network call to a blockchain index API
func (p *Payment) ValidateAPI() (Tx, error) {
	l := log.WithFields(log.Fields{
		"action":  "Payment.ValidateAPI",
		"payment": p,
	})
	var tx Tx
	var txs []Tx
	l.Debug("start")
	if p.Txid == "" {
		l.Error("txid is empty")
		return tx, errors.New("txid is empty")
	}
	if p.Network == "" {
		l.Error("network is empty")
		return tx, errors.New("network is empty")
	}
	c := &http.Client{}
	req, err := http.NewRequest("GET", os.Getenv("PAYMENT_VALIDATE_API")+"/txs", nil)
	if err != nil {
		l.WithError(err).Error("Failed to create request")
		return tx, err
	}
	q := req.URL.Query()
	q.Add("txid", p.Txid)
	q.Add("chain", p.Network)
	req.URL.RawQuery = q.Encode()
	resp, err := c.Do(req)
	if err != nil {
		l.WithError(err).Error("Failed to send request")
		return tx, err
	}
	l.WithField("status", resp.StatusCode).Debug("Response status")
	if resp.StatusCode != http.StatusOK {
		l.WithField("status", resp.StatusCode).Error("Failed to validate tx")
		return tx, errors.New("failed to validate tx")
	}
	if err := json.NewDecoder(resp.Body).Decode(&txs); err != nil {
		l.WithError(err).Error("Failed to decode response")
		return tx, err
	}
	l = l.WithField("txs", len(txs))
	for _, tx := range txs {
		if tx.Hash == p.Txid && tx.Status != 1 {
			l.Error("txid is not valid")
			return tx, errors.New("txid is not valid")
		} else if tx.Hash == p.Txid && tx.Status == 1 {
			l.WithField("tx", tx).Debug("Tx is a valid tx")
			l = l.WithField("reqs", len(p.Requests))
			for _, reqs := range p.Requests {
				l = l.WithFields(log.Fields{
					"tx":          tx,
					"network":     p.Network,
					"address":     reqs.Address,
					"tx.Value":    tx.Value,
					"reqs.Amount": reqs.Amount,
				})
				l.Debug("check")
				if reqs.Network == p.Network && reqs.Address == tx.ToAddr && tx.Value >= reqs.Amount {
					l.Debug("Tx is valid, and to address is valid")
					return tx, nil
				}
			}
		}
	}
	l.Debug("no valid tx found")
	return Tx{}, errors.New("no valid tx found")
}

// Validate both validates a payment and saves the data to prevent double validation
// should probably rename to be more descriptive
func (p *Payment) Validate() error {
	l := log.WithFields(log.Fields{
		"action":  "Payment.Validate",
		"payment": p,
	})
	l.Debug("start")
	if p.Txid == "" {
		l.Error("txid is empty")
		return errors.New("txid is empty")
	}
	if p.Network == "" {
		l.Error("network is empty")
		return errors.New("network is empty")
	}
	if err := p.Get(); err != nil && err != gorm.ErrRecordNotFound {
		l.WithError(err).Error("p.Get failed")
		return err
	} else if p.ID != 0 {
		l.Debug("payment already exists")
		return errors.New("payment already exists")
	}
	if mherr := p.ValidateMetaHash(); mherr != nil {
		l.WithError(mherr).Error("Failed to validate meta hash")
		return mherr
	}
	var tx Tx
	var verr error
	if tx, verr = p.ValidateAPI(); verr != nil {
		l.WithError(verr).Error("Failed to validate tx")
		return verr
	}
	if serr := p.Save(); serr != nil {
		l.WithError(serr).Error("Failed to save payment")
		return serr
	}
	if os.Getenv("VAULT_ENABLE") == "true" {
		wallet := &vault.Wallet{
			Address: tx.ToAddr,
			Network: p.Network,
			Txid:    tx.Hash,
		}
		if err := wallet.AddTxData(); err != nil {
			l.WithError(err).Error("Failed to add tx data")
			return err
		}
	}
	return nil
}

// HandleCheckPaymentValid handles the check payment valid route
func HandleCheckPaymentValid(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleCheckPaymentValid",
	})
	l.Debug("start")
	defer l.Debug("end")
	var payment Payment
	if err := json.NewDecoder(r.Body).Decode(&payment); err != nil {
		l.WithError(err).Error("Failed to decode payment")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := payment.Validate(); err != nil {
		l.WithError(err).Error("Failed to validate payment")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
