package payment

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/robertlestak/hpay/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PaymentRequest struct {
	gorm.Model
	PaymentID uint   `gorm:"index"`
	Amount    int64  `json:"amount"`
	Network   string `json:"network"`
	Address   string `json:"address"`
}

type Payment struct {
	gorm.Model
	Txid          string           `json:"txid"`
	Network       string           `json:"network"`
	Requests      []PaymentRequest `json:"requests"`
	Token         string           `json:"token" gorm:"-"`
	EncryptedMeta string           `json:"encrypted_meta" gorm:"-"`
}

type Tx struct {
	Status   int
	Hash     string
	ToAddr   string
	FromAddr string
	Value    int64
}

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
	if err := db.DB.Where("txid = ? AND network = ?", p.Txid, p.Network).First(p).Error; err != nil {
		l.WithError(err).Error("Failed to get payment")
		return err
	}
	return nil
}

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
	if _, verr := p.ValidateAPI(); verr != nil {
		l.WithError(verr).Error("Failed to validate tx")
		return verr
	}
	if serr := p.Save(); serr != nil {
		l.WithError(serr).Error("Failed to save payment")
		return serr
	}
	return nil
}

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
