package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/websocket"
	"github.com/robertlestak/hpay/internal/pubsub"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/upstream"
	log "github.com/sirupsen/logrus"
)

func decryptMetaFromPayment(payment *payment.Payment) (hpay.Meta, error) {
	l := log.WithFields(log.Fields{
		"action": "decryptMetaFromPayment",
	})
	l.Info("start")
	meta := hpay.Meta{}
	if payment.EncryptedMeta == "" {
		l.Error("encrypted meta is empty")
		return meta, errors.New("encrypted meta is empty")
	}
	if payment.MetaHash == "" {
		l.Error("meta hash is empty")
		return meta, errors.New("meta hash is empty")
	}
	var err error
	bdata, berr := base64.StdEncoding.DecodeString(payment.EncryptedMeta)
	if berr != nil {
		l.Error("base64 decode:", berr)
		return meta, errors.New("base64 decode: " + berr.Error())
	}
	decryptedMeta, derr := auth.DecryptWithPrivateKey(bdata, utils.MessageKeyID())
	if derr != nil {
		l.Error("decrypt meta:", derr)
		return meta, errors.New("decrypt meta: " + derr.Error())
	}
	err = json.Unmarshal(decryptedMeta, &meta)
	if err != nil {
		l.Error("unmarshal meta:", err)
		return meta, errors.New("unmarshal meta: " + err.Error())
	}
	l.Info("meta:", meta)
	return meta, nil
}

func addPaymentRequestJob(id string, payment *payment.Payment, pr *payment.PaymentRequest) error {
	l := log.WithFields(log.Fields{
		"action": "addPaymentRequestJob",
	})
	l.Info("start")
	if pr.Address == "" || pr.Amount == 0 {
		l.Error("address is empty")
		return errors.New("address is empty")
	}
	if jerr := pubsub.AddAddressJob(id, pr.Address, pr.Network, payment.EncryptedMeta, payment.MetaHash); jerr != nil {
		l.Error("add address job:", jerr)
		return errors.New("add address job: " + jerr.Error())
	}
	return nil
}

func waitForConfirmation(id string, conn *websocket.Conn, subscriber *redis.PubSub, meta hpay.Meta, payment *payment.Payment) error {
	l := log.WithFields(log.Fields{"func": "waitForConfirmation"})
	l.Info("start")
	for {
		l.Infof("Waiting for completion of payment: %s", payment)
		msg, err := subscriber.ReceiveMessage()
		if err != nil {
			l.Error(err)
			return err
		}
		l.Infof("Got message: %s", msg.Payload)

		if strings.HasPrefix(msg.Payload, "error:") {
			parts := strings.Split(msg.Payload, ":")
			return errors.New(strings.Join(parts[:len(parts)-1], ":"))
		}
		meta.Payment = payment
		if !clientAccessClaims(meta.Claims) {
			us := &upstream.Upstream{}
			us.ID = meta.UpstreamID
			if err := us.GetByID(); err != nil {
				l.Error(err)
				return err
			}
			if verr := hpay.ValidateRequestedClaims(meta.Claims, us); verr != nil {
				l.WithError(verr).Error("Failed to validate claims")
				if err := conn.WriteJSON(wsMessage{Message: "Failed to validate claims"}); err != nil {
					l.Println("write:", err)
					return err
				}
				return verr
			}
			cleanupSocket(id)
		}
		token, terr := meta.GenerateToken()
		if terr != nil {
			l.Error("generate token:", terr)
			if err := conn.WriteJSON(wsMessage{Message: "generate token"}); err != nil {
				l.Println("write:", err)
				return err
			}
			return terr
		}
		if token == "" {
			l.Error("token is empty")
			if err := conn.WriteJSON(wsMessage{Message: "token empty"}); err != nil {
				l.Println("write:", err)
				return err
			}
			return errors.New("token is empty")
		}
		mess := &wsMessage{
			Type:    "auth",
			Token:   token,
			Payment: meta.Payment,
		}
		err = conn.WriteJSON(mess)
		if err != nil {
			l.Println("write:", err)
			return err
		}
		cleanupSocket(id)
		l.Info("job complete")
		return nil
	}
}

func handleAddressCheck(id string, message *wsMessage) error {
	l := log.WithFields(log.Fields{"func": "handleAddressCheck"})
	l.Info("handleAddressCheck")
	l.Info(message)
	payment := message.Payment
	var ok bool
	var conn *websocket.Conn
	if conn, ok = socketClients[id]; !ok {
		l.Error("socket not found")
		return errors.New("socket not found")
	}
	meta, err := decryptMetaFromPayment(payment)
	if err != nil {
		l.Error("decrypt meta:", err)
		if err := conn.WriteJSON(wsMessage{Message: "decrypt meta"}); err != nil {
			l.Error("write json:", err)
			return err
		}
		return err
	}
	for _, pr := range meta.Payment.Requests {
		if err := addPaymentRequestJob(id, payment, pr); err != nil {
			l.Error("add payment request job:", err)
			if err := conn.WriteJSON(wsMessage{Message: "add payment request job"}); err != nil {
				l.Error("write json:", err)
				return err
			}
			return err
		}
	}

	// let the user know we're still here
	go func() {
		for {
			time.Sleep(time.Second * 5)
			if err := conn.WriteJSON(wsMessage{Data: meta.Payment.Requests, Message: "watching for txs", Type: "message"}); err != nil {
				l.Println("write:", err)
				return
			}
		}
	}()

	// TODO REFACTOR
	subscriber := pubsub.JobCompleteSubscriber(id)
	go waitForConfirmation(id, conn, subscriber, meta, payment)
	l.Info("end")
	return nil
}
