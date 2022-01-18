package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	"github.com/robertlestak/hpay/internal/pubsub"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/upstream"
	log "github.com/sirupsen/logrus"
)

// wsError contains a JSON error message sent to the client.
type wsError struct {
	Error string `json:"error"`
}

type wsMessage struct {
	Type    string           `json:"type"`
	Payment *payment.Payment `json:"payment"`
	Token   string           `json:"token"`
}

func handleAuth(conn *websocket.Conn, message *wsMessage) error {
	l := log.WithFields(log.Fields{
		"action": "handleAuth",
	})
	l.Info("start")
	defer l.Info("end")
	var err error
	token := message.Token
	if token == "" {
		l.Info("no token")
		if err := conn.WriteJSON(wsError{Error: "no token"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("no token")
	}
	payment := message.Payment
	var claims jwt.MapClaims
	_, claims, err = auth.ValidateJWT(token)
	if err != nil {
		l.WithError(err).Error("Failed to validate JWT")
		if err := conn.WriteJSON(wsError{Error: "invalid token"}); err != nil {
			l.Println("write:", err)
			return err
		}
	}
	l.WithField("claims", claims).Debug("JWT validated")
	bdata, berr := base64.StdEncoding.DecodeString(payment.EncryptedMeta)
	if berr != nil {
		l.Error("base64 decode:", berr)
		if err := conn.WriteJSON(wsError{Error: "base64 decode error"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	decryptedMeta, derr := auth.DecryptWithPrivateKey(bdata, utils.KeyID())
	if derr != nil {
		l.Error("decrypt meta:", derr)
		if err := conn.WriteJSON(wsError{Error: "decrypt meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	meta := hpay.Meta{}
	err = json.Unmarshal(decryptedMeta, &meta)
	if err != nil {
		l.Error("unmarshal meta:", err)
		if err := conn.WriteJSON(wsError{Error: "unmarshal meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	l.WithField("meta", meta).Debug("Got meta")
	if claims == nil {
		l.Info("no claims")
		if err := conn.WriteJSON(wsError{Error: "no claims"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("no claims")
	}
	if verr := auth.ValidateClaims(claims, meta.Claims); verr != nil {
		l.WithError(verr).Error("Failed to validate claims")
		if err := conn.WriteJSON(wsError{Error: "invalid claims"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("invalid claims: " + verr.Error())
	}
	l.Debug("claims valid")
	// generate a new token for this request
	token, terr := meta.GenerateToken()
	if terr != nil {
		l.Error("generate token:", terr)
		if err := conn.WriteJSON(wsError{Error: "generate token"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("generate token: " + terr.Error())
	}
	if token == "" {
		l.Error("token is empty")
		if err := conn.WriteJSON(wsError{Error: "token empty"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("token empty")
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
	l.Info("job complete")
	return nil
}

func clientAccessClaims(claims jwt.MapClaims) bool {
	if iss, ok := claims["iss"]; ok && iss == os.Getenv("JWT_ISS") {
		return true
	}
	return false
}

func handlePayment(conn *websocket.Conn, message *wsMessage) error {
	var err error
	l := log.WithFields(log.Fields{
		"action": "handlePayment",
	})
	l.Info("start")
	payment := message.Payment
	if payment.Txid == "" {
		l.Error("txid is empty")
		if err := conn.WriteJSON(wsError{Error: "txid empty"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	if payment.Network == "" {
		l.Error("network is empty")
		if err := conn.WriteJSON(wsError{Error: "network empty"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	if payment.MetaHash == "" {
		l.Error("metaHash is empty")
		if err := conn.WriteJSON(wsError{Error: "metaHash empty"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	if payment.Tenant == "" {
		l.Info("tenant is empty, using DEFAULT_TENANT")
		payment.Tenant = os.Getenv("DEFAULT_TENANT")
	}
	if !utils.NetworkSupported(payment.Network) {
		l.Error("network not supported")
		if err := conn.WriteJSON(wsError{Error: "network not supported"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	bdata, berr := base64.StdEncoding.DecodeString(payment.EncryptedMeta)
	if berr != nil {
		l.Error("base64 decode:", berr)
		if err := conn.WriteJSON(wsError{Error: "base64 decode error"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	decryptedMeta, derr := auth.DecryptWithPrivateKey(bdata, utils.KeyID())
	if derr != nil {
		l.Error("decrypt meta:", derr)
		if err := conn.WriteJSON(wsError{Error: "decrypt meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	meta := hpay.Meta{}
	err = json.Unmarshal(decryptedMeta, &meta)
	if err != nil {
		l.Error("unmarshal meta:", err)
		if err := conn.WriteJSON(wsError{Error: "unmarshal meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	pubsub.AddJob(payment.Txid, payment.Network, payment.EncryptedMeta, payment.MetaHash)
	subscriber := pubsub.JobCompleteSubscriber(payment.Network)
	go func() {
		for {
			l.Infof("Waiting for txid: %s", payment.Txid)
			msg, err := subscriber.ReceiveMessage()
			if err != nil {
				l.Error(err)
				return
			}
			l.Infof("Got message: %s", msg.Payload)

			if strings.Contains(msg.Payload, payment.Txid) && strings.Contains(msg.Payload, ":") {
				parts := strings.Split(msg.Payload, ":")
				if err := conn.WriteJSON(wsError{Error: parts[1]}); err != nil {
					l.Println("write:", err)
					return
				}
				return
			} else if strings.Contains(msg.Payload, payment.Txid) {
				meta.Payment = payment
				if !clientAccessClaims(meta.Claims) {
					us := &upstream.Upstream{}
					us.ID = meta.UpstreamID
					if err := us.GetByID(); err != nil {
						l.Error(err)
						return
					}
					if verr := hpay.ValidateRequestedClaims(meta.Claims, us); verr != nil {
						l.WithError(verr).Error("Failed to validate claims")
						if err := conn.WriteJSON(wsError{Error: "Failed to validate claims"}); err != nil {
							l.Println("write:", err)
							return
						}
						return
					}
				}
				token, terr := meta.GenerateToken()
				if terr != nil {
					l.Error("generate token:", terr)
					if err := conn.WriteJSON(wsError{Error: "generate token"}); err != nil {
						l.Println("write:", err)
						return
					}
					return
				}
				if token == "" {
					l.Error("token is empty")
					if err := conn.WriteJSON(wsError{Error: "token empty"}); err != nil {
						l.Println("write:", err)
						return
					}
					return
				}
				mess := &wsMessage{
					Type:    "auth",
					Token:   token,
					Payment: meta.Payment,
				}
				err = conn.WriteJSON(mess)
				if err != nil {
					l.Println("write:", err)
					return
				}
				l.Info("job complete")
				return
			}
		}
	}()
	return nil
}

// handlePaymentSocket handles a websocket connection
// it is a monolith e2e function (should be refactored) that receives a transaction
// from the client, validates the tx against the specified chain, and sends the
// client their access token for succesful payment
func handlePaymentSocket(conn *websocket.Conn) error {
	l := log.WithFields(log.Fields{
		"action": "handlePaymentSocket",
	})
	l.Info("start")
	message := &wsMessage{}
	err := conn.ReadJSON(&message)
	if err != nil {
		l.Println("read:", err)
		return err
	}
	l.Info("handle message")
	switch message.Type {
	case "auth":
		l.Info("auth")
		if err = handleAuth(conn, message); err != nil {
			l.Println("handle auth:", err)
			return err
		}
	case "payment":
		l.Info("payment")
		if herr := handlePayment(conn, message); herr != nil {
			l.Error(herr)
			return herr
		}
	}
	return nil
}

// wsHandler is a http handler for websocket connections
func wsHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "wsHandler",
	})
	l.Info("start")
	var upgrader = websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		l.WithError(err).Error("Failed to upgrade websocket")
		http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
		return
	}
	l.Info("handle socket")
	defer conn.Close()
	for {
		if err := handlePaymentSocket(conn); err != nil {
			l.WithError(err).Error("Failed to handle websocket")
			break
		}
	}
}
