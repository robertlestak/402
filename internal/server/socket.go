package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	"github.com/robertlestak/hpay/internal/pubsub"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/meta"
	"github.com/robertlestak/hpay/pkg/payment"
	log "github.com/sirupsen/logrus"
)

var (
	socketClients = make(map[string]*websocket.Conn)
)

type wsMessage struct {
	Type    string           `json:"type"`
	Payment *payment.Payment `json:"payment"`
	Token   string           `json:"token"`
	Message string           `json:"message"`
	Data    interface{}      `json:"data"`
}

func handleAuth(id string, message *wsMessage) error {
	l := log.WithFields(log.Fields{
		"action": "handleAuth",
	})
	l.Info("start")
	defer l.Info("end")
	var ok bool
	var conn *websocket.Conn
	if conn, ok = socketClients[id]; !ok {
		l.Error("socket not found")
		return errors.New("socket not found")
	}
	var err error
	token := message.Token
	if token == "" {
		l.Info("no token")
		if err := conn.WriteJSON(wsMessage{Message: "no token"}); err != nil {
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
		if err := conn.WriteJSON(wsMessage{Message: "invalid token"}); err != nil {
			l.Println("write:", err)
			return err
		}
	}
	l.WithField("claims", claims).Debug("JWT validated")
	bdata, berr := base64.StdEncoding.DecodeString(payment.EncryptedMeta)
	if berr != nil {
		l.Error("base64 decode:", berr)
		if err := conn.WriteJSON(wsMessage{Message: "base64 decode error"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	decryptedMeta, derr := utils.DecryptWithPrivateKey(bdata, utils.MessageKeyID())
	if derr != nil {
		l.Error("decrypt meta:", derr)
		if err := conn.WriteJSON(wsMessage{Message: "decrypt meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	meta := meta.Meta{}
	err = json.Unmarshal(decryptedMeta, &meta)
	if err != nil {
		l.Error("unmarshal meta:", err)
		if err := conn.WriteJSON(wsMessage{Message: "unmarshal meta"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return nil
	}
	l.WithField("meta", meta).Debug("Got meta")
	if claims == nil {
		l.Info("no claims")
		if err := conn.WriteJSON(wsMessage{Message: "no claims"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("no claims")
	}
	if verr := auth.ValidateClaims(claims, meta.Claims); verr != nil {
		l.WithError(verr).Error("Failed to validate claims")
		if err := conn.WriteJSON(wsMessage{Message: "invalid claims"}); err != nil {
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
		if err := conn.WriteJSON(wsMessage{Message: "generate token"}); err != nil {
			l.Println("write:", err)
			return err
		}
		return errors.New("generate token: " + terr.Error())
	}
	if token == "" {
		l.Error("token is empty")
		if err := conn.WriteJSON(wsMessage{Message: "token empty"}); err != nil {
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

// handlePaymentSocket handles a websocket connection
// it is a monolith e2e function (should be refactored) that receives a transaction
// from the client, validates the tx against the specified chain, and sends the
// client their access token for succesful payment
func handlePaymentSocket(id string) error {
	l := log.WithFields(log.Fields{
		"action": "handlePaymentSocket",
	})
	l.Info("start")
	if id == "" {
		l.Error("id is empty")
		return errors.New("id is empty")
	}
	var ok bool
	var conn *websocket.Conn
	if conn, ok = socketClients[id]; !ok {
		l.Error("socket not found")
		return errors.New("socket not found")
	}
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
		if err = handleAuth(id, message); err != nil {
			l.Println("handle auth:", err)
			return err
		}
	case "check":
		l.Info("check")
		if err = handleAddressCheck(id, message); err != nil {
			l.Println("handle check:", err)
			return err
		}
	case "ping":
		l.Info("ping")
		if err = conn.WriteJSON(wsMessage{Type: "pong"}); err != nil {
			l.Println("write:", err)
			return err
		}
	}
	return nil
}

func cleanupSocket(id string) {
	l := log.WithFields(log.Fields{
		"action": "cleanupSocket",
	})
	l.Info("start")
	if id == "" {
		l.Error("id is empty")
		return
	}
	delete(socketClients, id)
	pubsub.ExpireAddressJobs(id, time.Minute*1)
}

// wsHandler is a http handler for websocket connections
func wsHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "wsHandler",
	})
	l.Info("start")
	var upgrader = websocket.Upgrader{}
	upgrader.CheckOrigin = func(r *http.Request) bool {
		if os.Getenv("CORS_ALLOWED_ORIGINS") == "*" {
			return true
		}
		for _, h := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
			origin := r.Header["Origin"]
			if len(origin) == 0 {
				return true
			}
			if origin[0] == h {
				return true
			}
		}
		return false
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		l.WithError(err).Error("Failed to upgrade websocket")
		http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
		return
	}
	l.Info("handle socket")
	cid := uuid.New().String()
	l.Info("new connection id:", cid)
	socketClients[cid] = conn
	defer func() {
		l.Info("remove connection id:", cid)
		delete(socketClients, cid)
		conn.Close()
	}()
	for {
		if err := handlePaymentSocket(cid); err != nil {
			l.WithError(err).Error("Failed to handle websocket")
			cleanupSocket(cid)
			break
		}
	}
}
