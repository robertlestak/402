package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/robertlestak/hpay/internal/pubsub"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/upstream"
	log "github.com/sirupsen/logrus"
)

// apiPathPrefix joins the API prefix to the given path.
func apiPathPrefix(p string) string {
	pp := os.Getenv("API_PATH_PREFIX")
	if pp == "" {
		pp = "/"
	}
	return path.Join(pp, p)
}

// wsError contains a JSON error message sent to the client.
type wsError struct {
	Error string `json:"error"`
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
	payment := payment.Payment{}
	err := conn.ReadJSON(&payment)
	if err != nil {
		l.Println("read:", err)
		return err
	}
	l.Info("handle payment")
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
				payment.Token = token
				err = conn.WriteJSON(payment)
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

// Server handles all http server requests
func Server() error {
	l := log.WithFields(log.Fields{
		"action": "server",
	})
	l.Info("start")
	r := mux.NewRouter()

	r.HandleFunc(apiPathPrefix("/tokens/jwks"), auth.HandleCreateJWKS).Methods("GET")
	r.HandleFunc(apiPathPrefix("/tokens/valid"), auth.HandleValidateJWT).Methods("GET")
	// just for local testing remove this

	r.HandleFunc(apiPathPrefix("/"), upstream.HandlePurgeResource).Methods("PURGE")
	r.HandleFunc(apiPathPrefix("/"), hpay.HandleRequest).Methods("GET", "POST")

	r.HandleFunc(apiPathPrefix("/ws"), wsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	l.Infof("Listening on port %s", port)
	return http.ListenAndServe(":"+port, r)
}
