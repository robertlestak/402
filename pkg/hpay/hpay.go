package hpay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/upstream"
	log "github.com/sirupsen/logrus"
)

type Customization struct {
	JS    string `json:"js"`
	CSS   string `json:"css"`
	Image string `json:"image"`
}

type Meta struct {
	Claims        jwt.MapClaims   `json:"claims"`
	Exp           time.Duration   `json:"exp"`
	Payment       payment.Payment `json:"payment"`
	Customization Customization   `json:"customization"`
}

type Page struct {
	Meta  *Meta  `json:"meta"`
	WSURL string `json:"ws_url"`
}

func keyID() string {
	return os.Getenv("JWT_KEY_ID")
}

func ValidateClaims(claims jwt.MapClaims) error {
	l := log.WithFields(log.Fields{
		"action": "ValidateClaims",
	})
	l.Debug("start")
	defer l.Debug("end")
	if claims["sub"] == "root" {
		l.WithField("sub", claims["sub"]).Error("Invalid sub")
		return errors.New("invalid sub")
	}
	return nil
}

func (m *Meta) GenerateToken() (string, error) {
	l := log.WithFields(log.Fields{
		"action": "GenerateToken",
	})
	l.Debug("start")
	defer l.Debug("end")
	var exp time.Time
	if m.Exp > 0 {
		exp = time.Now().Add(m.Exp)
	}
	if verr := ValidateClaims(m.Claims); verr != nil {
		l.WithError(verr).Error("Failed to validate claims")
		return "", verr
	}
	token, err := auth.GenerateJWT(m.Claims, exp, keyID())
	if err != nil {
		l.Error(err)
		return "", err
	}
	l.WithField("token", token).Debug("Generated token")
	m.Payment.Token = token
	return token, nil
}

func parseMeta(h map[string]string) (*Meta, error) {
	l := log.WithFields(log.Fields{
		"action": "parseMeta",
	})
	l.Debug("start")
	if h == nil {
		l.Debug("end")
		return nil, nil
	}
	var metaBase64Str string
	if h[strings.ToLower(utils.HeaderPrefix()+"required")] == "true" {
		l.Debug("end")
		metaBase64Str = h[strings.ToLower(utils.HeaderPrefix()+"request")]
	} else {
		l.Debug("end")
		return nil, nil
	}
	if metaBase64Str == "" {
		return nil, errors.New("no meta header")
	}
	meta, err := base64.StdEncoding.DecodeString(metaBase64Str)
	if err != nil {
		l.WithError(err).Error("Failed to decode meta header")
		return nil, err
	}
	var metaObj Meta
	if err := json.Unmarshal(meta, &metaObj); err != nil {
		l.WithError(err).Error("Failed to unmarshal meta header")
		return nil, err
	}
	l.Debug("end")
	l.Debugf("meta: %+v", metaObj)
	return &metaObj, nil
}

func HandleRequest(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleRequest",
	})
	l.Debug("start")
	defer l.Debug("end")
	var claims jwt.MapClaims
	var err error
	resource := r.FormValue("resource")
	if resource == "" {
		l.Error("no resource")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "no resource")
		return
	}
	authToken := utils.AuthToken(r)
	if authToken == "" {
		l.Info("no auth token")
	} else {
		_, claims, err = auth.ValidateJWT(authToken)
		if err != nil {
			l.WithError(err).Error("Failed to validate JWT")
			//http.Error(w, err.Error(), http.StatusUnauthorized)
			//return
			authToken = ""
		}
		l.WithField("claims", claims).Debug("JWT validated")
	}
	us, uerr := upstream.UpstreamForRequest(r)
	if uerr != nil {
		l.WithError(uerr).Error("Failed to find upstream")
		http.Error(w, "Failed to find upstream", http.StatusInternalServerError)
		return
	}
	rd, herr := us.GetResourceMeta(resource)
	if herr != nil {
		l.WithError(herr).Error("Failed to get headers")
		http.Error(w, "Failed to get headers", http.StatusInternalServerError)
		return
	}
	l.WithField("resourceMeta", rd).Debug("Got resourceMeta")
	meta, merr := parseMeta(rd)
	if merr != nil {
		l.WithError(merr).Error("Failed to parse meta")
		http.Error(w, "Failed to parse meta", http.StatusInternalServerError)
		return
	}
	if meta == nil {
		l.Debug("no payment required")
		w.WriteHeader(http.StatusOK)
		return
	}
	l.WithField("meta", meta).Debug("Got meta")
	if claims != nil {
		if verr := auth.ValidateClaims(claims, meta.Claims); verr != nil {
			l.Error("claims not valid")
			http.Error(w, "claims not valid", http.StatusUnauthorized)
			return
		}
		l.Debug("claims valid")
		w.WriteHeader(http.StatusOK)
		return
	}
	l.Debug("no claims")
	w.WriteHeader(http.StatusPaymentRequired)
	mjson, err := json.Marshal(meta)
	if err != nil {
		l.WithError(err).Error("Failed to marshal meta")
		http.Error(w, "Failed to marshal meta", http.StatusInternalServerError)
		return
	}
	em, err := auth.EncryptWithPublicKey(mjson, keyID())
	if err != nil {
		l.WithError(err).Error("Failed to encrypt meta")
		http.Error(w, "Failed to encrypt meta", http.StatusInternalServerError)
		return
	}
	meta.Payment.EncryptedMeta = base64.StdEncoding.EncodeToString(em)
	l.WithField("meta", meta).Debug("Encrypted meta")
	pageData := &Page{
		Meta:  meta,
		WSURL: os.Getenv("WS_URL"),
	}
	payment.TemplatedPage(w, pageData, "402.html")
}

func (m *Meta) Decrypt(encrypted string) error {
	l := log.WithFields(log.Fields{
		"action": "Decrypt",
	})
	l.Debug("start")
	defer l.Debug("end")
	if encrypted == "" {
		l.Debug("end")
		return nil
	}

	bd, berr := auth.DecryptWithPrivateKey([]byte(encrypted), utils.KeyID())
	if berr != nil {
		l.WithError(berr).Error("Failed to decrypt")
		return berr
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bd))
	if err != nil {
		l.WithError(err).Error("Failed to decode")
		return err
	}
	l.WithField("decrypted", string(decoded)).Debug("Decrypted")
	if err := json.Unmarshal(decoded, &m); err != nil {
		l.WithError(err).Error("Failed to unmarshal")
		return err
	}
	l.WithField("meta", m).Debug("Unmarshaled")
	l.Debug("end")
	return nil
}

func (m *Meta) ValidatePayment() error {
	l := log.WithFields(log.Fields{
		"action": "ValidatePayment",
	})
	l.Debug("start")
	defer l.Debug("end")
	if perr := m.Payment.Validate(); perr != nil {
		l.WithError(perr).Error("Failed to validate payment")
		return perr
	}
	return nil
}

func ValidateEncryptedPayment(txid string, network string, encrypted string) error {
	l := log.WithFields(log.Fields{
		"action":  "ValidateEncryptedPayment",
		"txid":    txid,
		"network": network,
	})
	l.Debug("start")
	defer l.Debug("end")
	if encrypted == "" {
		l.Debug("end")
		return errors.New("no encrypted payment")
	}
	bd, berr := base64.StdEncoding.DecodeString(encrypted)
	if berr != nil {
		l.WithError(berr).Error("Failed to decode")
		return berr
	}
	decrypted, err := auth.DecryptWithPrivateKey(bd, utils.KeyID())
	if err != nil {
		l.WithError(err).Error("Failed to decrypt")
		return err
	}
	l.WithField("decrypted", string(decrypted)).Debug("Decrypted")
	var meta Meta
	if err := json.Unmarshal(decrypted, &meta); err != nil {
		l.WithError(err).Error("Failed to unmarshal")
		return err
	}
	meta.Payment.Txid = txid
	meta.Payment.Network = network
	l.WithField("meta", meta).Debug("Unmarshaled")
	if err := meta.ValidatePayment(); err != nil {
		l.WithError(err).Error("Failed to validate payment")
		return err
	}
	l.Debug("end")
	return nil
}
