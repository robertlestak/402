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
	"github.com/robertlestak/hpay/pkg/vault"
	log "github.com/sirupsen/logrus"
)

// Meta is the primary struct for a 402 request
type Meta struct {
	Claims        jwt.MapClaims   `json:"claims"`
	Exp           time.Duration   `json:"exp"`
	Payment       payment.Payment `json:"payment"`
	Customization Customization   `json:"customization"`
}

// Customization contains data the upstream can provide to customize the payment page
type Customization struct {
	JS    string `json:"js"`
	CSS   string `json:"css"`
	Image string `json:"image"`
}

// Page is the template for the payment page
type Page struct {
	Meta  *Meta  `json:"meta"`
	WSURL string `json:"ws_url"`
}

// Validate Claims validates the requested claims against any configured protected claims
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

// GenerateToken generates a JWT token for the provided payment request
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
	token, err := auth.GenerateJWT(m.Claims, exp, utils.KeyID())
	if err != nil {
		l.Error(err)
		return "", err
	}
	l.WithField("token", token).Debug("Generated token")
	m.Payment.Token = token
	return token, nil
}

// parseMeta parses the provided map[string]string for any configured payment meta fields
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

// HandleRequest is a monolith function (should be refactored) that handles an e2e request
// from a client. This will validate their current auth token (if provided) and if valid, will
// return 200 indicating the user has access to the resource. If the token is invalid, it will
// retrieve the upstream for the request, make a 402 head/meta request to retrieve the metadata,
// encrypt this request with the provided key, and return the [402 to the cllient
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
	// loop through payment requests to create addrs if necessary
	for _, pr := range meta.Payment.Requests {
		// if site owner has not provided static address, create one
		if pr.Address == "" {
			newWallet, werr := vault.NewWallet()
			if werr != nil {
				l.WithError(werr).Error("Failed to create wallet")
				http.Error(w, "Failed to create wallet", http.StatusInternalServerError)
				return
			}
			// store address in the payment request
			pr.Address = newWallet.Address
		}
	}
	mjson, err := json.Marshal(meta)
	if err != nil {
		l.WithError(err).Error("Failed to marshal meta")
		http.Error(w, "Failed to marshal meta", http.StatusInternalServerError)
		return
	}
	em, err := auth.EncryptWithPublicKey(mjson, utils.KeyID())
	if err != nil {
		l.WithError(err).Error("Failed to encrypt meta")
		http.Error(w, "Failed to encrypt meta", http.StatusInternalServerError)
		return
	}
	meta.Payment.EncryptedMeta = base64.StdEncoding.EncodeToString(em)
	if mherr := meta.Payment.CreateMetaHash(); mherr != nil {
		l.WithError(mherr).Error("Failed to create meta hash")
		http.Error(w, "Failed to create meta hash", http.StatusInternalServerError)
		return
	}
	l.WithField("meta", meta).Debug("Encrypted meta")
	pageData := &Page{
		Meta:  meta,
		WSURL: os.Getenv("WS_URL"),
	}
	payment.TemplatedPage(w, pageData, "402.html")
}

// Decrypt decrypts the encrypted meta object
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

// ValidatePayment validates the payment request
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

// ValidateEncryptedPayment handles an untrusted payment request from a user. It will take the
// encrypted meta resource from the user and decrypt it. It will then call the payment validation function
// which will compare the encrypted metadata and its hash to prevent tampering, and then will validate the
// txid provided against the requested network. Once the txid is validated, it will be checked to ensure that
// it is to an address in the payment request and has not been recieved before. If all of these checks pass,
// the payment request will be validated.
func ValidateEncryptedPayment(txid string, network string, encrypted string, metaHash string) error {
	l := log.WithFields(log.Fields{
		"action":   "ValidateEncryptedPayment",
		"txid":     txid,
		"network":  network,
		"metaHash": metaHash,
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
	meta.Payment.MetaHash = metaHash
	meta.Payment.EncryptedMeta = encrypted
	l.WithField("meta", meta).Debug("Unmarshaled")
	if err := meta.ValidatePayment(); err != nil {
		l.WithError(err).Error("Failed to validate payment")
		return err
	}
	l.Debug("end")
	return nil
}
