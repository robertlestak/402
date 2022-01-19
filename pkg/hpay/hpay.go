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
	Claims        jwt.MapClaims    `json:"claims"`
	Exp           time.Duration    `json:"exp"`
	Payment       *payment.Payment `json:"payment"`
	Customization Customization    `json:"customization"`
	UpstreamID    uint             `json:"upstream_id"`
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

// ValidateRequestedClaims validates the requested claims against any configured protected claims
func ValidateRequestedClaims(claims jwt.MapClaims, us *upstream.Upstream) error {
	l := log.WithFields(log.Fields{
		"action":   "ValidateRequestedClaims",
		"upstream": us,
	})
	l.Debug("start")
	defer l.Debug("end")
	if us.IsRootTenant() {
		l.Debug("root tenant")
		return nil
	}
	if _, ok := claims["iss"]; ok {
		return errors.New("iss claim is protected")
	}
	if _, ok := claims["sub"]; ok {
		return errors.New("sub claim is protected")
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
	if _, ok := m.Claims["iss"]; !ok && m.Payment.Tenant != "" {
		m.Claims["iss"] = m.Payment.Tenant
	}
	token, err := auth.GenerateJWT(m.Claims, exp, utils.TokenKeyID())
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

func requestClaims(r *http.Request, resource string) (jwt.MapClaims, error) {
	l := log.WithFields(log.Fields{
		"action": "requestClaims",
	})
	l.Debug("start")
	defer l.Debug("end")
	var claims jwt.MapClaims
	var err error
	authTokens := utils.AuthTokens(r)
	if len(authTokens) == 0 {
		l.Info("no auth token")
	} else {
		var token string
		if rc, ok := authTokens[resource]; ok {
			token = rc
		} else if hc, ok := authTokens[os.Getenv("HEADER_NAME_PREFIX")+"_token"]; ok {
			token = hc
		} else if rc, ok := authTokens["Authorization"]; ok {
			token = rc
		} else {
			l.Error("no auth token")
		}
		if token != "" {
			_, claims, err = auth.ValidateJWT(token)
			if err != nil {
				l.WithError(err).Error("Failed to validate JWT")
				//http.Error(w, err.Error(), http.StatusUnauthorized)
				//return
				token = ""
			}
			l.WithField("claims", claims).Debug("JWT validated")
		}
	}
	return claims, err
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
	resource := r.FormValue("resource")
	if resource == "" {
		l.Error("no resource")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "no resource")
		return
	}
	claims, err := requestClaims(r, resource)
	if err != nil {
		l.WithError(err).Error("Failed to validate JWT")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, http.StatusText(http.StatusUnauthorized))
		return
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
	meta.UpstreamID = us.ID
	l.WithField("meta", meta).Debug("Got meta")
	if claims != nil {
		if verr := auth.ValidateClaims(claims, meta.Claims); verr != nil {
			l.Error("claims not valid")
		} else {
			l.Debug("claims valid")
			w.WriteHeader(http.StatusOK)
			return
		}
	} else {
		l.Debug("no claims")
		if cerr := ValidateRequestedClaims(meta.Claims, us); cerr != nil {
			l.Error("requested claims not valid for request")
			http.Error(w, "requested claims not valid for request", http.StatusUnauthorized)
			return
		}
	}
	if meta.Payment.Tenant == "" {
		meta.Payment.Tenant = os.Getenv("DEFAULT_TENANT")
		l.WithField("tenant", meta.Payment.Tenant).Debug("No tenant provided, using default")
	}
	// loop through payment requests to create addrs if necessary
	for _, pr := range meta.Payment.Requests {
		// if site owner has not provided static address, create one. This is the recommended approach.
		if pr.Address == "" && os.Getenv("VAULT_ENABLE") == "true" {
			newWallet, werr := vault.NewTenantWallet(meta.Payment.Tenant)
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
	em, err := auth.EncryptWithPublicKey(mjson, utils.MessageKeyID())
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
	w.WriteHeader(http.StatusPaymentRequired)
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

	bd, berr := auth.DecryptWithPrivateKey([]byte(encrypted), utils.MessageKeyID())
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
func ValidateEncryptedPayment(requestId string, address string, network string, encrypted string, metaHash string) error {
	l := log.WithFields(log.Fields{
		"action":    "ValidateEncryptedPayment",
		"address":   address,
		"network":   network,
		"metaHash":  metaHash,
		"requestId": requestId,
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
	decrypted, err := auth.DecryptWithPrivateKey(bd, utils.MessageKeyID())
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
	// check address - if success, set txid and validate payment

	for _, req := range meta.Payment.Requests {
		if req.Address == address {
			tx, err := req.ValidateAPI()
			if err != nil {
				l.WithError(err).Error("Failed to validate payment")
				return err
			}
			meta.Payment.Txid = tx.Hash
			meta.Payment.Network = network
		}
	}
	if meta.Payment.Txid == "" {
		l.Debug("end")
		return errors.New("txid not found")
	}
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
