package meta

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/payment"
	log "github.com/sirupsen/logrus"
)

// Meta is the primary struct for a 402 request
type Meta struct {
	Claims        jwt.MapClaims    `json:"claims"`
	Exp           time.Duration    `json:"exp"`
	Renewable     bool             `json:"renewable"`
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
	if _, ok := m.Claims["tid"]; !ok && m.Payment.Tenant != "" {
		m.Claims["tid"] = m.Payment.Tenant
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

// Decrypt decrypts the encrypted meta object
func (m *Meta) Decrypt(encrypted string) error {
	l := log.WithFields(log.Fields{
		"action": "Decrypt",
	})
	l.Debug("start")
	defer l.Debug("end")
	if encrypted == "" {
		return nil
	}

	bd, berr := utils.DecryptWithPrivateKey([]byte(encrypted), utils.MessageKeyID())
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
