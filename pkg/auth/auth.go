package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/robertlestak/hpay/internal/utils"
	log "github.com/sirupsen/logrus"
)

var (
	// SignKeys is a map of key IDs to private keys
	SignKeys = make(map[string]*rsa.PrivateKey)
)

// CreateJWKS creates a JWKS document with the current sign keys
func CreateJWKS() (string, error) {
	var keys struct {
		Keys []jwk.Key `json:"keys"`
	}
	for k, v := range SignKeys {
		key, err := jwk.New(v)
		if err != nil {
			return "", fmt.Errorf("failed to create symmetric key: %s", err)
		}
		key.Set(jwk.KeyIDKey, k)
		keys.Keys = append(keys.Keys, key)
	}

	buf, err := json.Marshal(keys)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key into JSON: %s", err)
	}
	return string(buf), nil
}

// GetKey returns the key for the given key ID
func GetKey(id string) (*rsa.PrivateKey, error) {
	l := log.WithFields(log.Fields{
		"func": "GetKey",
	})
	l.Println("start")
	if key, ok := SignKeys[id]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key not found: %s", id)
}

// HandleCreateJWKS handles the creation of a JWKS document
func HandleCreateJWKS(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "HandleCreateJWKS",
	})
	l.Println("start")
	jwks, err := CreateJWKS()
	if err != nil {
		l.Errorf("failed to create jwks: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(jwks))
}

// InitSignKeys initializes the sign keys
func InitSignKeys() error {
	l := log.WithFields(log.Fields{
		"func": "InitSignKeys",
	})
	l.Println("start")
	for _, e := range strings.Split(os.Getenv("JWT_SIGN_KEYS"), ",") {
		e = strings.TrimSpace(e)
		ss := strings.Split(e, "_")
		if len(ss) != 2 {
			return errors.New("JWT_SIGN_KEYS must be in the form of '<name>_<base64_private_key>'")
		}
		name := strings.TrimSpace(ss[0])
		b64key := strings.TrimSpace(ss[1])
		bd, berr := base64.StdEncoding.DecodeString(b64key)
		if berr != nil {
			return fmt.Errorf("failed to decode key: %s", berr.Error())
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(bd)
		if err != nil {
			return err
		}
		l.Infof("added key: %s", key.Public())
		SignKeys[name] = key
	}
	return nil
}

// GenerateJWT generates a JWT with the provided claims
func GenerateJWT(claims map[string]interface{}, exp time.Time, keyID string) (string, error) {
	fields := log.Fields{
		"func": "GenerateJWT",
		"exp":  exp,
		"kid":  keyID,
	}
	for k, v := range claims {
		fields[k] = v
	}
	l := log.WithFields(fields)
	l.Println("start")
	token := jwt.New(jwt.SigningMethodRS256)
	c := token.Claims.(jwt.MapClaims)
	if !exp.IsZero() {
		c["exp"] = exp.Unix()
	}
	for k, v := range claims {
		c[k] = v
	}
	token.Header["kid"] = keyID
	if _, ok := c["aud"]; !ok {
		c["aud"] = os.Getenv("JWT_AUD")
	}
	c["iat"] = time.Now().Unix()
	c["iss"] = os.Getenv("JWT_ISS")
	tokenString, err := token.SignedString(SignKeys[keyID])
	if err != nil {
		l.Errorf("failed to sign token: %s", err)
		return "", err
	}
	return tokenString, nil
}

// GenerateRootJWT generates a root JWT with the provided claims
// this function should only be available to the root user
func GenerateRootJWT(exp time.Time) (string, error) {
	return GenerateJWT(map[string]interface{}{
		"sub": "root",
	}, exp, utils.KeyID())
}

// ParseClaimsUnverified parses the claims from the JWT without verifying the signature
// this is useful if we are either relying on an auth gateway ahead of us, or if we are simply
// trying to read claims from the JWT without actually validating they are accurate.
func ParseClaimsUnverified(t string) (*jwt.Token, jwt.MapClaims, error) {
	l := log.WithFields(log.Fields{
		"func": "ParseClaimsUnverified",
	})
	l.Println("start")
	claims := jwt.MapClaims{}
	p := &jwt.Parser{}
	// assuming token has been verified by auth gateway we are just accessing claims
	token, _, err := p.ParseUnverified(t, claims)
	if err != nil {
		l.Printf("p.ParseUnverified error=%v", err)
		return token, claims, nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		l.Printf("token.Claims.(jwt.MapClaims) error=%v", err)
		return nil, nil, fmt.Errorf("token.Claims.(jwt.MapClaims) error=%v", err)
	}
	l.Infof("claims=%v", claims)
	return token, claims, nil
}

// ValidateJWT validates the JWT and returns the claims
func ValidateJWT(token string) (*jwt.Token, jwt.MapClaims, error) {
	l := log.WithFields(log.Fields{
		"func": "ValidateJWT",
	})
	l.Println("start")
	kid := os.Getenv("JWT_KEY_ID")
	unverifiedToken, _, err := ParseClaimsUnverified(token)
	if err != nil {
		l.Errorf("failed to parse token: %s", err)
		return nil, nil, err
	}
	if unverifiedToken.Header["kid"] != "" {
		l.Infof("using kid=%s", unverifiedToken.Header["kid"])
		kid = unverifiedToken.Header["kid"].(string)
	}
	if kid == "" {
		l.Infof("using default JWT_KEY_ID=%s", kid)
		kid = os.Getenv("JWT_KEY_ID")
	}
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			l.Errorf("unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		l.Infof("validating jwt with kid=%s", kid)
		if k, ok := token.Header["kid"]; ok {
			kid = k.(string)
			l.Infof("found kid: %s", kid)
		}
		l.Infof("using kid: %s", kid)
		return SignKeys[kid].Public(), nil
	})
	l.Infof("parsed jwt")
	if err != nil {
		l.Errorf("failed to parse token: %s", err)
		return nil, nil, err
	}
	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		l.Infof("valid jwt with claims %v", claims)
		if exp, ok := claims["exp"]; ok {
			if exp.(float64) < float64(time.Now().Unix()) {
				l.Errorf("token expired")
				return nil, nil, fmt.Errorf("token expired")
			}
		}
		return t, claims, nil
	} else {
		l.Errorf("invalid jwt: %s", err.Error())
		return t, claims, err
	}
}

// ValidateClaims validates the requested claims against the claims of the JWT provided
func ValidateClaims(jwtClaims jwt.MapClaims, requestedClaims jwt.MapClaims) error {
	l := log.WithFields(log.Fields{
		"func":            "ValidateClaims",
		"jwtClaims":       jwtClaims,
		"requestedClaims": requestedClaims,
	})
	l.Debug("start")
	for k, v := range requestedClaims {
		if v2, ok := jwtClaims[k]; ok {
			if v2 != v {
				l.Errorf("claim %s does not match: %s != %s", k, v2, v)
				return fmt.Errorf("claim %s does not match: %s != %s", k, v2, v)
			}
		} else {
			l.Errorf("claim %s not found", k)
			return fmt.Errorf("claim %s not found", k)
		}
	}
	l.Debug("end")
	return nil
}

// TokenIsRoot returns true if the provided token has a root sub
func TokenIsRoot(token string) bool {
	l := log.WithFields(log.Fields{
		"func": "TokenIsRoot",
	})
	l.Debug("start")
	_, claims, err := ValidateJWT(token)
	if err != nil {
		l.Errorf("failed to validate token: %s", err)
		return false
	}
	if sub, ok := claims["sub"]; ok {
		if sub.(string) == "root" {
			l.Debug("end")
			return true
		}
	}
	l.Debug("end")
	return false
}

// HandleValidateJWT handles the validation of a provided JWT
func HandleValidateJWT(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "HandleValidateJWT",
	})
	l.Println("start")
	token := utils.AuthToken(r)
	_, claims, err := ValidateJWT(token)
	if err != nil {
		l.Errorf("failed to validate token: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	l.Infof("claims=%v", claims)
	w.WriteHeader(http.StatusOK)
	jerr := json.NewEncoder(w).Encode(claims)
	if jerr != nil {
		l.Errorf("failed to encode claims: %s", jerr)
	}
}
