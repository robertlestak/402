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
	"github.com/robertlestak/402/internal/utils"
	log "github.com/sirupsen/logrus"
)

// CreateJWKS creates a JWKS document with the current sign keys
func CreateJWKS() (string, error) {
	var keys struct {
		Keys []jwk.Key `json:"keys"`
	}
	for k, v := range utils.TokenSignKeys {
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

// GetTokenKey returns the key for the given key ID
func GetTokenKey(id string) (*rsa.PrivateKey, error) {
	l := log.WithFields(log.Fields{
		"func": "GetTokenKey",
	})
	l.Println("start")
	if key, ok := utils.TokenSignKeys[id]; ok {
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

// initKeysFromString initializes the sign keys
func initKeysFromString(k string) (map[string]*rsa.PrivateKey, error) {
	l := log.WithFields(log.Fields{
		"func": "initKeysFromString",
	})
	l.Println("start")
	keys := make(map[string]*rsa.PrivateKey)
	for _, e := range strings.Split(k, ",") {
		e = strings.TrimSpace(e)
		ss := strings.Split(e, "_")
		if len(ss) != 2 {
			return keys, errors.New("keys must be in the form of '<name>_<base64_private_key>'")
		}
		name := strings.TrimSpace(ss[0])
		b64key := strings.TrimSpace(ss[1])
		bd, berr := base64.StdEncoding.DecodeString(b64key)
		if berr != nil {
			return keys, fmt.Errorf("failed to decode key: %s", berr.Error())
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(bd)
		if err != nil {
			return keys, err
		}
		l.Infof("added key: %s", key.Public())
		keys[name] = key
	}
	return keys, nil
}

// InitSignKeys initializes the sign keys
func InitSignKeys() error {
	l := log.WithFields(log.Fields{
		"func": "InitSignKeys",
	})
	l.Println("start")
	// JWT keys
	var err error
	utils.TokenSignKeys, err = initKeysFromString(os.Getenv("JWT_SIGN_KEYS"))
	if err != nil {
		return err
	}
	// Message keys
	utils.MessageSignKeys, err = initKeysFromString(os.Getenv("MESSAGE_SIGN_KEYS"))
	if err != nil {
		return err
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
	/*
		if _, ok := c["aud"]; !ok {
			c["aud"] = os.Getenv("JWT_AUD")
		}
	*/
	c["iat"] = time.Now().Unix()
	/*
		if _, ok := c["iss"]; !ok {
			c["iss"] = os.Getenv("JWT_ISS")
		}
	*/
	tokenString, err := token.SignedString(utils.TokenSignKeys[keyID])
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
		"sub": os.Getenv("ROOT_TENANT"),
	}, exp, utils.TokenKeyID())
}

// GenerateSubJWT generates a JWT with the provided claims
// this function should only be available to the root user
func GenerateSubJWT(claims jwt.MapClaims, exp time.Time) (string, error) {
	return GenerateJWT(claims, exp, utils.TokenKeyID())
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
	if strings.TrimSpace(token) == "" {
		l.Printf("token is empty")
		return nil, nil, errors.New("token is empty")
	}
	kid := os.Getenv("JWT_KEY_ID")
	unverifiedToken, _, err := ParseClaimsUnverified(token)
	if err != nil {
		l.Errorf("failed to parse token: %s", err)
		return nil, nil, err
	}
	if unverifiedToken == nil {
		l.Errorf("unverifiedToken is nil")
		return nil, nil, errors.New("token is nil")
	}
	if _, ok := unverifiedToken.Header["kid"]; !ok {
		l.Printf("token has no kid")
		return nil, nil, errors.New("token has no kid")
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
		return utils.TokenSignKeys[kid].Public(), nil
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
	if RootClaimsValid(jwtClaims) {
		l.Debug("root claims valid")
		return nil
	}
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

func RootClaimsValid(claims jwt.MapClaims) bool {
	l := log.WithFields(log.Fields{
		"func":      "RootClaimsValid",
		"jwtClaims": claims,
	})
	l.Debug("start")
	if sub, ok := claims["sub"]; ok {
		if sub.(string) == os.Getenv("ROOT_TENANT") {
			l.Debug("end")
			return true
		}
	}
	l.Debug("end")
	return false
}

// TokenIsRoot returns true if the provided token has a root sub
func TokenIsRoot(token string) bool {
	l := log.WithFields(log.Fields{
		"func": "TokenIsRoot",
	})
	l.Debug("start")
	_, c, err := ValidateJWT(token)
	if err != nil {
		l.Errorf("failed to validate token: %s", err)
		return false
	}
	if RootClaimsValid(c) {
		l.Debug("end")
		return true
	}
	l.Debug("end")
	return false
}

// RequestIsRoot returns true if the provided request has a root sub
func RequestIsRoot(r *http.Request) bool {
	l := log.WithFields(log.Fields{
		"func": "RequestIsRoot",
	})
	l.Debug("start")
	for _, token := range utils.AuthTokens(r) {
		if TokenIsRoot(token) {
			l.Debug("token is root")
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
	for _, token := range utils.AuthTokens(r) {
		_, claims, err := ValidateJWT(token)
		if err != nil {
			l.Errorf("failed to validate token: %s", err)
			continue
		}
		l.Infof("claims=%v", claims)
		w.WriteHeader(http.StatusOK)
		jerr := json.NewEncoder(w).Encode(claims)
		if jerr != nil {
			l.Errorf("failed to encode claims: %s", jerr)
			continue
		}
		return
	}
	l.Println("end")
	w.WriteHeader(http.StatusUnauthorized)
}

// TokenOwnsTeanant returns true if the provided token has the provided tenant
// in the sub claim. If the token is root, it returns true. If verified is false,
// it will not verify the token before checking the sub claim. This is useful when running
// behind validating middleware where we may not have the signing keys but we trust our infra.
func TokenOwnsTenant(token string, tenant string, verified bool) bool {
	withService := os.Getenv("TOKEN_VALIDATE_WITH_SERVICE")
	l := log.WithFields(log.Fields{
		"func":        "TokenOwnsTenant",
		"tenant":      tenant,
		"withService": withService,
	})
	l.Debug("start")
	if token == "" {
		l.Error("token is empty")
		return false
	}
	if TokenIsRoot(token) {
		l.Debug("token is root")
		return true
	}
	var claims jwt.MapClaims
	var err error
	if withService == "true" {
		l.Debug("validating with service")
		_, claims, err = ValidateJWTWithService(token)
	} else if verified {
		l.Debug("validating verified")
		_, claims, err = ValidateJWT(token)
	} else {
		l.Debug("validating unverified")
		_, claims, err = ParseClaimsUnverified(token)
	}
	if err != nil {
		l.Errorf("failed to parse token: %s", err)
		return false
	}
	l.Debug("claims=%v", claims)
	if sub, ok := claims["sub"]; ok {
		l.Debugf("sub=%s tenant=%s", sub, tenant)
		if sub.(string) == tenant {
			l.Debug("sub==tenant")
			l.Debug("end")
			return true
		}
		l.Debug("sub!=tenant")
	}
	l.Debug("end")
	return false
}

func RequestOwnsTenant(r *http.Request, tenant string) bool {
	l := log.WithFields(log.Fields{
		"func": "RequestOwnsTenant",
	})
	l.Println("start")
	for _, token := range utils.AuthTokens(r) {
		if TokenOwnsTenant(token, tenant, true) {
			l.Debug("end")
			return true
		}
	}
	l.Debug("end")
	return false
}

func ValidateJWTWithService(idtoken string) (*jwt.Token, jwt.MapClaims, error) {
	l := log.WithFields(log.Fields{
		"method": "ValidateJWTWithService",
	})
	l.Info("ValidateJWTWithService")
	req, rerr := http.NewRequest("POST", os.Getenv("TOKEN_VALIDATION_API"), nil)
	if rerr != nil {
		l.Errorf("http.NewRequest: %v", rerr)
		return nil, nil, rerr
	}
	hc := &http.Client{}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idtoken)
	res, rerr := hc.Do(req)
	if rerr != nil {
		l.Errorf("hc.Do: %v", rerr)
		return nil, nil, rerr
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		l.Errorf("res.StatusCode != 200. StatusCode=%d", res.StatusCode)
		return nil, nil, errors.New(http.StatusText(http.StatusUnauthorized))
	} else {
		token, claims, err := ParseClaimsUnverified(idtoken)
		if err != nil {
			l.Errorf("auth.ParseClaimsUnverified: %v", err)
			return nil, nil, err
		}
		// the live /valid request above returns a 200 if token is valid
		// the ParseClaimsUnverified above returns a token and claims
		// together, with the istio auth, we can confirm that the token provided is valid
		token.Valid = true
		l.Infof("auth.ParseClaimsUnverified: %v", claims)
		return token, claims, nil
	}
}

func RequestAuthorized(r *http.Request) bool {
	l := log.WithFields(log.Fields{
		"action": "RequestAuthorized",
	})
	l.Info("RequestAuthorized")
	tenant := r.Header.Get(utils.HeaderPrefix() + "tenant")
	if tenant == "" {
		l.Info("tenant is empty")
		tenant = os.Getenv("DEFAULT_TENANT")
	}
	ts := utils.AuthTokens(r)
	l.Debugf("tenant=%s, tokens=%v", tenant, ts)
	for _, token := range ts {
		if token == "" {
			l.Error("HandleGetWalletsForTenant no token")
			continue
		}
		if TokenOwnsTenant(token, tenant, true) {
			l.Info("token owns tenant")
			return true
		}
	}
	l.Info("requestOwnsTenant false")
	return false
}

func RequestAuthorizedRoot(r *http.Request) bool {
	l := log.WithFields(log.Fields{
		"action": "RequestAuthorizedRoot",
	})
	l.Info("RequestAuthorizedRoot")
	for _, token := range utils.AuthTokens(r) {
		if token == "" {
			l.Error("HandleGetWalletsForTenant no token")
			continue
		}
		if TokenIsRoot(token) {
			l.Error("token is root")
			return true
		}
	}
	l.Info("RequestAuthorizedRoot false")
	return false
}
