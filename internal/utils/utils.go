package utils

import (
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	supportedNetworks = []string{
		"ethereum",
		"polygon",
	}
)

// NetworkSupported returns true if the given network is supported
func NetworkSupported(network string) bool {
	return StringInSlice(network, supportedNetworks)
}

// HeaderPrefix returns the prefix for upstream configuration metadata
func HeaderPrefix() string {
	return "x-" + os.Getenv("HEADER_NAME_PREFIX") + "-"
}

func Base64EncodeStripped(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	s = strings.TrimRight(encoded, "=")
	s = strings.Replace(s, "/", "_", -1)
	s = strings.Replace(s, "+", "-", -1)
	return s
}

func Base64DecodeStripped(s string) (string, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	s = strings.Replace(s, "_", "/", -1)
	s = strings.Replace(s, "-", "+", -1)
	decoded, err := base64.StdEncoding.DecodeString(s)
	return string(decoded), err
}

// AuthToken returns the auth token from the request
// iterating headers and cookies to find the token
func AuthToken(r *http.Request) string {
	for _, v := range r.Cookies() {
		if v.Name == os.Getenv("HEADER_NAME_PREFIX")+"_token" {
			return v.Value
		}
	}
	token := HeaderPrefix() + "token"
	if t := r.Header.Get(token); t == "" {
		token = r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token != "" {
			return token
		}
	}
	return token
}

func TokenCookiePrefix() string {
	return os.Getenv("HEADER_NAME_PREFIX") + "_token_"
}

// AuthTokens returns the auth token from the request
// iterating headers and cookies to find the tokens
func AuthTokens(r *http.Request) map[string]string {
	tokens := make(map[string]string)
	for _, v := range r.Cookies() {
		if v.Name == os.Getenv("HEADER_NAME_PREFIX")+"_token" {
			tokens[v.Name] = v.Value
		}
		pf := TokenCookiePrefix()
		if strings.HasPrefix(v.Name, pf) {
			key := strings.TrimPrefix(v.Name, pf)
			resource, err := Base64DecodeStripped(key)
			if err != nil {
				return nil
			}
			tokens[resource] = v.Value
		}
	}
	token := HeaderPrefix() + "token"
	if t := r.Header.Get(token); t == "" {
		token = r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token != "" {
			tokens["Authorization"] = token
		}
	}
	return tokens
}

// StringInSlice returns true if the given string is in the given slice
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// MessageKeyID is a simple wrapper that returns the current active KeyID
func MessageKeyID() string {
	return os.Getenv("MESSAGE_KEY_ID")
}

// TokenKeyID is a simple wrapper that returns the current active KeyID
func TokenKeyID() string {
	return os.Getenv("JWT_KEY_ID")
}

func GetPage(r *http.Request) (int, int) {
	page := 1
	pageSize := 10
	var err error
	if p := r.URL.Query().Get("page"); p != "" {
		page, err = strconv.Atoi(p)
		if err != nil {
			page = 1
		}
	}
	if ps := r.URL.Query().Get("pageSize"); ps != "" {
		pageSize, err = strconv.Atoi(ps)
		if err != nil {
			pageSize = 10
		}
	}
	return page, pageSize
}

func TenantName(t string) string {
	t = strings.ToLower(t)
	return t
}

func CreateSignature(p string) string {
	l := log.WithFields(log.Fields{
		"action": "CreateSignature",
		"p":      p,
	})
	l.Debug("Creating signature")
	sig := p + ":" + strconv.Itoa(int(time.Now().Unix()))
	ss, serr := EncryptWithPublicKey([]byte(sig), MessageKeyID())
	if serr != nil {
		l.WithError(serr).Error("Error encrypting signature")
		return ""
	}
	bd := base64.StdEncoding.EncodeToString(ss)
	return bd
}

func ValidateSignature(r *http.Request) bool {
	sig := r.Header.Get(HeaderPrefix() + "signature")
	l := log.WithFields(log.Fields{
		"method":    r.Method,
		"url":       r.URL.String(),
		"action":    "ValidateSignature",
		"signature": sig,
	})
	l.Debug("validating signature")
	if sig == "" {
		l.Error("Signature is empty")
		return false
	}
	bd, berr := base64.StdEncoding.DecodeString(sig)
	if berr != nil {
		l.WithError(berr).Error("Failed to decode signature")
		return false
	}
	m, merr := DecryptWithPrivateKey(bd, MessageKeyID())
	if merr != nil {
		l.Errorf("Error decrypting signature: %s", merr)
		return false
	}
	strSig := string(m)
	l = l.WithField("signatureDecoded", strSig)
	l.Debug("Decoded signature")
	strs := strings.Split(strSig, ":")
	if len(strs) != 2 {
		l.Error("Invalid signature")
		return false
	}
	res := strs[0]
	strUnixTime := strs[1]
	if r.URL.Path != res {
		l.Errorf("Invalid signature: %s", res)
		return false
	}
	unixTime, err := strconv.ParseInt(strUnixTime, 10, 64)
	if err != nil {
		l.Errorf("Error converting signature to unix time: %s", err)
		return false
	}
	sigExp, err := strconv.ParseInt(os.Getenv("SIGNATURE_EXPIRY_TIME"), 10, 64)
	if err != nil {
		l.Errorf("Error converting signature expiry time: %s", err)
		return false
	}
	tdiff := time.Now().Unix() - unixTime
	l = l.WithFields(log.Fields{
		"timeDiff": tdiff,
		"sigExp":   sigExp,
	})
	l.Debug("Time diff")
	if tdiff > sigExp {
		l.Error("Signature has expired")
		return false
	}
	l.Debug("Signature valid")
	return true
}
