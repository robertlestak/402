package utils

import (
	"encoding/base64"
	"net/http"
	"os"
	"strings"
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

// KeyID is a simple wrapper that returns the current active KeyID
func KeyID() string {
	return os.Getenv("JWT_KEY_ID")
}
