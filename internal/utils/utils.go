package utils

import (
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
