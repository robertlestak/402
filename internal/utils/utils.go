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

func NetworkSupported(network string) bool {
	return StringInSlice(network, supportedNetworks)
}

func HeaderPrefix() string {
	return "x-" + os.Getenv("HEADER_NAME_PREFIX") + "-"
}

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

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func KeyID() string {
	return os.Getenv("JWT_KEY_ID")
}
