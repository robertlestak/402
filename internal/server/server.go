package server

import (
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/upstream"
	"github.com/robertlestak/hpay/pkg/vault"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

// apiPathPrefix joins the API prefix to the given path.
func apiPathPrefix(p string) string {
	pp := os.Getenv("API_PATH_PREFIX")
	if pp == "" {
		pp = "/"
	}
	return strings.ReplaceAll(path.Join(pp, p), "//", "/")
}

func handleHealthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Server handles all http server requests
func Server() error {
	l := log.WithFields(log.Fields{
		"action": "server",
	})
	l.Info("start")
	r := mux.NewRouter()

	r.HandleFunc(apiPathPrefix("/tokens/jwks"), auth.HandleCreateJWKS).Methods("GET")
	r.HandleFunc(apiPathPrefix("/tokens/valid"), auth.HandleValidateJWT).Methods("GET")
	r.HandleFunc(apiPathPrefix("/upstreams"), upstream.HandleUpdateUpstream).Methods("POST")
	r.HandleFunc(apiPathPrefix("/upstreams"), upstream.HandleListUpstreamsForTenant).Methods("GET")
	r.HandleFunc(apiPathPrefix("/upstreams"), upstream.HandleDeleteUpstreamForTenant).Methods("DELETE")
	r.HandleFunc(apiPathPrefix("/wallets/list"), vault.HandleListWalletsForTenant).Methods("GET")
	r.HandleFunc(apiPathPrefix("/wallets/get"), vault.HandleGetWalletsForTenant).Methods("POST")
	r.HandleFunc(apiPathPrefix("/wallets/{address}"), vault.HandleDeleteSecretForTenant).Methods("DELETE")

	r.HandleFunc(apiPathPrefix("/payments/{network}/{txid}"), payment.HandleGetPaymentByTenant).Methods("GET")
	r.HandleFunc(apiPathPrefix("/payments"), payment.HandleListPaymentsForTenant).Methods("GET")
	// just for local testing remove this

	r.HandleFunc(apiPathPrefix("/"), upstream.HandlePurgeResource).Methods("PURGE")
	r.HandleFunc(apiPathPrefix("/"), hpay.HandleRequest).Methods("GET", "POST")

	r.HandleFunc(apiPathPrefix("/ws"), wsHandler)

	r.HandleFunc(apiPathPrefix("/status/healthz"), handleHealthcheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            true,
	})
	h := c.Handler(r)
	l.Infof("Listening on port %s", port)
	return http.ListenAndServe(":"+port, h)
}
