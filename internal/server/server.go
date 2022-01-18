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
	"github.com/robertlestak/hpay/pkg/tenant"
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

	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/"), tenant.HandleGetTenant).Methods("GET")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/"), tenant.HandleCreateTenant).Methods("POST")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/"), tenant.HandleHeadPaymentRequest).Methods("HEAD")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/{plan}"), tenant.HandleGetTenant).Methods("GET")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/{plan}"), tenant.HandleCreateTenant).Methods("POST")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/{plan}"), tenant.HandleHeadPaymentRequest).Methods("HEAD")
	r.HandleFunc(apiPathPrefix("/tenants/{tenant}/jwt"), tenant.HandleGenerateNewJWT).Methods("GET")

	r.HandleFunc(apiPathPrefix("/plans"), tenant.HandleListAccessPlans).Methods("GET")
	r.HandleFunc(apiPathPrefix("/plans"), tenant.HandleCreateAccessPlan).Methods("POST")
	r.HandleFunc(apiPathPrefix("/plans"), tenant.HandleDeleteAccessPlan).Methods("DELETE")

	r.HandleFunc(apiPathPrefix("/"), upstream.HandlePurgeResource).Methods("PURGE")
	r.HandleFunc(apiPathPrefix("/"), hpay.HandleRequest).Methods("GET", "POST")

	r.HandleFunc(apiPathPrefix("/ws"), wsHandler)

	r.HandleFunc(apiPathPrefix("/status/healthz"), handleHealthcheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ","),
		AllowedHeaders:   strings.Split(os.Getenv("CORS_ALLOWED_HEADERS"), ","),
		AllowedMethods:   strings.Split(os.Getenv("CORS_ALLOWED_METHODS"), ","),
		AllowCredentials: true,
		Debug:            os.Getenv("CORS_DEBUG") == "true",
	})
	h := c.Handler(r)
	l.Infof("Listening on port %s", port)
	return http.ListenAndServe(":"+port, h)
}
