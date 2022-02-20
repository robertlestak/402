package server

import (
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/robertlestak/402/pkg/upstream"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

// UpstreamServer is a server service dedicated solely to communicating with client-provided upstream.
// separating this from the main server allows for this to be placed in a DMZ separate from the central 402 stack
func UpstreamServer() error {
	l := log.WithFields(log.Fields{
		"action": "UpstreamServer",
	})
	l.Info("start")
	r := mux.NewRouter()
	r.HandleFunc(apiPathPrefix("/status/healthz"), handleHealthcheck)
	r.HandleFunc(apiPathPrefix("/upstream"), upstream.HandleGetResourceMeta).Methods("GET", "POST")
	port := os.Getenv("UPSTREAM_META_SERVICE_PORT")
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
