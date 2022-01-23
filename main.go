package main

import (
	"os"

	"github.com/robertlestak/hpay/internal/cache"
	"github.com/robertlestak/hpay/internal/cli"
	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/internal/pubsub"
	"github.com/robertlestak/hpay/internal/server"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	"github.com/robertlestak/hpay/pkg/tenant"
	"github.com/robertlestak/hpay/pkg/upstream"
	"github.com/robertlestak/hpay/pkg/vault"
	log "github.com/sirupsen/logrus"
)

func coreUtils() {
	l := log.WithFields(log.Fields{
		"action": "coreUtils",
	})
	l.Info("start")
	derr := db.Init()
	if derr != nil {
		l.WithError(derr).Fatal("Failed to initialize database")
	}
	db.DB.AutoMigrate(&payment.Payment{})
	db.DB.AutoMigrate(&payment.PaymentRequest{})
	db.DB.AutoMigrate(&upstream.Upstream{})
	db.DB.AutoMigrate(&tenant.Tenant{})
	db.DB.AutoMigrate(&tenant.AccessPlan{})
	db.DB.AutoMigrate(&tenant.AccessPlanAmount{})
	if uuerr := upstream.Init(); uuerr != nil {
		l.WithError(uuerr).Fatal("Failed to initialize upstreams")
	}
	if os.Getenv("VAULT_ENABLE") == "true" {
		_, verr := vault.NewClient()
		if verr != nil {
			l.WithError(verr).Fatal("Failed to initialize vault")
		}
		if os.Getenv("VAULT_CLEANUP_ENABLE") == "true" {
			go vault.Cleaner()
		}
	}
}

func init() {
	ll := log.InfoLevel
	var err error
	ll, err = log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)

	l := log.WithFields(log.Fields{
		"action": "init",
	})
	l.Info("start")
	if kerr := auth.InitSignKeys(); kerr != nil {
		l.WithError(kerr).Fatal("Failed to initialize auth keys")
	}
	if cerr := cache.Init(); cerr != nil {
		l.WithError(cerr).Fatal("Failed to initialize cache")
	}
	if perr := pubsub.Init(); perr != nil {
		l.WithError(perr).Fatal("Failed to initialize pubsub")
	}
	l.Info("end")
	if len(os.Args) > 1 && os.Args[1] != "upstream-server" {
		coreUtils()
	}
}

func serverUtils() {
	go cache.Healthcheck()
	go pubsub.ActiveJobsWorker(hpay.ValidateEncryptedPayment)
	go pubsub.Healthcheck()
	go db.Healthchecker()
}

func main() {
	l := log.WithFields(log.Fields{
		"action": "main",
	})
	l.Info("start")
	if len(os.Args) < 2 {
		l.Fatal("Usage: 402 <action>")
	}
	switch os.Args[1] {
	case "server":
		serverUtils()
		if err := server.Server(); err != nil {
			l.WithError(err).Fatal("Failed to start server")
		}
	case "upstream-server":
		if err := server.UpstreamServer(); err != nil {
			l.WithError(err).Fatal("Failed to start upstream server")
		}
	case "cli":
		if err := cli.Cli(); err != nil {
			l.WithError(err).Fatal("Failed to start cli")
		}
	default:
		l.Fatal("Unknown action")
	}
}
