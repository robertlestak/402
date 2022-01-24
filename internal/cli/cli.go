package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/tenant"
	"github.com/robertlestak/hpay/pkg/vault"
	log "github.com/sirupsen/logrus"
)

func resetusage(tf string) error {
	l := log.WithFields(log.Fields{
		"action": "resetusage",
	})
	l.Info("start")
	l.Info("Resetting usage for " + tf)
	err := tenant.GlobalResetUsage(tf)
	if err != nil {
		l.WithError(err).Error("Failed to reset usage")
		return err
	}
	l.Info("Reset usage for " + tf)
	l.Info("end")
	return nil
}

// Cli is the entrypoint func for cli operations
func Cli() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: 402 cli <action>")
	}
	switch os.Args[2] {
	case "create-token":
		if len(os.Args) < 4 {
			return fmt.Errorf("usage: 402 cli create-token <tenant-id> <pid> <exp>")
		}
		tid := os.Args[3]
		pid := os.Args[4]
		var exp time.Duration
		var expT time.Time
		var err error
		if len(os.Args) > 5 {
			exp, err = time.ParseDuration(os.Args[5])
			if err != nil {
				return fmt.Errorf("usage: 402 cli create-token <tenant-id> <pid> <exp>")
			}
			expT = time.Now().Add(exp)
		}
		claims := jwt.MapClaims{
			"pid": pid,
			"sub": tid,
			"iss": os.Getenv("JWT_ISS"),
		}
		if t, err := auth.GenerateSubJWT(claims, expT); err != nil {
			return err
		} else {
			fmt.Println(t)
		}
	case "vault":
		if err := vault.Cli(); err != nil {
			return err
		}
	case "reset-usage":
		if len(os.Args) < 4 {
			return fmt.Errorf("usage: 402 cli reset-usage <time-frame>")
		}
		tf := os.Args[3]
		if err := resetusage(tf); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown action: %s", os.Args[2])
	}
	os.Exit(0)
	return nil
}
