package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/robertlestak/402/pkg/auth"
	"github.com/robertlestak/402/pkg/tenant"
	"github.com/robertlestak/402/pkg/vault"
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
		// args in format:
		// 402 cli create-token claim1=val1 claim2=val2 ... exp=<exp>
		claims := jwt.MapClaims{
			"iss": os.Getenv("JWT_ISS"),
		}
		var expT time.Time
		for i := 3; i < len(os.Args); i++ {
			kv := strings.Split(os.Args[i], "=")
			if len(kv) != 2 {
				return fmt.Errorf("usage: 402 cli create-token claim1=val1 claim2=val2 ... exp=<exp>")
			}
			if kv[0] == "exp" {
				exp, err := time.ParseDuration(kv[1])
				if err != nil {
					return fmt.Errorf("usage: 402 cli create-token claim1=val1 claim2=val2 ... exp=<exp>")
				}
				expT = time.Now().Add(exp)
			} else {
				claims[kv[0]] = kv[1]
			}
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
