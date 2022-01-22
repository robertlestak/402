package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/vault"
)

// Cli is the entrypoint func for cli operations
func Cli() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: 402 cli <action>")
	}
	switch os.Args[2] {
	case "create-token":
		if len(os.Args) < 4 {
			return fmt.Errorf("usage: 402 cli create-token <tenant-id> <exp>")
		}
		tid := os.Args[3]
		var exp time.Duration
		var expT time.Time
		var err error
		if len(os.Args) > 4 {
			exp, err = time.ParseDuration(os.Args[4])
			if err != nil {
				return fmt.Errorf("usage: 402 cli create-token <tenant-id> <exp>")
			}
			expT = time.Now().Add(exp)
		}
		if t, err := auth.GenerateSubJWT(tid, expT); err != nil {
			return err
		} else {
			fmt.Println(t)
		}
	case "vault":
		if err := vault.Cli(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown action: %s", os.Args[2])
	}
	os.Exit(0)
	return nil
}
