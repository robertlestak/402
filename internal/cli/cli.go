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
	case "root-token":
		if t, err := auth.GenerateRootJWT(time.Time{}); err != nil {
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
