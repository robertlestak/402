package vault

import (
	"fmt"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

// CleanupJob is a job to cleanup unused addresses
type CleanupJob struct {
	RetentionTime time.Duration
}

// Secret is a secret
type Secret struct {
	Path        string
	UpdatedTime time.Time
	MustCleanup bool
	Wallet      Wallet
}

// Cleanup checks a secret, determines if it should be cleaned up and cleans it up if necessary
func (s *Secret) Cleanup(retentionTime time.Duration) error {
	l := log.WithFields(log.Fields{
		"package":       "vault",
		"action":        "cleanup",
		"retentionTime": retentionTime,
		"path":          s.Path,
	})
	l.Debug("start")
	defer l.Debug("end")
	ss := Secret{
		Path: s.Path,
	}
	sd, merr := GetSecretRawWithFreshToken(s.Path)
	if merr != nil {
		l.Error(merr)
		return merr
	}
	var md map[string]interface{}
	var ok bool
	var ut string
	var dt string
	var ct string
	var err error
	var destroyed bool
	if md, ok = sd["metadata"].(map[string]interface{}); !ok {
		l.Error("no metadata found")
		return fmt.Errorf("no metadata found")
	}
	if destroyed, ok = md["destroyed"].(bool); ok {
		if destroyed {
			l.Debugf("Secret %s is destroyed", s)
			ss.MustCleanup = true
		}
	}
	l.Debugf("Got metadata %+v", md)
	if ct, ok = md["created_time"].(string); !ok {
		l.Info("created_time is not time.Time")
	}
	if ut, ok = md["updated_time"].(string); !ok {
		l.Info("updated_time is not time.Time")
	}
	if dt, ok = md["deletion_time"].(string); !ok {
		l.Info("deletion_time is not time.Time")
	}

	if ut == "" && ct != "" {
		ut = ct
	}
	if ut != "" && dt != "" {
		ut = dt
	}
	if ut != "" {
		s.UpdatedTime, err = time.Parse(time.RFC3339Nano, ut)
		if err != nil {
			l.Error(err)
			return err
		}
	}
	w := Wallet{}
	var nsd map[string]interface{}
	if nsd, ok = sd["data"].(map[string]interface{}); !ok {
		l.Error("no data found")
	}
	if nsd != nil {
		if err := w.ParseMap(nsd); err != nil {
			l.Error(err)
			return err
		}
		s.Wallet = w
	}
	if retentionTime > 0 && s.UpdatedTime.Add(retentionTime).Before(time.Now()) && s.Wallet.Txid == "" {
		l.Debugf("Secret %s must be cleaned up", s.Path)
		s.MustCleanup = true
	}
	//s.MustCleanup = true
	if s.MustCleanup {
		l.Debugf("secret %s must be cleaned up", s.Path)
		if err := DeleteSecret(s.Path); err != nil {
			l.Error(err)
			return err
		}
		l.Debugf("secret %s deleted", s.Path)
	}
	return nil
}

// cleanupWorkCollector is a worker cleanup secrets
func cleanupWorkCollector(retentionTime time.Duration, work chan Secret, res chan error) {
	l := log.WithFields(log.Fields{
		"package":       "vault",
		"action":        "cleanupWorkCollector",
		"retentionTime": retentionTime,
	})
	l.Debug("start")
	defer l.Debug("end")
	for j := range work {
		l.Debugf("cleanup job %+v", j)
		if err := j.Cleanup(retentionTime); err != nil {
			l.Error(err)
			res <- err
		} else {
			res <- nil
		}
	}
}

// GetSecrets gets all secrets and performs cleanup
func (c *CleanupJob) GetSecrets() error {
	l := log.WithFields(log.Fields{
		"action": "getSecrets",
	})
	l.Debug("start")
	defer l.Debug("end")
	sec, err := ListSecretsRetry(os.Getenv("VAULT_KV_NAME"))
	if err != nil {
		l.Error(err)
		return err
	}
	jobLen := 20
	work := make(chan Secret, len(sec))
	res := make(chan error, len(sec))
	if len(sec) < jobLen {
		jobLen = len(sec)
	}
	for i := 0; i < jobLen; i++ {
		go cleanupWorkCollector(c.RetentionTime, work, res)
	}
	for _, s := range sec {
		work <- Secret{
			Path: path.Join(os.Getenv("VAULT_KV_NAME"), s),
		}
	}
	close(work)
	for i := 0; i < len(sec); i++ {
		err := <-res
		if err != nil {
			l.Error(err)
			return err
		}
	}
	return nil
}

// Cleanup cleans up unused addresses beyond retention time
func Cleanup(retentionTime time.Duration) error {
	l := log.WithFields(log.Fields{
		"package": "cache",
	})
	l.Debug("Cleaning up unused addresses")
	if len(os.Args) < 5 {
		l.Error("no retention time specified")
		return fmt.Errorf("no retention time specified")
	}
	c := CleanupJob{
		RetentionTime: retentionTime,
	}
	if err := c.GetSecrets(); err != nil {
		l.Error(err)
		return err
	}
	return nil
}

// Cleaner is a cleanup job that runs continually
func Cleaner() {
	l := log.WithFields(log.Fields{
		"package": "vault",
	})
	l.Debug("cleaning up unused addresses")
	dur, err := time.ParseDuration(os.Getenv("VAULT_CLEANUP_INTERVAL"))
	if err != nil {
		l.Error(err)
		return
	}
	retention, rerr := time.ParseDuration(os.Getenv("VAULT_DEFAULT_RETENTIION_TIME"))
	if rerr != nil {
		l.Error(rerr)
		return
	}
	for {
		if err := Cleanup(retention); err != nil {
			l.Error(err)
		}
		time.Sleep(dur)
	}
}

// Cli is a command line interface for the vault apis
func Cli() error {
	l := log.WithFields(log.Fields{
		"package": "vault.Cli",
	})
	l.Debug("start")
	defer l.Debug("end")
	if len(os.Args) < 4 {
		l.Error("no command given")
		return fmt.Errorf("no command given")
	}
	switch os.Args[3] {
	case "list-secrets":
		sec, err := ListSecretsRetry(os.Getenv("VAULT_KV_NAME"))
		if err != nil {
			l.Error(err)
			return err
		}
		l.Debugf("Got secrets from vault %+v", sec)
		for _, s := range sec {
			fmt.Println(s)
		}
		return nil
	case "cleanup":
		retentionTime, err := time.ParseDuration(os.Args[4])
		if err != nil {
			l.Error(err)
			return err
		}
		if err := Cleanup(retentionTime); err != nil {
			l.Error(err)
			return err
		}
	}
	return nil
}
