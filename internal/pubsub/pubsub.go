package pubsub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/robertlestak/hpay/internal/utils"

	log "github.com/sirupsen/logrus"
)

var (
	// Client is the redis client
	Client *redis.Client
	// DefaultExpiration is the default expiration time of a job
	DefaultExpiration = time.Hour
)

const (
	// cachePrefix is the prefix for the pubsub
	cachePrefix = "pubsub:"
	// jobsPrefix is the prefix for the jobs
	jobsPrefix = "jobs:"
	// JobPubSubCompleteNameSuffix is the suffix for the complete pubsub
	JobPubSubCompleteNameSuffix = ":complete"
)

// Init initializes the pubsub client
func Init() error {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
	})
	l.Debug("Initializing redis client")
	Client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	cmd := Client.Ping()
	if cmd.Err() != nil {
		l.Error("Failed to connect to redis")
		return cmd.Err()
	}
	l.Debug("Connected to redis")
	return nil
}

// AddJob adds a job to the queue
func AddJob(txid string, network string, encryptedMeta string, metaHash string) error {
	key := jobsPrefix + network
	l := log.WithFields(log.Fields{
		"package":  "pubsub",
		"method":   "AddJob",
		"txid":     txid,
		"network":  network,
		"key":      key,
		"metaHash": metaHash,
	})
	l.Info("Adding job")
	data := encryptedMeta + ":" + metaHash
	return Client.HSet(key, txid, data).Err()
}

// PublishComplete publishes the job complete and removes it from the queue
func PublishComplete(txid string, network string) error {
	key := cachePrefix + network + JobPubSubCompleteNameSuffix
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "PublishComplete",
		"txid":    txid,
		"network": network,
		"key":     key,
	})
	l.Info("Publishing complete")
	Client.HDel(jobsPrefix+network, txid)
	return Client.Publish(key, txid).Err()
}

// PublishError publishes the job error and depending on the error type,
// it can be removed from the queue or left to be retried later
func PublishError(txid string, network string, err string, remove bool) error {
	key := cachePrefix + network + JobPubSubCompleteNameSuffix
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "PublishError",
		"txid":    txid,
		"network": network,
		"key":     key,
		"err":     err,
		"remove":  remove,
	})
	l.Info("Publishing error")
	if remove {
		l.Info("Removing job")
		Client.HDel(jobsPrefix+network, txid)
	} else {
		l.Info("Leaving job")
	}
	return Client.Publish(key, txid+":"+err).Err()
}

// JobCompleteSubscriber returns a subscriber for the job complete channel
func JobCompleteSubscriber(network string) *redis.PubSub {
	key := cachePrefix + network + JobPubSubCompleteNameSuffix
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "JobCompleteSubscriber",
		"network": network,
		"key":     key,
	})
	l.Info("Subscribing to job complete")
	subscriber := Client.Subscribe(key)
	return subscriber
}

// JobCompleteNow will wait for the job to be completed
// if either the context is canceled or the timeout is exceeded, it will return
func JobCompleteNow(ctx context.Context, txid string, network string, timeout time.Duration) (string, error) {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "JobCompleteNow",
		"txid":    txid,
		"network": network,
	})
	l.Info("Job complete")

	subscriber := JobCompleteSubscriber(network)

	for {
		msg, err := subscriber.ReceiveMessage()
		if err != nil {
			l.Error(err)
			return "", err
		}
		l.Infof("Got message: %s", msg.Payload)

		if strings.Contains(msg.Payload, txid) && strings.Contains(msg.Payload, ":") {
			parts := strings.Split(msg.Payload, ":")
			return "", errors.New(parts[1])
		} else if strings.Contains(msg.Payload, txid) {
			return msg.Payload, nil
		}
		select {
		case <-ctx.Done():
			l.Info("Context done")
			return "", nil
		case <-time.After(timeout):
			l.Info("Timeout")
			return "", errors.New("timeout")
		default:
			continue
		}
	}
}

// GetEncryptedMeta retrieves the encrypted meta object from the cache
// encrypted meta schema is stored as "encryptedMeta:metaHash" where
// encryptedMeta is the encrypted meta object and metaHash is the hash of the encrypted meta + recipients + secret
func GetEncryptedMeta(txid string, network string) (string, error) {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "GetEncryptedMeta",
		"txid":    txid,
		"network": network,
	})
	l.Info("Getting encrypted meta")
	key := jobsPrefix + network
	return Client.HGet(key, txid).Result()
}

// removableError checks the error and returns true
// the error is unrecoverable and warrants the job being removed from the queue
func removableError(err error) bool {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "removableError",
		"err":     err,
	})
	l.Info("Checking error")
	var removable bool
	switch err.Error() {
	case "timeout":
		removable = false
	case "context canceled":
		removable = false
	case "context deadline exceeded":
		removable = false
	default:
		removable = false
	}
	return removable
}

// ActiveJobs finds the currently pending jobs in the queue
// and passes the job data into the input function fx
func ActiveJobs(fx func(string, string, string, string) error) error {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "ActiveJobs",
	})
	l.Debug("Getting active jobs")
	var cursor uint64
	var initCursor bool = true
	var jobs []string
	for cursor > 0 || initCursor {
		scmd := Client.Scan(cursor, jobsPrefix+"*", 1000)
		if scmd.Err() != nil && scmd.Err() != redis.Nil {
			l.Error("Failed to get block index keys")
			return scmd.Err()
		}
		var ljobs []string
		ljobs, cursor = scmd.Val()
		for _, b := range ljobs {
			b = strings.TrimPrefix(b, jobsPrefix)
			if !utils.StringInSlice(b, jobs) {
				jobs = append(jobs, b)
			}
		}
		initCursor = false
	}
	for _, b := range jobs {
		l.Infof("get work for %s", b)
		scmd := Client.HKeys(jobsPrefix + b)
		if scmd.Err() != nil && scmd.Err() != redis.Nil {
			l.Error("Failed to get block index keys")
			return scmd.Err()
		}
		txs := scmd.Val()
		for _, t := range txs {
			l.Infof("check work for %s %s", b, t)
			emd, derr := GetEncryptedMeta(t, b)
			if derr != nil {
				l.Error(derr)
				return derr
			}
			emds := strings.Split(emd, ":")
			em := emds[0]
			mh := emds[1]
			if err := fx(t, b, em, mh); err != nil {
				l.Error(err)
				if cerr := PublishError(t, b, err.Error(), removableError(err)); cerr != nil {
					l.WithField("txid", t).Error("Failed to publish error")
					return cerr
				}
				return err
			} else {
				if cerr := PublishComplete(t, b); cerr != nil {
					l.WithField("txid", t).Error("Failed to publish complete")
					return cerr
				}
			}
		}
	}
	return nil
}

// ActiveJobsWorker is a worker that will check for active jobs
// and execute the input function fx on each job
func ActiveJobsWorker(fx func(string, string, string, string) error) error {
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "ActiveJobsWorker",
	})
	l.Info("Getting active jobs")
	for {
		ActiveJobs(fx)
		l.Debug("Sleeping")
		time.Sleep(time.Second * 1)
	}
}

// Ping returns the redis ping
func Ping() error {
	l := log.WithFields(log.Fields{
		"package": "cache",
	})
	l.Debug("Pinging redis")
	cmd := Client.Ping()
	if cmd.Err() != nil {
		l.Error("Failed to ping redis")
		return cmd.Err()
	}
	l.Debug("Pinged redis")
	return nil
}

// Healthcheck returns the redis healthcheck
func Healthcheck() {
	l := log.WithFields(log.Fields{
		"package": "cache",
	})
	l.Debug("Checking redis health")
	for {
		cmd := Client.Ping()
		if cmd.Err() != nil {
			l.WithError(cmd.Err()).Fatal("Redis healthcheck failed")
		}
		l.Debug("Pinged redis")
		time.Sleep(time.Second * 5)
	}
}
