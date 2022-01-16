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
	Client            *redis.Client
	DefaultExpiration = time.Hour
)

const (
	cachePrefix                 = "pubsub:"
	jobsPrefix                  = "jobs:"
	JobPubSubCompleteNameSuffix = ":complete"
)

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

func AddJob(txid string, network string, encryptedMeta string) error {
	key := jobsPrefix + network
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "AddJob",
		"txid":    txid,
		"network": network,
		"key":     key,
	})
	l.Info("Adding job")
	return Client.HSet(key, txid, encryptedMeta).Err()
}

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

func PublishError(txid string, network string, err string) error {
	key := cachePrefix + network + JobPubSubCompleteNameSuffix
	l := log.WithFields(log.Fields{
		"package": "pubsub",
		"method":  "PublishError",
		"txid":    txid,
		"network": network,
		"key":     key,
		"err":     err,
	})
	l.Info("Publishing error")
	Client.HDel(jobsPrefix+network, txid)
	return Client.Publish(key, txid+":"+err).Err()
}

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

func JobCompleteNow(ctx context.Context, txid string, network string) (string, error) {
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
		default:
			continue
		}
	}
}

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

func ActiveJobs(fx func(string, string, string) error) error {
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
			em, derr := GetEncryptedMeta(t, b)
			if derr != nil {
				l.Error(derr)
				return derr
			}
			if err := fx(t, b, em); err != nil {
				l.Error(err)
				if cerr := PublishError(t, b, err.Error()); cerr != nil {
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

func ActiveJobsWorker(fx func(string, string, string) error) error {
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
