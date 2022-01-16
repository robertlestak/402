package db

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the global database connection
var DB *gorm.DB

// Init initializes the database connection
func Init() error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PASSWORD"),
	)
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}
	return nil
}

// Paginate provides a paginator function
func Paginate(page, pageSize int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if page == 0 {
			page = 1
		}

		switch {
		case pageSize > 100:
			pageSize = 100
		case pageSize <= 0:
			pageSize = 10
		}

		offset := (page - 1) * pageSize
		return db.Offset(offset).Limit(pageSize)
	}
}

// Ping checks the database connection
func Ping(db *gorm.DB) error {
	d, derr := db.DB()
	if derr != nil {
		return derr
	}
	return d.Ping()
}

// Healthcheck checks the database connection with Ping, and can be extended for deeper health checks
func Healthcheck() error {
	if err := Ping(DB); err != nil {
		return err
	}
	return nil
}

// Healthchecker continually checks the DB connection and logs Fatal on any error, assuming orchestrator will handle restarts
func Healthchecker() error {
	for {
		if err := Healthcheck(); err != nil {
			log.Fatal(err)
			return err
		}
		time.Sleep(time.Second * 10)
	}
}
