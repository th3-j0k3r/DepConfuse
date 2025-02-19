package src

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	logFile, err := os.OpenFile("logfile.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	log.SetOutput(logFile)

	log.SetFormatter(&logrus.JSONFormatter{})

	log.SetLevel(logrus.InfoLevel)
}
