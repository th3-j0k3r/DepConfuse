package src

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	maxRetries     = 3
	retryDelay     = 1 * time.Second
	defaultTimeout = 10 * time.Second
)

func HttpGetWithTimeout(url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: defaultTimeout,
	}
	return client.Get(url)
}

func handleAPIResponse(resp *http.Response, purl string, output *os.File) {
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		log.WithFields(logrus.Fields{
			"purl": purl,
		}).Warn("PURL is potentially vulnerable to dependency confusion")
		fmt.Printf("Warning: PURL %s is potentially vulnerable to dependency confusion\n", purl)
		if output != nil {
			fmt.Fprintf(output, "Warning: PURL %s is potentially vulnerable to dependency confusion\n", purl)
		}
	case http.StatusOK:
		log.WithFields(logrus.Fields{
			"purl": purl,
		}).Info("PURL is not vulnerable to dependency confusion")
	default:
		log.WithFields(logrus.Fields{
			"purl":        purl,
			"status_code": resp.StatusCode,
		}).Error("Received unexpected status code")
	}
}

func checkPURLForVulnerabilities(registry, namespace, packageName, purl string, output *os.File) {
	var urlString string

	decodedPackageName, err := url.QueryUnescape(packageName)
	if err != nil {
		logError(fmt.Sprintf("Error decoding package name: %v", err))
		return
	}

	if namespace != "" && decodedPackageName != "" {
		if registry == "npmjs.org" {
			urlString = fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s/%s", registry, namespace, decodedPackageName)
		} else {
			urlString = fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s:%s", registry, namespace, decodedPackageName)
		}
	} else {
		urlString = fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s", registry, decodedPackageName)
	}

	log.WithFields(logrus.Fields{
		"url":  urlString,
		"purl": purl,
	}).Info("Sending HTTP request")

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := HttpGetWithTimeout(urlString)
		if err != nil {
			logError(fmt.Sprintf("Error calling API: %v", err))
			return
		}

		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			log.WithFields(logrus.Fields{
				"attempt": attempt + 1,
				"purl":    purl,
			}).Warn("Retrying request due to server error")
			time.Sleep(retryDelay)
			continue
		}

		handleAPIResponse(resp, purl, output)
		break
	}
}
