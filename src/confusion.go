package src

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"
)

const (
	maxRetries     = 3
	retryDelay     = 1 * time.Second
	defaultTimeout = 10 * time.Second
)

type Vulnerability struct {
	Type      string `json:"type"`
	Purl      string `json:"purl"`
	Namespace string `json:"namespace,omitempty"`
	Evidence  string `json:"evidence"`
}

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
		logVulnerability(purl, output)
	case http.StatusOK:
		logNoVulnerability(purl)
	default:
		logUnexpectedStatus(purl, resp.StatusCode)
	}
}

func logVulnerability(purl string, output *os.File) {
	log.WithFields(logrus.Fields{
		"purl": purl,
	}).Warn("PURL is vulnerable to dependency confusion")

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	message := fmt.Sprintf("\n[%s] %s\n", red("VULNERABLE"), yellow("Dependency Confusion"))
	message += fmt.Sprintf("  PURL: %s\n\n", purl)

	fmt.Print(message)
	if output != nil {
		instance, err := packageurl.FromString(purl)
		if err != nil {
			log.WithError(err).Error("Failed to parse PURL")
			return
		}

		registry := packageTypeToRegistry[instance.Type]
		vuln := Vulnerability{
			Type:     "dependency_confusion",
			Purl:     purl,
			Evidence: buildPackageURL(registry, instance.Namespace, instance.Name),
		}
		jsonData, err := json.MarshalIndent(vuln, "", "  ")
		if err != nil {
			log.WithError(err).Error("Failed to marshal vulnerability data")
			return
		}
		fmt.Fprintf(output, "%s\n", jsonData)
	}
}

func logNoVulnerability(purl string) {
	log.WithFields(logrus.Fields{
		"purl": purl,
	}).Info("PURL is not vulnerable to dependency confusion")

	green := color.New(color.FgGreen).SprintFunc()
	message := fmt.Sprintf("[%s] %s\n", green("SAFE"), purl)
	fmt.Print(message)
}

func logUnexpectedStatus(purl string, statusCode int) {
	log.WithFields(logrus.Fields{
		"purl":        purl,
		"status_code": statusCode,
	}).Error("Received unexpected status code")

	yellow := color.New(color.FgYellow).SprintFunc()
	message := fmt.Sprintf("[%s] Unexpected status code %d for %s\n", yellow("WARNING"), statusCode, purl)
	fmt.Print(message)
}

type NamespaceResponse struct {
	Name          string `json:"name"`
	PackagesCount int    `json:"packages_count"`
	PackagesURL   string `json:"packages_url"`
}

func checkNamespaceExists(registry, namespace string) (bool, error) {
	cleanNamespace := sanitizeNamespace(namespace)
	urlString := buildNamespaceURL(registry, cleanNamespace)

	logNamespaceCheck(urlString, namespace, cleanNamespace)

	resp, err := HttpGetWithTimeout(urlString)
	if err != nil {
		return false, fmt.Errorf("failed to check namespace: %v", err)
	}
	defer resp.Body.Close()

	return processNamespaceResponse(resp, cleanNamespace)
}

func sanitizeNamespace(namespace string) string {
	cleanNamespace := strings.ReplaceAll(namespace, "@", "")
	return strings.ReplaceAll(cleanNamespace, "%40", "")
}

func buildNamespaceURL(registry, namespace string) string {
	return fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/namespaces/%s",
		registry, namespace)
}

func processNamespaceResponse(resp *http.Response, namespace string) (bool, error) {
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var namespaceResp NamespaceResponse
	if err := json.NewDecoder(resp.Body).Decode(&namespaceResp); err != nil {
		return false, fmt.Errorf("failed to parse namespace response: %v", err)
	}

	logNamespaceResult(namespace, namespaceResp.PackagesCount)
	return namespaceResp.PackagesCount > 0, nil
}

func checkPURLForVulnerabilities(registry, namespace, packageName, purl string, output *os.File) {
	decodedPackageName, err := url.QueryUnescape(packageName)
	if err != nil {
		log.WithField("error", fmt.Sprintf("Error decoding package name: %v", err)).Error("Package name error")
		return
	}

	if namespace != "" {
		handleNamespaceCheck(registry, namespace, purl, output)
		return
	}

	urlString := buildPackageURL(registry, namespace, decodedPackageName)
	checkPackageExistence(urlString, purl, output)
}

func handleNamespaceCheck(registry, namespace, purl string, output *os.File) {
	exists, err := checkNamespaceExists(registry, namespace)
	if err != nil {
		log.WithFields(logrus.Fields{
			"purl":  purl,
			"error": err,
		}).Error("Failed to check namespace existence")
		return
	}

	if exists {
		log.WithFields(logrus.Fields{
			"purl":      purl,
			"namespace": namespace,
		}).Info("Namespace exists, not vulnerable to dependency confusion")
	} else {
		logNamespaceVulnerability(purl, namespace, output)
	}
}

func buildPackageURL(registry, namespace, packageName string) string {
	if namespace != "" && packageName != "" {
		if registry == "npmjs.org" {
			return fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s/%s",
				registry, namespace, packageName)
		}
		return fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s:%s",
			registry, namespace, packageName)
	}
	return fmt.Sprintf("https://packages.ecosyste.ms/api/v1/registries/%s/packages/%s",
		registry, packageName)
}

func checkPackageExistence(urlString, purl string, output *os.File) {
	log.WithFields(logrus.Fields{
		"url":  urlString,
		"purl": purl,
	}).Info("Checking package existence")

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := HttpGetWithTimeout(urlString)
		if err != nil {
			log.WithField("error", fmt.Sprintf("Error calling API: %v", err)).Error("API call error")
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

func logNamespaceCheck(urlString, originalNamespace, cleanedNamespace string) {
	log.WithFields(logrus.Fields{
		"url":                urlString,
		"original_namespace": originalNamespace,
		"cleaned_namespace":  cleanedNamespace,
	}).Info("Checking namespace existence")
}

func logNamespaceResult(namespace string, packagesCount int) {
	log.WithFields(logrus.Fields{
		"namespace":      namespace,
		"packages_count": packagesCount,
	}).Info("Namespace check result")
}

func logNamespaceVulnerability(purl, namespace string, output *os.File) {
	log.WithFields(logrus.Fields{
		"purl":      purl,
		"namespace": namespace,
	}).Warn("Namespace does not exist, package is vulnerable to dependency confusion")

	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	message := fmt.Sprintf("\n[%s] %s\n", red("VULNERABLE"), yellow("Dependency Confusion"))
	message += fmt.Sprintf("  PURL: %s\n", purl)
	message += fmt.Sprintf("  Namespace: %s\n\n", namespace)

	fmt.Print(message)
	if output != nil {
		instance, err := packageurl.FromString(purl)
		if err != nil {
			log.WithError(err).Error("Failed to parse PURL")
			return
		}

		registry := packageTypeToRegistry[instance.Type]
		vuln := Vulnerability{
			Type:      "dependency_confusion",
			Purl:      purl,
			Namespace: namespace,
			Evidence:  buildNamespaceURL(registry, namespace),
		}
		jsonData, err := json.MarshalIndent(vuln, "", "  ")
		if err != nil {
			log.WithError(err).Error("Failed to marshal vulnerability data")
			return
		}
		fmt.Fprintf(output, "%s\n", jsonData)
	}
}
