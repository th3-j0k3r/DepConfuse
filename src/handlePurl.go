package src

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/package-url/packageurl-go"
)

func handlePURL(purl string, output *os.File) {
	instance, err := packageurl.FromString(purl)
	if err != nil {
		logError(fmt.Sprintf("Error processing PURL: %v", err))
		return
	}

	var packageType = instance.Type
	var namespace = instance.Namespace
	var packageName = instance.Name

	var decodedPURL = purl
	if registry, exists := packageTypeToRegistry[packageType]; exists {
		checkPURLForVulnerabilities(registry, namespace, packageName, decodedPURL, output)
	} else {
		logError(fmt.Sprintf("Unknown package type: %s for purl %s", packageType, decodedPURL))
	}
}

func handlePURLFile(purlFile string, output *os.File) {
	file, err := os.Open(purlFile)
	if err != nil {
		logError(fmt.Sprintf("Error opening PURL file: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "pkg:") {
			handlePURL(line, output)
		}
	}

	if err := scanner.Err(); err != nil {
		logError(fmt.Sprintf("Error reading PURL file: %v", err))
	}
}
