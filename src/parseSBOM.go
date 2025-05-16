package src

import (
	"flag"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func InitMain() {
	const banner = `
  ____                    ____                    __                      
 |  _ \    ___   _ __    / ___|   ___    _ __    / _|  _   _   ___    ___ 
 | | | |  / _ \ | '_ \  | |      / _ \  | '_ \  | |_  | | | | / __|  / _ \
 | |_| | |  __/ | |_) | | |___  | (_) | | | | | |  _| | |_| | \__ \ |  __/
 |____/   \___| | .__/   \____|  \___/  |_| |_| |_|    \__,_| |___/  \___|
                |_|                                                       
				`
	fmt.Println(banner)

	sbomFile := flag.String(sbomFlag, "", "Path to the SBOM file")
	purlFile := flag.String(purlFlag, "", "Path to the file containing PURLs")
	outputFile := flag.String(outputFlag, "", "Path to the output file")
	flag.Parse()

	if *sbomFile == "" && *purlFile == "" {
		fmt.Println("Please provide either --sbom or --file option")
		return
	}

	if *outputFile == "" {
		fmt.Println("Please provide --output option")
		return
	}

	output, err := os.Create(*outputFile)
	if err != nil {
		logError(fmt.Sprintf("Error creating output file: %v", err))
		return
	}
	defer output.Close()

	if *sbomFile != "" {
		handleSBOM(*sbomFile, output)
	} else {
		handlePURLFile(*purlFile, output)
	}
}

func logError(msg string) {
	log.WithField("error", msg).Error("Logging error")
}

func handleSBOM(sbomFile string, output *os.File) {
	file, err := os.Open(sbomFile)
	if err != nil {
		logError(fmt.Sprintf("Error opening SBOM file: %v", err))
		return
	}
	defer file.Close()

	bom, err := parseBOM(file)
	if err != nil {
		logError(fmt.Sprintf("Error parsing SBOM file: %v", err))
		return
	}

	for _, component := range *bom.Components {
		handlePURL(component.PackageURL, output)
	}
}

func parseBOM(file *os.File) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(file, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}
