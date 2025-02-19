# DepConfuse

A command-line tool to detect potential dependency confusion vulnerabilities from a Software Bill of Materials (SBOM) or list of package URLs (PURLs).

## Overview

DepConfuse helps security teams and developers identify packages that might be potentially vulnerable to dependency confusion attacks. It analyzes CycloneDX SBOMs or direct package URLs (PURLs) and checks package availability across multiple package registries.

## Installation

`git clone git@github.com:th3-j0k3r/DepConfuse.git`  
`cd DepConfuse`  
`go build`  

## Usage

DepConfuse can be used in two modes:

### 1. SBOM Analysis Mode
`./depconfuse --sbom /path/to/sbom.json --output results.txt`

### 2. PURL File Analysis Mode
`./depconfuse --file /path/to/purls.txt --output results.txt`


## Credits
This project uses the following open-source projects:

- [CycloneDX](https://cyclonedx.org/)
- [Package URL (PURL)](https://github.com/package-url/purl-spec) 
- [Echosyste.ms](https://ecosyste.ms/)
