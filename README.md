# DepConfuse

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/th3-j0k3r/DepConfuse)
![GitHub license](https://img.shields.io/github/license/th3-j0k3r/DepConfuse)
![GitHub last commit](https://img.shields.io/github/last-commit/th3-j0k3r/DepConfuse)
[![GitHub stars](https://img.shields.io/github/stars/th3-j0k3r/DepConfuse?style=social)](https://github.com/th3-j0k3r/DepConfuse/stargazers)

## Overview

**DepConfuse** is a command-line tool that proactively detects dependency confusion vulnerabilities. It scans SBOMs or PURLs to identify internal package names that could be subject to public package takeover, providing actionable insights to secure your software supply chain.

## ✨ Key Features

* **SBOM Analysis:** Scan a CycloneDX JSON SBOM to extract all declared dependencies.
* **PURL Analysis:** Directly analyze a list of Package URLs (PURLs) from a text file.
* **Multi-Registry Support:** Supports 20+ package registries.

## 📦 Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/th3-j0k3r/DepConfuse.git
    ```
2.  **Navigate to the Directory:**
    ```bash
    cd DepConfuse
    ```
3.  **Build the Executable:**
    ```bash
    go build -o depconfuse
    ```

## Usage

DepConfuse can be used in two modes:

### 1. SBOM Analysis Mode
`./depconfuse --sbom /path/to/sbom.json --output results.txt`

### 2. PURL File Analysis Mode
`./depconfuse --file /path/to/purls.txt --output results.txt`

![](/assets/depconfuse.png)



## Credits
This project uses the following open-source projects:

- [CycloneDX](https://cyclonedx.org/)
- [Package URL (PURL)](https://github.com/package-url/purl-spec) 
- [Echosyste.ms](https://ecosyste.ms/)
- [Alex birsan dependency confusion research](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
