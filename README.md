# DepConfuse

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/th3-j0k3r/DepConfuse)
![GitHub license](https://img.shields.io/github/license/th3-j0k3r/DepConfuse)
![GitHub last commit](https://img.shields.io/github/last-commit/th3-j0k3r/DepConfuse)
[![GitHub stars](https://img.shields.io/github/stars/th3-j0k3r/DepConfuse?style=social)](https://github.com/th3-j0k3r/DepConfuse/stargazers)

## Overview

**DepConfuse** is a command-line tool that proactively detects dependency confusion vulnerabilities. It scans SBOMs or PURLs to identify internal package names that could be subject to public package takeover, providing actionable insights to secure your software supply chain.

## ✨ Key Features

* **SBOM-First Approach:** Built on CycloneDX SBOMs, DepConfuse detects dependency confusion risks across ecosystems, offering broader and more precise coverage than tools limited to individual package managers.
* **Multi-Registry Support:** Supports 20+ package registries. It covers npm, PyPI, Maven, NuGet, Docker Hub, Go modules, Ruby gems and more.
* **PURL Analysis:** Directly analyzes a list of Package URLs (PURLs) from a text file.
* **Flexible Input Modes:** Accepts both CycloneDX SBOMs (--sbom) and plain PURL lists (--file).
* **Ecosystems.ms Integration:** Provides real-time, namespace-aware checks across multiple ecosystems via a unified API.

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

## 🔧 Usage

DepConfuse can be used in two modes:

### 1. SBOM Analysis Mode
`./depconfuse --sbom /path/to/sbom.json --output results.txt`

### 2. PURL File Analysis Mode
`./depconfuse --file /path/to/purls.txt --output results.txt`

![](/demo/demo.gif)

## 🤝 Credits
This project uses the following open-source projects:

- [CycloneDX](https://cyclonedx.org/)
- [Package URL (PURL)](https://github.com/package-url/purl-spec) 
- [Echosyste.ms](https://ecosyste.ms/)
- [Alex Birsan dependency confusion research](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
