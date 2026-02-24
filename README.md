# Contract Go

[![contract-go CI](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml/badge.svg)](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/ibm-hyper-protect/contract-go?include_prereleases)](https://github.com/ibm-hyper-protect/contract-go/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-hyper-protect/contract-go)](https://goreportcard.com/report/ibm-hyper-protect/contract-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/ibm-hyper-protect/contract-go.svg)](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go/v2)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Note:** The offering name has been changed from **Hyper Protect Virtual Servers (HPVS)** to **IBM Confidential Computing Container Runtime (CCCR)**.

A Go library for automating the provisioning and management of IBM Hyper Protect confidential computing workloads.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Supported Platforms](#supported-platforms)
- [Examples](#examples)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Overview

The `contract-go` library automates the provisioning of IBM Hyper Protect confidential computing solutions:

- **IBM Confidential Computing Container Runtime (CCCR)** - Secure virtual servers on IBM Cloud
- **IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions (CCCRV)**
- **IBM Confidential Computing Containers for Red Hat OpenShift Container Platform (HPCC)**

This library provides cryptographic operations, contract generation, validation, and management capabilities for deploying workloads in secure enclaves on IBM LinuxONE.

### What are Hyper Protect Services?

IBM Hyper Protect services provide confidential computing capabilities that protect data in use by leveraging Secure Execution feature of Z. 

Learn more:

- [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se)
- [IBM Confidential Computing Container Runtime (CCCR)](https://www.ibm.com/docs/en/hpvs/2.2.x)
- [IBM Confidential Computing Containers for Red Hat OpenShift Container Platform](https://www.ibm.com/docs/en/hpcc/1.1.x)

## Features

- **Attestation Management**
  - Decrypt encrypted attestation records

- **Certificate Operations**
  - Download CCCR encryption certificates from IBM Cloud
  - Extract specific encryption certificates by version
  - Validate expiry of encryption certificate

- **Contract Generation**
  - Generate Base64-encoded data from text, JSON, initdata annotation and docker compose / podman play archives
  - Create encrypted and signed contracts
  - Support contract expiry with CSR (Certificate Signing Request)
  - Validate contract schemas
  - Decrypt encrypted text in Hyper Protect format

- **Archive Management**
  - Generate Base64 tar archives of `docker-compose.yaml` or `pods.yaml`
  - Support encrypted base64 tar generation

- **Image Selection**
  - Retrieve latest CCCR image details from IBM Cloud API
  - Filter images by semantic versioning

- **Network Validation**
  - Validate network-config schemas for on-premise deployments
  - Support CCCR, CCCRV, and IBM Confidential Computing Containers for Red Hat OpenShift Container Platform configurations

## Installation

```bash
go get github.com/ibm-hyper-protect/contract-go/v2
```

### Prerequisites

- **Go 1.24.7 or later**
- **OpenSSL** - Required for encryption operations
  - On Linux: `apt-get install openssl` or `yum install openssl`
  - On macOS: `brew install openssl`
  - On Windows: [Download OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)

#### Optional: Custom OpenSSL Path

If OpenSSL is not in your system PATH, set the `OPENSSL_BIN` environment variable:

```bash
# Linux/macOS
export OPENSSL_BIN=/usr/bin/openssl

# Windows (PowerShell)
$env:OPENSSL_BIN="C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
```

## Quick Start

### Generate a Signed and Encrypted Contract

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/contract"
)

func main() {
    // Your contract YAML
    contractYAML := `
env: |
  type: env
  logging:
    logRouter:
      hostname: 5c2d6b69-c7f0-41bd-b69b-240695369d6e.ingress.us-south.logs.cloud.ibm.com
      iamApiKey: ab00e3c09p1d4ff7fff9f04c12183413
workload: |
  type: workload
  compose:
    archive: your-archive
attestationPublicKey: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF4cklNT3RvSktWRTZQbGhvVlJ1dgorb3YxaW1jOEZRZUdQZ3VoVFBpQUFrNDVqRStJSnVKTHZtVHFkOE8yVlZwT05iZEhiN3ZpWGEydUwxeFBOcUp2ClVpVmZNTDUyN1B4V25TU3drcitKNDYwamZvZCtaMkJOQ0k1eVV6dVYxQVhvNHV3YmVLVzNYbVM2b2FIT1YrNmsKU1YwWCt3cFE5a3J5QnJ2NWVJc2tsSTBtS3JnaXBOc2N4b3hvNG4rRDlPMWRDVU5XRzZ4MmlpVnVLeXp4VzZZTgordW9wNHZxb3VMM2pGQ1crVkRGVHgycGViNzNqL2V6WnRUVVhEbStPZTc1V21zVkxjUUg4RXZYbVFsRVAvbEduCnZZMWQ1RXI1ZjlBSU5yOEdRWjM1OHNrWENvdCtseDZiMmQveTZwWEFOTFpBR2ZoRmZLSUMxSVdHOTQrRVdqMG4KUFB6Y1NpeHhHUk53bHZjV3BDY3hKTHFEb1VCaDF0NVA4OGJTVVJUVnpuZUVydDVYbUtjRVdDd3JsSGRrSWdGYgp1azFpbWlEOHl4S2RtZmNKdzZzRm5NeDlTb3FxSFFqNk9FUFZrV3E3Y1VYQUVMN05PSzlWTnZzZUxlNnEwRkRVClNLOSt5Ty9PdEdtSEFMcFJtY2dzNGlKOVJmRTlZQUt0a1JQRlRETUdYR0lFUGdnQkIyMHRlblk0ZTRyaXE1UWgKYWp1Y2txd3psRkhjbEZLWk9jMXNMR3NCRmhHSERIZm1taWNnWkhBdVN5YVpaM29QM3czbmhNK2IwT2grSjFSMwpWQUVWWUlDMzArVUZVR1dyTU40Q3ZDLzZaVk5YVkZ4ZkZMcU8raGFnNnI4Q3VqVEtLQ3NiaE5kaVNoNlRvdWhUCjZNY2N3OVg2bkpPdFBhK0E3L0ZVV3BVQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
`

    // Generate signed and encrypted contract
    signedContract, inputHash, outputHash, err := contract.HpcrContractSignedEncrypted(
        contractYAML,
        "hpvs",              // Hyper Protect OS type (CCCR)
        "",                  // Use default encryption certificate
        privateKey,          // Your RSA private key
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signed Contract: %s\n", signedContract)
    fmt.Printf("Input SHA256: %s\n", inputHash)
    fmt.Printf("Output SHA256: %s\n", outputHash)
}
```

### Select Latest HPCR Image

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/image"
)

func main() {
    // Image JSON from IBM Cloud
    imageJSON := `[...]` // Your IBM Cloud images JSON

    // Get latest image matching version constraint
    imageID, imageName, checksum, version, err := image.HpcrSelectImage(
        imageJSON,
        ">=1.1.0", // Optional version constraint
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Image ID: %s\n", imageID)
    fmt.Printf("Image Name: %s\n", imageName)
    fmt.Printf("Checksum: %s\n", checksum)
    fmt.Printf("Version: %s\n", version)
}
```

## Documentation

Comprehensive documentation is available at:

- **[User Documentation](https://ibm-hyper-protect.github.io/contract-go)** - Detailed API reference and usage examples
- **[Go Package Documentation](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go/v2)** - Generated Go docs
- **[Examples](samples/)** - Sample contracts and configurations

## Supported Platforms

| Platform | Description | Support Status |
|----------|-------------|----------------|
| CCCR | IBM Confidential Computing Container Runtime | Supported |
| CCCRV | IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions | Supported |
| IBM Confidential Computing Containers for Red Hat OpenShift Container Platform | IBM Confidential Computing Containers for Red Hat OpenShift Container Platform | Supported |

## Examples

The [`samples/`](samples/) directory contains example configurations:

- [Simple Contract](samples/simple_contract.yaml)
- [Workload Configuration](samples/workload.yaml)
- [Network Configuration](samples/network/network_config.yaml)
- [Docker Compose](samples/tgz/docker-compose.yaml)

## Related Projects

This library is used by several tools in the IBM Hyper Protect ecosystem:

| Project | Description |
|---------|-------------|
| [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) | CLI tool for generating Hyper Protect contracts |
| [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) | Terraform provider for Hyper Protect contracts |
| [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) | Kubernetes operator for contract management |
| [linuxone-vsi-automation-samples](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples) | Terraform examples for CCCR and CCCRV |
| [hyper-protect-virtual-server-samples](https://github.com/ibm-hyper-protect/hyper-protect-virtual-server-samples) | CCCR feature samples and scripts |

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Opening issues
- Submitting pull requests
- Code style and conventions
- Testing requirements

Please also read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

### Reporting Issues

We use GitHub issue templates to help us understand and address your concerns efficiently:

- **[Report a Bug](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=bug_report.yml)** - Found a bug? Let us know!
- **[Request a Feature](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=feature_request.yml)** - Have an idea for improvement?
- **[Ask a Question](https://github.com/ibm-hyper-protect/contract-go/issues/new?template=question.yml)** - Need help using the library?

### Security

- **Security Vulnerabilities**: Report via [GitHub Security Advisories](https://github.com/ibm-hyper-protect/contract-go/security/advisories/new) - **DO NOT** create public issues
- See our complete [Security Policy](SECURITY.md) for details

### Community

- **[Discussions](https://github.com/ibm-hyper-protect/contract-go/discussions)** - General questions and community discussion
- **[Documentation](https://ibm-hyper-protect.github.io/contract-go)** - Comprehensive API documentation
- **[Maintainers](MAINTAINERS.md)** - Current maintainer list and contact info

## Contributors

![Contributors](https://contrib.rocks/image?repo=ibm-hyper-protect/contract-go)
