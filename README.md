# Contract Go

[![contract-go CI](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml/badge.svg)](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/ibm-hyper-protect/contract-go?include_prereleases)](https://github.com/ibm-hyper-protect/contract-go/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-hyper-protect/contract-go)](https://goreportcard.com/report/ibm-hyper-protect/contract-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/ibm-hyper-protect/contract-go.svg)](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go/v2)
[![User Documentation](https://img.shields.io/badge/User%20Documentation-GitHub%20Pages-blue.svg)](https://ibm-hyper-protect.github.io/contract-go)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go library for generating, signing, and encrypting deployment contracts for IBM Confidential Computing workloads on IBM Z and LinuxONE.

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

The `contract-go` library automates the provisioning of IBM Confidential Computing solutions:

- **IBM Confidential Computing Container Runtime (CCRT)** (formerly known as Hyper Protect Virtual Servers) — Deploy confidential computing workloads on IBM Z and LinuxONE using IBM Secure Execution for Linux
- **IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions (CCRV)** (formerly known as Hyper Protect Container Runtime for Red Hat Virtualization Solutions) — Purpose-built for hosting critical, centralized services within tightly controlled virtualized environments on IBM Z
- **IBM Confidential Computing Containers for Red Hat OpenShift Container Platform (CCCO)** (formerly known as IBM Hyper Protect Confidential Container for Red Hat OpenShift Container Platform) — Deploy isolated workloads using IBM Secure Execution for Linux, integrated with Red Hat OpenShift Container Platform

This library provides cryptographic operations, contract generation, validation, and management capabilities for deploying workloads in secure enclaves on IBM Z and LinuxONE.

### Who Is This For?

This library is for **Go developers** who need to programmatically generate, sign, and encrypt deployment contracts for IBM Confidential Computing services. Common users include:

- **DevOps engineers** automating confidential computing deployments via Terraform or CI/CD pipelines
- **Solution providers** building applications that run in secure enclaves
- **Platform teams** managing contract lifecycle across environments

### What is IBM Confidential Computing?

IBM Confidential Computing services protect data in use by leveraging the IBM Secure Execution for Linux feature on IBM Z and LinuxONE hardware. Each deployment is configured through a **contract** — an encrypted YAML definition file that specifies workload, environment, and attestation settings. This library automates the generation and management of these contracts.

Learn more:

- [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se)
- [IBM Confidential Computing Container Runtime](https://www.ibm.com/docs/en/cccr/2.2.x)
- [IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions](https://www.ibm.com/docs/en/ccrv/1.1.x)
- [IBM Confidential Computing Containers for Red Hat OpenShift](https://www.ibm.com/docs/en/ccro/1.1.x)

## Features

- **Attestation Management**
  - Decrypt encrypted attestation records
  - Verify signature of attestation records against IBM certificates

- **Certificate Operations**
  - Download HPVS encryption certificates from IBM Cloud
  - Extract specific encryption certificates by version
  - Validate expiry of encryption certificate
  - **Validate complete certificate chains** (encryption cert -> intermediate -> root)
  - **Check certificate revocation status** using CRL (Certificate Revocation List)
  - **Download CRLs** from certificate distribution points

- **Contract Generation**
  - Generate Base64-encoded data from text, JSON, initdata annotation and docker compose / podman play archives
  - Create signed and encrypted & signed contracts
  - Support contract expiry with CSR (Certificate Signing Request)
  - Load built-in workload and env contract templates
  - Validate contract schemas
  - Decrypt encrypted text in Hyper Protect format
  - Password-protected private key support for decrypting attestation records and generate signed contracts

- **Archive Management**
  - Generate Base64 tar archives of `docker-compose.yaml` or `pods.yaml`
  - Support encrypted base64 tar generation

- **Image Selection**
  - Retrieve latest HPVS image details from IBM Cloud API
  - Filter images by semantic versioning

- **Network Validation**
  - Validate network-config schemas for on-premise deployments
  - Support HPVS, HPCR RHVS, and HPCC Peer Pod configurations

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

### Encode Text

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/contract"
)

func main() {
    text := "Hello, IBM Confidential Computing!"

    encoded, inputHash, outputHash, err := contract.HpcrText(text)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Base64 encoded: %s\n", encoded)
    fmt.Printf("Input SHA256:  %s\n", inputHash)
    fmt.Printf("Output SHA256: %s\n", outputHash)
}
```

### Load Contract Templates

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/contract"
)

func main() {
    // Retrieve workload template only
    workloadTemplate, err := contract.HpcrContractTemplate("workload")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Workload Template:\n%s\n", workloadTemplate)

    // Retrieve env template only
    envTemplate, err := contract.HpcrContractTemplate("env")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Env Template:\n%s\n", envTemplate)

    // Retrieve combined contract scaffold:
    // workload: | <workload template>
    // env: | <env template>
    contractTemplate, err := contract.HpcrContractTemplate("")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Combined Contract Template:\n%s\n", contractTemplate)
}
```

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
attestationPublicKey: LS0tLS1CRUdJTi...
`
    privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`

    // Generate signed and encrypted contract
    signedContract, inputHash, outputHash, err := contract.HpcrContractSignedEncrypted(
        contractYAML,
        "ccrt",              // Platform type (ccrt, ccrv, or ccco)
        "",                  // Use default encryption certificate
        privateKey,          // Your RSA private key
        "",                  // Password for encrypted private key (empty if not encrypted)
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signed Contract: %s\n", signedContract)
    fmt.Printf("Input SHA256: %s\n", inputHash)
    fmt.Printf("Output SHA256: %s\n", outputHash)
}
```

### Using Password-Protected Private Keys

If your private key is encrypted with a password, provide it as the last parameter:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/contract"
)

func main() {
    contractYAML := `...` // Your contract YAML
    
    // Encrypted private key (with password protection)
    encryptedPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1234567890ABCDEF

MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`

    password := "your-secure-password"

    // Generate signed and encrypted contract with password-protected key
    signedContract, inputHash, outputHash, err := contract.HpcrContractSignedEncrypted(
        contractYAML,
        "ccrt",
        "",
        encryptedPrivateKey,
        password,  // Provide password for encrypted private key
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

### Validate Certificate Documents

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/v2/certificate"
)

func main() {
    // Download IBM encryption certificate
    versions := []string{"1.1.15"}
    certsJSON, err := certificate.HpcrDownloadEncryptionCertificates(versions, "json", "")
    if err != nil {
        log.Fatal(err)
    }

    // Extract encryption certificate
    _, encCert, _, _, _, err := certificate.HpcrGetEncryptionCertificateFromJson(certsJSON, "1.1.15")
    if err != nil {
        log.Fatal(err)
    }

    // Load intermediate and root certificates
    // In production, obtain these from IBM or DigiCert
    intermediateCert := `-----BEGIN CERTIFICATE-----
... IBM intermediate CA certificate ...
-----END CERTIFICATE-----`
    
    rootCert := `-----BEGIN CERTIFICATE-----
... DigiCert root CA certificate ...
-----END CERTIFICATE-----`

    digicertIntermediateCert := `-----BEGIN CERTIFICATE-----
... DigiCert intermediate CA certificate ...
-----END CERTIFICATE-----`

    // Validate encryption certificate document (chain + signature + dates)
    valid, msg, err := certificate.HpcrVerifyEncryptionCertificateDocument(
        encCert,                  // encryption certificate document
        intermediateCert,         // IBM intermediate CA certificate
        digicertIntermediateCert, // DigiCert intermediate CA certificate
        rootCert,                 // DigiCert root CA certificate
    )
    if err != nil || !valid {
        log.Fatalf("Certificate validation failed: %v", err)
    }

    fmt.Printf("%s\n", msg)

    // Attestation certificate document (for combined CRL check)
    attestationCert := `-----BEGIN CERTIFICATE-----
... attestation certificate document ...
-----END CERTIFICATE-----`

    // Validate CRL signature and ensure encryption certificate serial is not revoked
    valid, msg, err = certificate.HpcrValidateCertificateRevocationList(
        encCert,
        intermediateCert,
    )
    if err != nil {
        log.Fatal(err)
    }
    if !valid {
        log.Fatalf("Encryption CRL validation failed: %s", msg)
    }
    fmt.Printf("%s\n", msg)

    // Validate CRL signature and ensure attestation certificate serial is not revoked
    valid, msg, err = certificate.HpcrValidateCertificateRevocationList(
        attestationCert,
        intermediateCert,
    )
    if err != nil {
        log.Fatal(err)
    }
    if !valid {
        log.Fatalf("Attestation CRL validation failed: %s", msg)
    }

    fmt.Printf("%s\n", msg)
}
```

## Documentation

Comprehensive documentation is available at:

- **[User Documentation](https://ibm-hyper-protect.github.io/contract-go)** — Detailed API reference and usage examples
- **[Go Package Documentation](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go/v2)** — Generated Go docs
- **[Examples](samples/)** — Sample contracts and configurations

## Supported Platforms

| Platform | Official Name | Version | Support Status |
|----------|---------------|---------|----------------|
| CCRT | IBM Confidential Computing Container Runtime (CCRT) | 2.2.x | Supported |
| CCRV | IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions (CCRV) | 1.1.x | Supported |
| CCCO | IBM Confidential Computing Containers for Red Hat OpenShift Container Platform (CCCO) | 1.1.x | Supported |

## Examples

The [`samples/`](samples/) directory contains example configurations:

- [Simple Contract](samples/simple_contract.yaml)
- [Contract with Attestation Public Key](samples/attest_pub_key_contract.yaml)
- [Workload Configuration](samples/workload.yaml)
- [Encrypted Contract](samples/sign/contract.enc.yaml)
- [CCCO Signed & Encrypted Contract](samples/ccco/signed-encrypt-ccco.yaml)
- [Docker Compose](samples/tgz/docker-compose.yaml)
- [Certificate Chain Validation](samples/certificate-chain/)

## Related Projects

This library is used by several tools in the IBM Confidential Computing ecosystem:

| Project | Description |
|---------|-------------|
| [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) | CLI tool for generating IBM Confidential Computing contracts |
| [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) | Terraform provider for IBM Confidential Computing contracts |
| [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) | Kubernetes operator for contract management |
| [linuxone-vsi-automation-samples](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples) | Examples for IBM Confidential Computing deployments |

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
