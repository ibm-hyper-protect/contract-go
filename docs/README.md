# Hyper Protect Contract Go Library - API Documentation

## Introduction

The `contract-go` library provides a comprehensive API for working with IBM Hyper Protect services. This documentation covers all available functions, their parameters, return values, and usage examples.

## Table of Contents

- [Configuration](#configuration)
- [Attestation Functions](#attestation-functions)
- [Certificate Functions](#certificate-functions)
- [Contract Functions](#contract-functions)
- [Image Functions](#image-functions)
- [Network Functions](#network-functions)
- [Common Patterns](#common-patterns)
- [Error Handling](#error-handling)

## Configuration

### Prerequisites

- **Go 1.24.7 or later**
- **OpenSSL** - Required for cryptographic operations

### Environment Variables

#### `OPENSSL_BIN` (Optional)

Configure the path to the OpenSSL binary. This is useful on systems where OpenSSL is not in the system PATH (e.g., Windows).

**Linux/macOS:**
```bash
export OPENSSL_BIN=/usr/bin/openssl
```

**Windows (PowerShell):**
```powershell
$env:OPENSSL_BIN="C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
```

**Windows (Command Prompt):**
```cmd
set OPENSSL_BIN=C:\Program Files\OpenSSL-Win64\bin\openssl.exe
```

---

## Attestation Functions

### HpcrGetAttestationRecords

Decrypts encrypted attestation records received from IBM Hyper Protect services.

**Package:** `github.com/ibm-hyper-protect/contract-go/attestation`

**Signature:**
```go
func HpcrGetAttestationRecords(data, privateKey string) (string, error)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `string` | Encrypted attestation data in the format `hyper-protect-basic.<password>.<data>` |
| `privateKey` | `string` | RSA private key (PEM format) used to decrypt the password |

**Returns:**
| Return | Type | Description |
|--------|------|-------------|
| Attestation Records | `string` | Decrypted attestation records |
| Error | `error` | Error if decryption fails or parameters are invalid |

**Example:**
```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/attestation"
)

func main() {
    // Encrypted attestation data received from HPVS
    encryptedData := "hyper-protect-basic.aBcD123..."

    // Your RSA private key
    privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`

    // Decrypt attestation records
    records, err := attestation.HpcrGetAttestationRecords(encryptedData, privateKey)
    if err != nil {
        log.Fatalf("Failed to decrypt attestation: %v", err)
    }

    fmt.Println("Attestation Records:", records)
}
```

**Common Errors:**
- `"required parameter is missing"` - One or more parameters are empty
- `"failed to decrypt password"` - Invalid private key or corrupted encrypted data
- `"failed to decrypt attestation records"` - Invalid password or corrupted data

---

## Certificate Functions


### HpcrDownloadEncryptionCertificates()
This function downloads HPCR encryption certificates from IBM Cloud.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/certificate"

func main() {
    certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersionsList, jsonFormat, certDownloadUrlTemplate)
}
```

#### Input(s)
1. List of versions to download (eg: ["1.1.14", "1.1.15"])
2. Output format (json or yaml)
3. Encryption certificate URL Template (default to `https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt`)

#### Output(s)
1. Certificates and versions as JSON string
2. Error (If any)


### HpcrGetEncryptionCertificateFromJson()
This function returns encryption certificate and version from HpcrDownloadEncryptionCertificates() output.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/certificate"

func main() {
    version, cert, err := HpcrGetEncryptionCertificateFromJson(sampleJsonData, desiredVersion)
}
```

#### Input(s)
1. Encryption certificate JSON string
2. Version name

#### Output(s)
1. Version name
2. Encryption Certificate
3. Error (If any)


### HpcrSelectImage()
This function selects the latest HPCR image details from image list out from IBM Cloud images API.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/image"

func main() {
    imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, version)
}
```

#### Input(s)
1. Image JSON from IBM Cloud images from Terraform, API or CLI. The input can be as follows:-
    1. Terraform `ibmcloud is images`: The input should be output of `data.ibm_is_images.hyper_protect_images.images`.
    2. IBM Cloud API: The result of following command should be input:
        ```bash
        curl -X GET "https://<region>.cloud.ibm.com/v1/images?version=2022-09-13&generation=2"  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" | jq .images
        ```
    3. IBM CLI output: The input should be output of `ibmcloud is images --json`.
2. version to select (optional)

#### Output(s)
1. Image ID
2. Image name
3. Image checksum
4. Image version
5. Error (If any)


### HpcrText()
This function generates Base64 for given string.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    base64, inputSha256, outputSha256, err := HpcrText(sampleStringData)
}
```

#### Input(s)
1. Text to encode

#### Output(s)
1. Base64 of input
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrTextEncrypted()
This function encrypts text and formats text as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encryptedText, inputSha256, outputSha256, err := HpcrTextEncrypted(sampleStringData, HyperProtectOsType, encryptionCertificate)
}
```

#### Input(s)
1. Text to encrypt
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrJson()
This function generates Base64 of JSON input

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    base64, inputSha256, outputSha256, err := HpcrJson(sampleStringJson)
}
```

#### Input(s)
1. Text to encode

#### Output(s)
1. Base64 of input
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrJsonEncrypted()
This function generates encrypts JSON and formats text as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encryptedJson, inputSha256, outputSha256, err := HpcrJsonEncrypted(sampleStringJson, HyperProtectOsType, encryptionCertificate)
}
```

#### Input(s)
1. JSON text to encrypt
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrTgz()
This function generates base64 of TGZ that contains files under the given folder

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encodedTgz, inputSha256, outputSha256, err := HpcrTgz(composePath)
}
```

#### Input(s)
1. Path of folder

#### Output(s)
1. Base64 of TGZ where TGZ is contents of given folder
2. Checksum of imput
3. Checksum of output
4. Error (If any)


### HpcrVerifyContract()
This function verifies if the parsed encrypted contract is schematically valid. The validation is successful, if error is nil.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    err := HpcrVerifyContract(contract, HyperProtectOsType)
}
```

#### Input(s)
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)

#### Output(s)
1. Error (if any)


### HpcrTgzEncrypted()
This function first generates base64 of TGZ that contains files under the given folder and then encrypts the data as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encodedTgz, inputSha256, outputSha256, err := HpcrTgzEncrypted(composePath, HyperProtectOsType, encryptionCertificate)
}
```

#### Input(s)
1. Path of folder
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. encrypted base64 of TGZ where TGZ is contents of given folder
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrContractSignedEncrypted()
This function generates a signed and encrypted contract with format `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    signedEncryptedContract, inputSha256, outputSha256, err := HpcrContractSignedEncrypted(contract, HyperProtectOsType, encryptionCertificate, privateKey)
}
```

#### Input(s)
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)
3. Encryption certificate (optional)
4. Private Key for signing

#### Output(s)
1. Signed and encrypted contract
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrContractSignedEncryptedContractExpiry()
This function generates a signed and encrypted contract with contract expiry enabled. The output will be of the format `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func usingCsrParams() {
    sampleCeCSRPems = map[string]interface{}{
		"country":  "IN",
		"state":    "Karnataka",
		"location": "Bangalore",
		"org":      "IBM",
		"unit":     "ISDL",
		"domain":   "HPVS",
		"mail":     "sashwat.k@ibm.com",
	}

    signedEncryptedCEContract, inputSha256, outputSha256, err := HpcrContractSignedEncryptedContractExpiry(contract, HyperProtectOsType, encryptionCertificate, privateKey, caCert, caKey, string(csrParams), "", sampleContractExpiryDays)
}

func usingCsrPem() {
    signedEncryptedCEContract, inputSha256, outputSha256, err := HpcrContractSignedEncryptedContractExpiry(contract, encryptionCertificate, privateKey, caCert, caKey, "", csr, sampleContractExpiryDays)
}
```

#### Input(s)
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs or hpcc-peerpod) (optional)
3. Encryption certificate (optional)
4. Private Key for signing
5. CA Certificate
6. CA Key
7. CSR Parameter JSON as string
8. CSR PEM file
9. Expiry of contract in number of days

The point 7 and 8 is one of. That is, either CSR parameters or CSR PEM file.

The CSR parameters should be of the format:-

```
"country":  "IN",
"state":    "Karnataka",
"location": "Bangalore",
"org":      "IBM",
"unit":     "ISDL",
"domain":   "HPVS",
"mail":     "sashwat.k@ibm.com"
```

#### Output(s)
1. Signed and encrypted contract
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrVerifyNetworkConfig

Validates network configuration schema for on-premise deployments of HPVS, HPCR RHVS, and HPCC Peer Pods.

**Package:** `github.com/ibm-hyper-protect/contract-go/network`

**Signature:**
```go
func HpcrVerifyNetworkConfig(networkConfig string) error
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `networkConfig` | `string` | Network configuration in YAML format |

**Returns:**
| Return | Type | Description |
|--------|------|-------------|
| Error | `error` | `nil` if valid, error with details if invalid |

**Example:**
```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/ibm-hyper-protect/contract-go/network"
)

func main() {
    // Read network config file
    configData, err := os.ReadFile("network-config.yaml")
    if err != nil {
        log.Fatal(err)
    }

    // Validate schema
    err = network.HpcrVerifyNetworkConfig(string(configData))
    if err != nil {
        log.Fatalf("Invalid network config: %v", err)
    }

    fmt.Println("Network configuration is valid!")
}
```

**Supported Platforms:**
- HPVS (Hyper Protect Virtual Servers)
- HPCR RHVS (Hyper Protect Container Runtime for Red Hat Virtualization)
- HPCC Peer Pod (Hyper Protect Confidential Container Peer Pods)

---

## Common Patterns

### Pattern 1: Complete Contract Workflow

Generate and deploy a signed, encrypted contract for HPVS:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/certificate"
    "github.com/ibm-hyper-protect/contract-go/contract"
)

func main() {
    // 1. Download encryption certificates
    versions := []string{"1.1.14", "1.1.15"}
    certsJSON, err := certificate.HpcrDownloadEncryptionCertificates(versions, "json", "")
    if err != nil {
        log.Fatal(err)
    }

    // 2. Get specific version certificate
    version, cert, err := certificate.HpcrGetEncryptionCertificateFromJson(certsJSON, "1.1.15")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Using certificate version: %s\n", version)

    // 3. Define your contract
    contractYAML := `
env: |
  type: env
  logging:
    logDNA:
      ingestionKey: your-key
workload: |
  type: workload
  compose:
    archive: your-archive
`

    // 4. Validate contract
    err = contract.HpcrVerifyContract(contractYAML, "hpvs")
    if err != nil {
        log.Fatalf("Contract validation failed: %v", err)
    }

    // 5. Generate signed and encrypted contract
    privateKey := `-----BEGIN RSA PRIVATE KEY-----
...your private key...
-----END RSA PRIVATE KEY-----`

    signedContract, inputHash, outputHash, err := contract.HpcrContractSignedEncrypted(
        contractYAML,
        "hpvs",
        cert,
        privateKey,
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Contract generated successfully!\n")
    fmt.Printf("Input SHA256: %s\n", inputHash)
    fmt.Printf("Output SHA256: %s\n", outputHash)
    fmt.Printf("Signed Contract: %s\n", signedContract)
}
```

### Pattern 2: Image Selection with Version Constraints

Select the latest compatible HPCR image:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os/exec"

    "github.com/ibm-hyper-protect/contract-go/image"
)

func main() {
    // Get images from IBM Cloud CLI
    cmd := exec.Command("ibmcloud", "is", "images", "--json")
    output, err := cmd.Output()
    if err != nil {
        log.Fatal(err)
    }

    // Select latest image with version >= 1.1.0
    imageID, imageName, checksum, version, err := image.HpcrSelectImage(
        string(output),
        ">=1.1.0",
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Selected Image:\n")
    fmt.Printf("  ID: %s\n", imageID)
    fmt.Printf("  Name: %s\n", imageName)
    fmt.Printf("  Version: %s\n", version)
    fmt.Printf("  Checksum: %s\n", checksum)
}
```

### Pattern 3: Working with Contract Expiry

Generate a contract with expiration:

```go
package main

import (
    "encoding/json"
    "log"

    "github.com/ibm-hyper-protect/contract-go/contract"
)

func main() {
    contractYAML := `...your contract...`
    privateKey := `...your private key...`
    caCert := `...your CA certificate...`
    caKey := `...your CA key...`

    // CSR parameters
    csrParams := map[string]interface{}{
        "country":  "US",
        "state":    "California",
        "location": "San Francisco",
        "org":      "MyOrg",
        "unit":     "Engineering",
        "domain":   "example.com",
        "mail":     "admin@example.com",
    }

    csrJSON, _ := json.Marshal(csrParams)

    // Generate contract with 90-day expiry
    signedContract, inputHash, outputHash, err := contract.HpcrContractSignedEncryptedContractExpiry(
        contractYAML,
        "hpvs",
        "",           // Use default encryption cert
        privateKey,
        caCert,
        caKey,
        string(csrJSON),
        "",           // Not using CSR PEM file
        90,           // Expire in 90 days
    )
    if err != nil {
        log.Fatal(err)
    }

    // Use the contract...
}
```

### Pattern 4: Encrypting Workload Data

Encrypt different types of data for contracts:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ibm-hyper-protect/contract-go/contract"
)

func main() {
    // Encrypt plain text
    text := "Hello, Hyper Protect!"
    encText, _, _, err := contract.HpcrTextEncrypted(text, "hpvs", "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted text: %s\n", encText)

    // Encrypt JSON
    jsonData := `{"key": "value", "number": 42}`
    encJSON, _, _, err := contract.HpcrJsonEncrypted(jsonData, "hpvs", "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted JSON: %s\n", encJSON)

    // Encrypt TGZ archive
    encTGZ, _, _, err := contract.HpcrTgzEncrypted("/path/to/compose/folder", "hpvs", "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted TGZ: %s\n", encTGZ)
}
```

---

## Error Handling

### Common Error Messages

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `"required parameter is empty"` | Missing required parameter | Ensure all required parameters are provided |
| `"required parameter is missing"` | Missing required parameter | Ensure all required parameters are provided |
| `"not a JSON data"` | Invalid JSON format | Verify JSON syntax |
| `"contract is not a JSON data"` | Contract is not valid JSON | Check contract format |
| `"openssl not found"` | OpenSSL not installed or not in PATH | Install OpenSSL or set `OPENSSL_BIN` |
| `"schema verification failed"` | Contract doesn't match schema | Review contract structure against schema |
| `"failed to decrypt password"` | Invalid private key or corrupted data | Verify private key matches public key |
| `"failed to encrypt key"` | Encryption operation failed | Check certificate validity |
| `"folder doesn't exists"` | Path not found | Verify folder path exists |
| `"no Hyper Protect image matching version found"` | No images match version constraint | Adjust version constraint or check available images |

### Best Practices for Error Handling

1. **Always Check Errors:**
```go
result, err := contract.HpcrText("data")
if err != nil {
    log.Fatalf("Operation failed: %v", err)
}
```

2. **Wrap Errors with Context:**
```go
signedContract, _, _, err := contract.HpcrContractSignedEncrypted(...)
if err != nil {
    return fmt.Errorf("failed to generate signed contract: %w", err)
}
```

3. **Validate Input Before Processing:**
```go
// Validate contract schema before encryption
err := contract.HpcrVerifyContract(contractYAML, "hpvs")
if err != nil {
    return fmt.Errorf("invalid contract: %w", err)
}

// Now proceed with encryption
signedContract, _, _, err := contract.HpcrContractSignedEncrypted(...)
```

4. **Use Checksums for Verification:**
```go
encrypted, inputHash, outputHash, err := contract.HpcrTextEncrypted(data, "hpvs", "")
if err != nil {
    return err
}

// Store checksums for later verification
fmt.Printf("Input checksum: %s\n", inputHash)
fmt.Printf("Output checksum: %s\n", outputHash)
```

---

## Platform-Specific Constants

The library supports three Hyper Protect platforms:

```go
const (
    HyperProtectOsHpvs     = "hpvs"         // Hyper Protect Virtual Servers
    HyperProtectOsHpcrRhvs = "hpcr-rhvs"    // HPCR for Red Hat Virtualization
    HyperProtectConfidentialContainerPeerPods = "hpcc-peerpod" // HPCC Peer Pods
)
```

Use these constants when calling functions that require a platform specification:

```go
import "github.com/ibm-hyper-protect/contract-go/common/general"

// Example usage
contract.HpcrContractSignedEncrypted(
    contractYAML,
    general.HyperProtectOsHpvs,  // or "hpvs"
    cert,
    privateKey,
)
```

---

## Additional Resources

- **Main Documentation:** [README.md](../README.md)
- **Go Package Docs:** [pkg.go.dev](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go)
- **Examples:** [samples/](../samples/)
- **Contributing:** [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Security:** [SECURITY.md](../SECURITY.md)

### IBM Hyper Protect Documentation

- [Confidential Computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se)
- [IBM Hyper Protect Virtual Servers](https://www.ibm.com/docs/en/hpvs/2.2.x)
- [IBM Hyper Protect Confidential Container](https://www.ibm.com/docs/en/hpcc/1.1.x)

### Related Projects

- [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) - CLI tool
- [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) - Terraform provider
- [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) - Kubernetes operator

---

**Last Updated:** 2025-01-26
