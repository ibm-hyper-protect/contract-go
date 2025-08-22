# Hyper Protect Contract Go Library

## Introduction

The library is developed to automate the process for provisioning Hyper Protect Virtual Servers for VPC and Hyper Protect Container Runtime.


## Configuration

#### Prerequisites

##### `OPENSSL_BIN` (optional)

You can configure the path to the `openssl` binary using the `OPENSSL_BIN` environment variable.
It is useful especially on systems where `openssl` is not available in the system `PATH` (for example, on Windows).

#### Usage:

Set the `OPENSSL_BIN` environment variable to the full path of your `openssl` executable.

##### On Linux/macOS:

```bash
export OPENSSL_BIN=/usr/bin/openssl
```

On Windows (PowerShell):
```powershell
$env:OPENSSL_BIN="C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
```

## Usage

### HpcrGetAttestationRecords()
This function decrypts encrypted attestation records.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/attestation"

func main() {
    decryptedAttestationRecords, err := HpcrGetAttestationRecords(encryptedChecksum, privateKey)
}
```

#### Inputs
1. Encrypted attestation records
2. Private key

#### Outputs
1. Decrypted attestation records
2. Error (If any)


### HpcrDownloadEncryptionCertificates()
This function downloads HPCR encryption certificates from IBM Cloud.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/certificate"

func main() {
    certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersionsList, jsonFormat, certDownloadUrlTemplate)
}
```

#### Inputs
1. List of versions to download (for example: ["1.1.14", "1.1.15"])
2. Output format (JSON or YAML)
3. Encryption certificate URL Template (default to `https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt`)

#### Outputs
1. Certificates and versions as JSON string
2. Error (If any)


### HpcrGetEncryptionCertificateFromJson()
This function returns the encryption certificate and version from HpcrDownloadEncryptionCertificates() output.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/certificate"

func main() {
    version, cert, err := HpcrGetEncryptionCertificateFromJson(sampleJsonData, desiredVersion)
}
```

#### Inputs
1. Encryption certificate JSON string
2. Version name

#### Outputs
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

#### Inputs
1. Image JSON from IBM Cloud images from Terraform, API, or CLI. The input can be as follows:-
    1. Terraform `ibmcloud is images`: The input should be output of `data.ibm_is_images.hyper_protect_images.images`.
    2. IBM Cloud API: The result of following command should be input:
        ```bash
        curl -X GET "https://<region>.cloud.ibm.com/v1/images?version=2022-09-13&generation=2"  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" | jq .images
        ```
    3. IBM CLI output: The input should be output of `ibmcloud is images --json`.
2. Version to select (optional)

#### Outputs
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

#### Inputs
1. Text to encode

#### Outputs
1. Base64 of input
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrTextEncrypted()
This function encrypts text and formats tex as `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encryptedText, inputSha256, outputSha256, err := HpcrTextEncrypted(sampleStringData, HyperProtectOsType, encryptionCertificate)
}
```

#### Inputs
1. Text to encrypt
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)
3. Encryption certificate (optional)

#### Outputs
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

#### Inputs
1. Text to encode

#### Outputs
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

#### Inputs
1. JSON text to encrypt
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)
3. Encryption certificate (optional)

#### Outputs
1. Encrypted text
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrTgz()
This function generates a Base64 of TGZ that contains files under the given folder

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encodedTgz, inputSha256, outputSha256, err := HpcrTgz(composePath)
}
```

#### Input
1. Path of folder

#### Outputs
1. Base64 of TGZ where TGZ is the contents of given folder
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrVerifyContract()
This function verifies whether the parsed encrypted contract is schematically valid. The validation is successful, if error is nil.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    err := HpcrVerifyContract(contract, HyperProtectOsType)
}
```

#### Inputs
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)

#### Outputs
1. Error (if any)


### HpcrTgzEncrypted()
This function first generates Base64 of TGZ that contains files under the given folder and then encrypts the data as `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/contract"

func main() {
    encodedTgz, inputSha256, outputSha256, err := HpcrTgzEncrypted(composePath, HyperProtectOsType, encryptionCertificate)
}
```

#### Inputs
1. Path of folder
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)
3. Encryption certificate (optional)

#### Outputs
1. Encrypted Base64 of TGZ where TGZ is the contents of given folder
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

#### Inputs
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)
3. Encryption certificate (optional)
4. Private Key for signing

#### Outputs
1. Signed and encrypted contract
2. Checksum of input
3. Checksum of output
4. Error (If any)


### HpcrContractSignedEncryptedContractExpiry()
This function generates a signed and encrypted contract with contract expiry enabled. The output is of the format `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

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

#### Inputs
1. Contract
2. Hyper Protect OS (hpvs or hpcr-rhvs) (optional)
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

#### Outputs
1. Signed and encrypted contract
2. Checksum of input
3. Checksum of output
4. Error (If any)
