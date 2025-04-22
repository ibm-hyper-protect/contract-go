# Hyper Protect Contract Go Library

## Introduction

The library has been developed to simply the process for provisioning Hyper Protect Virtual Servers for VPC and Hyper Protect Container Runtime.

For more details on Hyper Protect Virtual Servers for VPC and Hyper Protect Container Runtime, refer [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se) and [IBM Hyper Protect Virtual Servers](https://www.ibm.com/docs/en/hpvs/2.2.x).


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

#### Input(s)
1. Encrypted attestation records
2. Private key

#### Output(s)
1. Decrypted attestation records


### HpcrDownloadEncryptionCertificates()
This function downloads HPCR encryption certificates from IBM Cloud.

### Example
```go
import "github.com/ibm-hyper-protect/contract-go/certificate"

func main() {
    certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersionsList)
}
```

#### Input(s)
1. List of versions to download (eg: ["1.1.14", "1.1.15"])

#### Output(s)
1. Certificates and versions as JSON string


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
2. Hyper Protect OS (ubuntu or rhel) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input
3. Checksum of output


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
2. Hyper Protect OS (ubuntu or rhel) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input
3. Checksum of output


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
2. Hyper Protect OS (ubuntu or rhel) (optional)
3. Encryption certificate (optional)

#### Output(s)
1. encrypted base64 of TGZ where TGZ is contents of given folder
2. Checksum of input
3. Checksum of output


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
2. Hyper Protect OS (ubuntu or rhel) (optional)
3. Encryption certificate (optional)
4. Private Key for signing

#### Output(s)
1. Signed and encrypted contract
2. Checksum of input
3. Checksum of output


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
2. Hyper Protect OS (ubuntu or rhel) (optional)
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
1. Image JSON from IBM Cloud images API
2. version to select (optional)

#### Output(s)
1. Image ID
2. Image name
3. Image checksum
4. Image version
