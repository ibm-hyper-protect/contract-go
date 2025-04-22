package encryption

import (
	_ "embed"
)

//go:embed ibm-hyper-protect-container-runtime-1-0-s390x-22-encrypt.crt
var EncryptionCertificateUbuntu string

//go:embed ibm-hyper-protect-container-runtime-1-0-s390x-22-encrypt.crt
var EncryptionCertificateRhel string
