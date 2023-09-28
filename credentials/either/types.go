package either

import (
	E "github.com/IBM/fp-go/either"
	C "github.com/ibm-hyper-protect/contract-go/credentials"
)

type (
	// service that solves a credential from a URL
	CredentialService = func(string) E.Either[error, C.Credential]
)
