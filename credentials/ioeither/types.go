package ioeither

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	C "github.com/ibm-hyper-protect/contract-go/credentials"
	CE "github.com/ibm-hyper-protect/contract-go/credentials/either"
	ENV "github.com/ibm-hyper-protect/contract-go/environment"
)

type (
	// service that resolves a credential from a URL
	CredentialService = func(string) IOE.IOEither[error, C.Credential]
)

// CredentialServiceFromEnv create a credential service from an environment
func CredentialServiceFromEnv(env IOE.IOEither[error, ENV.Env]) CredentialService {
	// the memoized resolver
	resolver := F.Pipe2(
		env,
		IOE.Map[error](CE.ResolveCredential),
		IOE.Memoize[error, func(string) E.Either[error, C.Credential]],
	)
	// resolve the actual key from the resolver
	return func(key string) IOE.IOEither[error, C.Credential] {
		return F.Pipe1(
			resolver,
			IOE.ChainEitherK(I.Ap[E.Either[error, C.Credential]](key)),
		)
	}
}
