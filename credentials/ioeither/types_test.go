package ioeither

import (
	"os"
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/stretchr/testify/assert"

	C "github.com/ibm-hyper-protect/contract-go/credentials"
	ENVIOE "github.com/ibm-hyper-protect/contract-go/environment/ioeither"
)

var (
	getwd = IOE.TryCatchError(os.Getwd)
)

func TestCredentialsFromEnv(t *testing.T) {
	// read from current directory
	credSvc := F.Pipe2(
		getwd,
		IOE.Chain(ENVIOE.EnvFromDotEnv),
		CredentialServiceFromEnv,
	)
	// the credential
	cred := credSvc("https://private.de.icr.io/zaas-hpse-dev/hpse-docker-hello-world-s390x/")
	// validate the credential
	assert.Equal(t, E.Of[error](C.Credential{Username: "iamapikey", Password: "password"}), cred())
}
