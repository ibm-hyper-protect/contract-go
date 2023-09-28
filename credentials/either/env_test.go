// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package either

import (
	"os"
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
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
	env := F.Pipe3(
		getwd,
		IOE.Chain(ENVIOE.EnvFromDotEnv),
		IOE.Map[error](ResolveCredential),
		IOE.ChainEitherK(I.Ap[E.Either[error, C.Credential]]("https://private.de.icr.io/zaas-hpse-dev/hpse-docker-hello-world-s390x/")),
	)
	// validate the credential
	assert.Equal(t, E.Of[error](C.Credential{Username: "iamapikey", Password: "password"}), env())
}
