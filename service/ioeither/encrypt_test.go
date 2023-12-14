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

package ioeither

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	T "github.com/ibm-hyper-protect/contract-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// keypair for testing
	privKeyE = Encrypt.OpenSSLPrivateKey()
	pubKeyE  = F.Pipe1(
		privKeyE,
		E.Chain(Encrypt.OpenSSLPublicKey),
	)
)

func TestEncryptFromStruct(t *testing.T) {
	// let's create a contract from scratch
	contract := &T.Contract{
		Env: &T.Env{
			Type: "env",
			Logging: &T.Logging{
				LogDNA: &T.LogDNA{
					IngestionKey: "key",
					Hostname:     "example.com",
				},
			},
		},
		Workload: &T.Workload{
			Type: "workload",
			ConfidentialContainers: T.AnyMap{
				"config": T.AnyMap{
					"allowAllEndpoints": false,
				},
			},
		},
	}
	// manually create our encryption service without DI
	// note that this is an `Either` of an encryption function because access to the public key might have failed
	encrypterE := F.Pipe1(
		pubKeyE,
		E.Map[error](EncryptContract(Encrypt.DefaultEncryption().EncryptBasic)),
	)

	// build the encryption chain
	encryptedIOE := F.Pipe2(
		encrypterE,
		// we need this FromEither because for testing we represented the key as an `Either`. In real life the key
		// will probably come from a location that requires a side effect, in that case it would already be in the `IOEither` monad, then
		// `FromEither` would not be required
		IOE.FromEither[error, func(ctr *T.Contract) IOE.IOEither[error, SC.EncryptedContract]], // what a type mess in go, nothing inside the [] should be needed :-)
		IOE.Chain(I.Ap[IOE.IOEither[error, SC.EncryptedContract]](contract)),
	)

	// execute the encryption here, when staying in the functional pattern this should be the last step
	encyptedE := encryptedIOE()

	// move over to the go world
	encrypted, err := E.UnwrapError(encyptedE)
	require.NoError(t, err)

	assert.Contains(t, encrypted, SC.KeyEnv)
	assert.Contains(t, encrypted, SC.KeyWorkload)
}

func TestEncryptFromStructAndKeyFromFile(t *testing.T) {
	// filename
	filename := "../../samples/data/sample.crt"
	require.FileExists(t, filename)

	// read the key from file
	pubKeyIOE := IOEF.ReadFile(filename)

	// let's create a contract from scratch
	contract := &T.Contract{
		Env: &T.Env{
			Type: "env",
			Logging: &T.Logging{
				LogDNA: &T.LogDNA{
					IngestionKey: "key",
					Hostname:     "example.com",
				},
			},
		},
		Workload: &T.Workload{
			Type: "workload",
			ConfidentialContainers: T.AnyMap{
				"config": T.AnyMap{
					"allowAllEndpoints": false,
				},
			},
		},
	}
	// manually create our encryption service without DI
	// note that this is an `Either` of an encryption function because access to the public key might have failed
	encrypterIOE := F.Pipe1(
		pubKeyIOE,
		IOE.Map[error](EncryptContract(Encrypt.DefaultEncryption().EncryptBasic)),
	)

	// build the encryption chain
	encryptedIOE := F.Pipe1(
		encrypterIOE,
		IOE.Chain(I.Ap[IOE.IOEither[error, SC.EncryptedContract]](contract)),
	)

	// execute the encryption here, when staying in the functional pattern this should be the last step
	encyptedE := encryptedIOE()

	// move over to the go world
	encrypted, err := E.UnwrapError(encyptedE)
	require.NoError(t, err)

	assert.Contains(t, encrypted, SC.KeyEnv)
	assert.Contains(t, encrypted, SC.KeyWorkload)
}
