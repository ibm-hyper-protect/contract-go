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
	"fmt"
	"testing"

	B "github.com/IBM/fp-go/bytes"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	Types "github.com/ibm-hyper-protect/contract-go/types"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
	"github.com/stretchr/testify/require"
)

func TestEncryptAndSign(t *testing.T) {

	// filename
	filename := "../../samples/data/sample.crt"
	require.FileExists(t, filename)

	// read the key from file
	encKeyIOE := IOEF.ReadFile(filename)

	// private key for signing
	signKeyIOE := F.Pipe1(
		privKeyE,
		IOE.FromEither[error, []byte],
	)

	// let's create a contract from scratch
	contract := &Types.Contract{
		Env: &Types.Env{
			Type: "env",
			Logging: &Types.Logging{
				LogDNA: &Types.LogDNA{
					IngestionKey: "key",
					Hostname:     "example.com",
				},
			},
		},
		Workload: &Types.Workload{
			Type: "workload",
			ConfidentialContainers: Types.AnyMap{
				"config": Types.AnyMap{
					"allowAllEndpoints": false,
				},
			},
		},
	}

	// this is the encryption service
	encAndSign := F.Pipe2(
		encKeyIOE,
		IOE.Map[error](func(encKey []byte) func(privKey []byte) ContractEncrypter {
			defEnc := Encrypt.DefaultEncryption()
			return EncryptAndSignContract(defEnc.EncryptBasic(encKey), defEnc.SignDigest, defEnc.PubKey)
		}),
		IOE.Ap[ContractEncrypter](signKeyIOE),
	)

	// apply the encryption service to the contract
	resIOE := F.Pipe3(
		encAndSign,
		// serialize to a string map
		IOE.Chain(I.Ap[IOE.IOEither[error, SC.EncryptedContract]](contract)),
		// serialize to YAML
		IOE.ChainEitherK(Y.Stringify[SC.EncryptedContract]),
		IOE.Map[error](B.ToString),
	)

	// just print for the moment
	fmt.Println(resIOE())
}
