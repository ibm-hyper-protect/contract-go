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

	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	O "github.com/IBM/fp-go/option"
	R "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	Contract "github.com/ibm-hyper-protect/contract-go/contract"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	Types "github.com/ibm-hyper-protect/contract-go/types"
)

var (
	getEnv        = R.Lookup[string](Contract.KeyEnv)
	getWorkload   = R.Lookup[string](Contract.KeyWorkload)
	getSigningKey = R.Lookup[any](Contract.KeySigningKey)
)

// upsertPubKeyIntoEnv adds the public signing key to the env section of the contract
// TODO write using optics
func upsertPubKeyIntoEnv(pubKey []byte) func(ctr *Types.Env) *Types.Env {
	// convert key to string
	key := B.ToString(pubKey)
	return F.Flow2(
		O.FromNillable[Types.Env],
		O.Fold(
			func() *Types.Env {
				return &Types.Env{
					Type:       Types.TypeEnv,
					SigningKey: &key,
				}
			}, func(env *Types.Env) *Types.Env {
				cpy := *env
				cpy.SigningKey = &key
				return &cpy

			}),
	)
}

// upsertPubKey adds the public signing key to the contract
// TODO write using optics
func upsertPubKey(pubKey []byte) func(ctr *Types.Contract) *Types.Contract {
	upsertEnv := upsertPubKeyIntoEnv(pubKey)
	return F.Flow2(
		O.FromNillable[Types.Contract],
		O.Fold(
			func() *Types.Contract {
				return &Types.Contract{
					Env: upsertEnv(nil),
				}
			},
			func(ctr *Types.Contract) *Types.Contract {
				cpy := *ctr
				cpy.Env = upsertEnv(ctr.Env)
				return &cpy
			}),
	)
}

// computes the signature across workload and env
func createEnvWorkloadSignature(signer func([]byte) func([]byte) IOE.IOEither[error, []byte]) func([]byte) func(ctr SC.EncryptedContract) IOE.IOEither[error, string] {
	// produce the actual function
	return func(privKey []byte) func(ctr SC.EncryptedContract) IOE.IOEither[error, string] {
		// callback to construct the digest
		sign := signer(privKey)
		// combine into a digest
		return func(contract SC.EncryptedContract) IOE.IOEither[error, string] {
			// lookup the
			return F.Pipe5(
				O.SequenceT2(getWorkload(contract), getEnv(contract)),
				O.Map(T.Tupled2(S.Monoid.Concat)),
				O.Map(S.ToBytes),
				IOE.FromOption[[]byte](func() error {
					return fmt.Errorf("the contract is missing [%s] or [%s] or both", Contract.KeyEnv, Contract.KeyWorkload)
				}),
				IOE.Chain(sign),
				IOE.Map[error](Common.Base64Encode),
			)
		}
	}
}

// constructs a workload across workload and env and adds this to the map
func upsertEnvWorkloadSignature(
	enc func(data []byte) IOE.IOEither[error, string],
	signer func([]byte) func([]byte) IOE.IOEither[error, []byte],
) func([]byte) func(ctr SC.EncryptedContract) IOE.IOEither[error, SC.EncryptedContract] {
	// callback that can creates the signature
	envWorkloadSignature := createEnvWorkloadSignature(signer)

	return func(privKey []byte) func(SC.EncryptedContract) IOE.IOEither[error, SC.EncryptedContract] {
		// callback to create the signature
		create := envWorkloadSignature(privKey)
		setSignature := F.Bind1st(R.UpsertAt[string, string], Contract.KeyEnvWorkloadSignature)

		return func(contract SC.EncryptedContract) IOE.IOEither[error, SC.EncryptedContract] {
			return F.Pipe2(
				contract,
				create,
				// enable again when https://github.com/ibm-hyper-protect/contract-go/pull/342 gets fixed
				// IOE.Map[error](S.ToBytes),
				// IOE.Chain(enc),
				IOE.Map[error](F.Flow2(
					setSignature,
					I.Ap[SC.EncryptedContract, SC.EncryptedContract](contract),
				)),
			)
		}
	}
}

// EncryptAndSignContract returns a function that signs the workload and env part of a contract and that adds the public key of the signature
//
// - enc encrypts a piece of data
// - signer signs a piece of data
// - pubKey extracts the public key from the private key
func EncryptAndSignContract(
	enc func(data []byte) IOE.IOEither[error, string],
	signer func([]byte) func([]byte) IOE.IOEither[error, []byte],
	pubKey func([]byte) E.Either[error, []byte],
) func(privKey []byte) ContractEncrypter {
	// string encrypzet
	encStrg := F.Flow2(
		S.ToBytes,
		enc,
	)
	upsertSig := upsertEnvWorkloadSignature(enc, signer)
	// callback to handle signature
	return func(privKey []byte) ContractEncrypter {
		// insert public key into contract
		addSigningKey := F.Pipe2(
			privKey,
			pubKey,
			E.Map[error](upsertPubKey),
		)
		// upsert the signature
		addSignature := upsertSig(privKey)

		return func(ctr *Types.Contract) IOE.IOEither[error, SC.EncryptedContract] {

			return F.Pipe4(
				addSigningKey,
				E.Map[error](F.Flow2(
					I.Ap[*Types.Contract](ctr),
					SC.SerializeContract,
				)),
				IOE.FromEither[error, SC.EncryptedContract],
				IOE.Chain(IOE.TraverseRecord[string](encStrg)),
				IOE.Chain(addSignature),
			)
		}
	}
}
