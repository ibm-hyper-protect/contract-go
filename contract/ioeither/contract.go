// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package Datasource

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
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
)

var (
	getEnv        = R.Lookup[any](Contract.KeyEnv)
	getWorkload   = R.Lookup[any](Contract.KeyWorkload)
	getSigningKey = R.Lookup[any](Contract.KeySigningKey)
)

func toAny[A any](a A) any {
	return a
}

func anyToBytes(a any) []byte {
	return []byte(fmt.Sprintf("%s", a))
}

// computes the signature across workload and env
func createEnvWorkloadSignature(signer func([]byte) func([]byte) IOE.IOEither[error, []byte]) func([]byte) func(Contract.RawMap) IOE.IOEither[error, string] {
	// lookup workload and env
	getEnvO := F.Flow2(
		getEnv,
		O.Map(anyToBytes),
	)
	getWorkloadO := F.Flow2(
		getWorkload,
		O.Map(anyToBytes),
	)
	// produce the actual function
	return func(privKey []byte) func(Contract.RawMap) IOE.IOEither[error, string] {
		// callback to construct the digest
		sign := signer(privKey)
		// combine into a digest
		return func(contract Contract.RawMap) IOE.IOEither[error, string] {
			// lookup the
			return F.Pipe4(
				O.SequenceT2(getWorkloadO(contract), getEnvO(contract)),
				O.Map(T.Tupled2(B.Monoid.Concat)),
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
func upsertEnvWorkloadSignature(signer func([]byte) func([]byte) IOE.IOEither[error, []byte]) func([]byte) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
	// callback that can creates the signature
	envWorkloadSignature := createEnvWorkloadSignature(signer)

	return func(privKey []byte) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
		// callback to create the signature
		create := envWorkloadSignature(privKey)
		setSignature := F.Bind1st(R.UpsertAt[string, any], Contract.KeyEnvWorkloadSignature)

		return func(contract Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
			return F.Pipe4(
				contract,
				create,
				IOE.Map[error](toAny[string]),
				IOE.Map[error](setSignature),
				IOE.Map[error](I.Ap[Contract.RawMap, Contract.RawMap](contract)),
			)
		}
	}
}

// returns a function that adds the public part of the key to the input mapping
func addSigningKey(pubKey func([]byte) E.Either[error, []byte]) func(key []byte) func(Contract.RawMap) E.Either[error, Contract.RawMap] {
	// callback to decode the key
	getPemE := F.Flow2(
		pubKey,
		E.Map[error](F.Flow3(
			B.ToString,
			toAny[string],
			F.Bind1st(R.UpsertAt[string, any], Contract.KeySigningKey),
		)),
	)

	return func(key []byte) func(Contract.RawMap) E.Either[error, Contract.RawMap] {
		// function to add the pkey into a map
		pemE := F.Pipe1(
			key,
			getPemE,
		)
		// actually work on a map
		return func(data Contract.RawMap) E.Either[error, Contract.RawMap] {
			// insert into the map
			return F.Pipe1(
				pemE,
				E.Map[error](I.Ap[Contract.RawMap, Contract.RawMap](data)),
			)
		}
	}
}

// upsertSigningKey returns a function that adds the public part of the signing key
func upsertSigningKey(pubKey func([]byte) E.Either[error, []byte]) func([]byte) func(Contract.RawMap) E.Either[error, Contract.RawMap] {
	// bind the function to the callback that can extract a public key
	addSigningKeyE := addSigningKey(pubKey)
	setEnv := F.Bind1st(R.UpsertAt[string, any], Contract.KeyEnv)

	return func(privKey []byte) func(Contract.RawMap) E.Either[error, Contract.RawMap] {
		// adds the signing key to the env map
		addKeyE := addSigningKeyE(privKey)

		return func(contract Contract.RawMap) E.Either[error, Contract.RawMap] {
			// get the env part, fall back to the empty map, then insert the signature
			return F.Pipe5(
				contract,
				getEnv,
				O.Chain(Common.ToTypeO[Contract.RawMap]),
				O.GetOrElse(F.Constant(make(Contract.RawMap))),
				addKeyE,
				E.Map[error](F.Flow3(
					toAny[Contract.RawMap],
					setEnv,
					I.Ap[Contract.RawMap, Contract.RawMap](contract),
				)),
			)
		}
	}
}

// stringify serializes data to yaml if data is not a string, else it returns the string
func stringify(data any) E.Either[error, []byte] {
	return F.Pipe2(
		data,
		O.ToType[string],
		O.Fold(F.Nullary2(F.Constant(data), Y.Stringify[any]), F.Flow2(S.ToBytes, E.Of[error, []byte])),
	)
}

// function that accepts a map, transforms the given key and returns a map with the key encrypted
func upsertEncrypted(enc func(data []byte) IOE.IOEither[error, string]) func(string) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
	// callback that accepts the key
	return func(key string) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
		// callback to insert the key into the target
		setKey := F.Bind1st(R.UpsertAt[string, any], key)
		getKey := R.Lookup[any](key)
		// returns the actual upserter
		return func(dst Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
			// lookup the original key
			return F.Pipe3(
				dst,
				getKey,
				O.Map(F.Flow4(
					stringify,
					IOE.FromEither[error, []byte],
					IOE.Chain(enc),
					IOE.Map[error](F.Flow3(
						toAny[string],
						setKey,
						I.Ap[Contract.RawMap, Contract.RawMap](dst),
					)),
				)),
				O.GetOrElse(F.Constant(IOE.Of[error](dst))),
			)
		}
	}
}

// EncryptAndSignContract returns a function that signs the workload and env part of a contract and that adds the public key of the signature to the map
// the value of the input map must either be of type `string` or of type `Contract.RawMap`
//
// - enc encrypts a piece of data
// - signer signs a piece of data
// - pubKey extracts the public key from the private key
func EncryptAndSignContract(
	enc func(data []byte) IOE.IOEither[error, string],
	signer func([]byte) func([]byte) IOE.IOEither[error, []byte],
	pubKey func([]byte) E.Either[error, []byte],
) func([]byte) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
	// the upserter
	upsertKey := upsertSigningKey(pubKey)
	upsertSig := upsertEnvWorkloadSignature(signer)
	// the function that encrypts fields
	encrypter := upsertEncrypted(enc)
	encEnv := encrypter(Contract.KeyEnv)
	encWorkload := encrypter(Contract.KeyWorkload)
	encAttPubKey := encrypter(Contract.KeyAttestationPublicKey)
	// callback to handle signature
	return func(privKey []byte) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
		// the signature callback
		addPubKey := upsertKey(privKey)
		addSignature := upsertSig(privKey)
		// execute one step after the other
		return F.Flow6(
			addPubKey,
			IOE.FromEither[error, Contract.RawMap],
			IOE.Chain(encEnv),
			IOE.Chain(encWorkload),
			IOE.Chain(encAttPubKey),
			IOE.Chain(addSignature),
		)
	}
}
