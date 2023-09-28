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
	"regexp"
	"testing"

	_ "embed"

	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	R "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	Contract "github.com/ibm-hyper-protect/contract-go/contract"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
	"github.com/stretchr/testify/assert"
)

//go:embed samples/contract1.yaml
var Contract1 string

var (
	// keypair for testing
	privKeyE = Encrypt.OpenSSLPrivateKey()
	pubKeyE  = F.Pipe1(
		privKeyE,
		E.Chain(Encrypt.OpenSSLPublicKey),
	)

	// the encryption function based on the keys
	openSSLEncryptBasicIOE = F.Pipe2(
		pubKeyE,
		IOE.FromEither[error, []byte],
		IOE.Map[error](func(pubKey []byte) func([]byte) IOE.IOEither[error, string] {
			return Encrypt.EncryptBasic(Encrypt.OpenSSLRandomPassword(32), Encrypt.AsymmetricEncryptPub(pubKey), Encrypt.SymmetricEncrypt)
		}),
	)
)

func openSSLEncryptAndSignContract(pubKey []byte) func([]byte) func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap] {
	return EncryptAndSignContract(Encrypt.EncryptBasic(Encrypt.OpenSSLRandomPassword(32), Encrypt.AsymmetricEncryptPub(pubKey), Encrypt.SymmetricEncrypt), Encrypt.OpenSSLSignDigest, Encrypt.OpenSSLPublicKey)
}

func TestAddSigningKey(t *testing.T) {
	privKeyE := Encrypt.OpenSSLPrivateKey()
	// add to key
	addKey := F.Pipe1(
		privKeyE,
		E.Map[error](addSigningKey(Encrypt.OpenSSLPublicKey)),
	)
	// the target map
	var env Contract.RawMap

	augE := F.Pipe3(
		addKey,
		E.Chain(I.Ap[E.Either[error, Contract.RawMap]](env)),
		E.ChainOptionK[Contract.RawMap, any](func() error {
			return fmt.Errorf("No key [%s]", Contract.KeySigningKey)
		})(getSigningKey),
		E.Chain(Common.ToTypeE[string]),
	)

	pubE := F.Pipe2(
		privKeyE,
		E.Chain(Encrypt.OpenSSLPublicKey),
		E.Map[error](B.ToString),
	)

	assert.Equal(t, pubE, augE)
}

// regular expression used to split the token
var tokenRe = regexp.MustCompile(`^hyper-protect-basic\.((?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?)\.((?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?)$`)

// regular expression used to check for the existence of a public key
var keyRe = regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`)

func TestUpsertEncrypted(t *testing.T) {
	// the encryption function
	upsertIOE := F.Pipe1(
		openSSLEncryptBasicIOE,
		IOE.Map[error](upsertEncrypted),
	)
	// encrypt env
	encEnv := F.Pipe1(
		upsertIOE,
		IOE.Map[error](I.Ap[func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap]](Contract.KeyEnv)),
	)
	// prepare some data
	data := Contract.RawMap{
		Contract.KeyEnv: Contract.RawMap{
			"type": "env",
		},
	}
	// encrypt the data
	resIOE := F.Pipe1(
		encEnv,
		IOE.Chain(I.Ap[IOE.IOEither[error, Contract.RawMap]](data)),
	)
	// validate that the key exists and that it is a token
	getKeyIOE := F.Flow2(
		R.Lookup[any](Contract.KeyEnv),
		IOE.FromOption[any](func() error {
			return fmt.Errorf("Key not found")
		}),
	)

	r := F.Pipe3(
		resIOE,
		IOE.Chain(getKeyIOE),
		IOE.ChainEitherK(Common.ToTypeE[string]),
		IOE.ChainEitherK(E.FromPredicate(tokenRe.MatchString, func(s string) error {
			return fmt.Errorf("string [%s] is not a valid typer protect token", s)
		})),
	)

	assert.True(t, E.IsRight(r()))
}

func TestUpsertSigningKey(t *testing.T) {
	privKeyE := Encrypt.OpenSSLPrivateKey()
	// add to key
	upsertKeyE := F.Pipe1(
		privKeyE,
		E.Map[error](upsertSigningKey(Encrypt.OpenSSLPublicKey)),
	)
	// prepare some contract without a key
	contractE := F.Pipe2(
		Contract1,
		S.ToBytes,
		Y.Parse[Contract.RawMap],
	)
	// actually upsert
	resE := F.Pipe4(
		upsertKeyE,
		E.Ap[E.Either[error, Contract.RawMap]](contractE),
		E.Flatten[error, Contract.RawMap],
		E.Chain(Y.Stringify[Contract.RawMap]),
		E.Map[error](B.ToString),
	)
	// check that the serialized form contains the key
	checkE := F.Pipe1(
		resE,
		E.Map[error](keyRe.MatchString),
	)

	assert.Equal(t, E.Of[error](true), checkE)
}

func TestEncryptAndSignContract(t *testing.T) {
	// the private key used to sign the workload
	privKeyE := Encrypt.OpenSSLPrivateKey()
	// the encryption function
	signerE := F.Pipe2(
		pubKeyE,
		E.Map[error](openSSLEncryptAndSignContract),
		E.Ap[func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap]](privKeyE),
	)
	// prepare some contract without a key
	contractE := F.Pipe2(
		Contract1,
		S.ToBytes,
		Y.Parse[Contract.RawMap],
	)
	// add signature and encrypt the fields
	resIOE := F.Pipe5(
		signerE,
		E.Ap[IOE.IOEither[error, Contract.RawMap]](contractE),
		IOE.FromEither[error, IOE.IOEither[error, Contract.RawMap]],
		IOE.Flatten[error, Contract.RawMap],
		IOE.ChainEitherK(Y.Stringify[Contract.RawMap]),
		IOE.Map[error](B.ToString),
	)
	assert.True(t, E.IsRight(resIOE()))

	fmt.Println(resIOE())
}

func TestEnvWorkloadSignature(t *testing.T) {
	// the private key
	privKeyE := Encrypt.OpenSSLPrivateKey()

	signer := F.Pipe1(
		privKeyE,
		E.Map[error](createEnvWorkloadSignature(Encrypt.OpenSSLSignDigest)),
	)

	// some sample data
	data := Contract.RawMap{
		Contract.KeyEnv:      "some env",
		Contract.KeyWorkload: "some workload",
	}

	// compute the signature
	signatureIOE := F.Pipe2(
		signer,
		IOE.FromEither[error, func(Contract.RawMap) IOE.IOEither[error, string]],
		IOE.Chain(I.Ap[IOE.IOEither[error, string]](data)),
	)

	assert.True(t, E.IsRight(signatureIOE()))
}

func BenchmarkEncryptAndSignContract(t *testing.B) {
	// the private key used to sign the workload
	privKeyE := Encrypt.OpenSSLPrivateKey()
	// the encryption function
	signerE := F.Pipe2(
		pubKeyE,
		E.Map[error](openSSLEncryptAndSignContract),
		E.Ap[func(Contract.RawMap) IOE.IOEither[error, Contract.RawMap]](privKeyE),
	)
	// prepare some contract without a key
	contractE := F.Pipe2(
		Contract1,
		S.ToBytes,
		Y.Parse[Contract.RawMap],
	)
	// add signature and encrypt the fields
	resIOE := F.Pipe5(
		signerE,
		E.Ap[IOE.IOEither[error, Contract.RawMap]](contractE),
		IOE.FromEither[error, IOE.IOEither[error, Contract.RawMap]],
		IOE.Flatten[error, Contract.RawMap],
		IOE.ChainEitherK(Y.Stringify[Contract.RawMap]),
		IOE.Map[error](B.ToString),
	)
	assert.True(t, E.IsRight(resIOE()))

	fmt.Println(resIOE())
}
