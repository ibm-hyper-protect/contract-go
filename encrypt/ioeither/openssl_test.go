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
	"encoding/pem"
	"fmt"
	"testing"

	AR "github.com/IBM/fp-go/array"
	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/IBM/fp-go/ioeither/file"
	O "github.com/IBM/fp-go/option"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	EC "github.com/ibm-hyper-protect/contract-go/encrypt/common"
	"github.com/stretchr/testify/assert"
)

var (
	// loads the basic certificate
	encryptBasicCertificate = file.ReadFile("../../build/mavenResolver/se-encrypt-basic.crt")
)

func TestOpenSSLPublicKeyFromCertificate(t *testing.T) {
	// decode
	res := F.Pipe2(
		encryptBasicCertificate,
		IOE.Chain(openSSLPublicKeyFromCertificate),
		IOE.ChainEitherK(F.Flow3(
			EC.PemDecodeAll,
			AR.Head[*pem.Block],
			O.Fold(F.Nullary2(errors.OnNone("no pem block found"), E.Left[bool, error]), F.Flow2(IsPublicKey, E.Of[error, bool])),
		)),
	)
	// validate
	assert.Equal(t, E.Of[error](true), res())
}

func TestValidOpenSSL(t *testing.T) {
	// check if we have a valid openSSL binary
	validBinaryE := validOpenSSL()

	assert.True(t, E.IsRight(validBinaryE))
}

func TestOpenSSLBinaryFromEnv(t *testing.T) {
	somepath := "/somepath/openssl.exe"
	t.Setenv(EC.KeyEnvOpenSSL, somepath)

	assert.Equal(t, somepath, EC.OpenSSLBinary())
}

func TestOpenSSLBinary(t *testing.T) {
	assert.NotEmpty(t, EC.OpenSSLBinary())
}

func TestVersion(t *testing.T) {

	res := openSSLVersion()

	assert.NotEmpty(t, E.IsRight(res))
}

func TestRandomPassword(t *testing.T) {

	genPwd := OpenSSLRandomPassword(keylen)

	pwd := genPwd()

	fmt.Println(pwd)
}

func TestEncryptPassword(t *testing.T) {

	//	genPwd := RandomPassword(keylen)

}

func TestPrivateKey(t *testing.T) {
	privKeyE := OpenSSLPrivateKey()

	pubKey := F.Pipe2(
		privKeyE,
		E.Chain(OpenSSLPublicKey),
		E.Map[error](B.ToString),
	)

	// TODO verify it's indeed a public key
	fmt.Println(pubKey)
}

func TestSignDigest(t *testing.T) {
	// some key
	privKeyIOE := OpenSSLPrivateKey
	// some input data
	data := []byte("Carsten")

	signE := F.Pipe1(
		privKeyIOE,
		IOE.Map[error](OpenSSLSignDigest),
	)

	resE := F.Pipe2(
		signE,
		IOE.Chain(I.Ap[IOE.IOEither[error, []byte]](data)),
		IOE.Map[error](Common.Base64Encode),
	)

	assert.True(t, E.IsRight(resE()))
}

func TestPrivKeyFingerprint(t *testing.T) {
	// some key
	privKeyE := OpenSSLPrivateKey()

	fpE := F.Pipe1(
		privKeyE,
		E.Chain(OpenSSLPrivKeyFingerprint),
	)

	assert.True(t, E.IsRight(fpE))
}

// TestOpenSSLSignature checks if the signature works when created and verified by the openSSL APIs
func TestOpenSSLSignature(t *testing.T) {
	SignatureTest(
		OpenSSLPrivateKey,
		OpenSSLPublicKey,
		OpenSSLRandomPassword(3333),
		OpenSSLSignDigest,
		OpenSSLVerifyDigest,
	)(t)
}

// TestCryptoOpenSSLSignature checks if the signature works when created and verified by the openSSL APIs
func TestCryptoOpenSSLSignature(t *testing.T) {
	SignatureTest(
		OpenSSLPrivateKey,
		OpenSSLPublicKey,
		OpenSSLRandomPassword(3333),
		CryptoSignDigest,
		OpenSSLVerifyDigest,
	)(t)
}
