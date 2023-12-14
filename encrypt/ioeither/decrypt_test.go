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
	"math/rand"
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	T "github.com/IBM/fp-go/tuple"
	"github.com/stretchr/testify/assert"
)

func testSymmetricDecrypt(
	t *testing.T,
	srcLen int,
	encrypt func(srcPlainBytes []byte) func([]byte) IOE.IOEither[error, string],
	decrypt func(token string) func([]byte) IOE.IOEither[error, []byte]) IOE.IOEither[error, bool] {

	// generate some random data
	data := F.Pipe1(
		cryptoRandomIOE(srcLen),
		IOE.Memoize[error, []byte],
	)

	// generate some password
	pwd := F.Pipe1(
		CryptoRandomPassword(keylen),
		IOE.Memoize[error, []byte],
	)

	// encrypt the data record
	enc := F.Pipe3(
		data,
		IOE.Map[error](encrypt),
		IOE.Ap[IOE.IOEither[error, string]](pwd),
		IOE.Flatten[error, string],
	)

	// decrypt the data record
	dec := F.Pipe3(
		enc,
		IOE.Map[error](decrypt),
		IOE.Ap[IOE.IOEither[error, []byte]](pwd),
		IOE.Flatten[error, []byte],
	)

	return F.Pipe1(
		IOE.SequenceT2(data, dec),
		IOE.Map[error](T.Tupled2(func(exp, actual []byte) bool {
			return assert.Equal(t, exp, actual)
		})),
	)
}

func testAsymmetricDecrypt(
	t *testing.T,
	srcLen int,
	encrypt func([]byte) func([]byte) IOE.IOEither[error, string],
	decrypt func([]byte) func(string) IOE.IOEither[error, []byte]) IOE.IOEither[error, bool] {

	// generate some random data
	data := F.Pipe1(
		cryptoRandomIOE(srcLen),
		IOE.Memoize[error, []byte],
	)

	// generate a key pair
	privKey := F.Pipe1(
		CryptoPrivateKey,
		IOE.Memoize[error, []byte],
	)

	pubKey := F.Pipe1(
		privKey,
		IOE.ChainEitherK(CryptoPublicKey),
	)

	// encrypt the data record
	enc := F.Pipe3(
		pubKey,
		IOE.Map[error](encrypt),
		IOE.Ap[IOE.IOEither[error, string]](data),
		IOE.Flatten[error, string],
	)

	// decrypt the data record
	dec := F.Pipe3(
		privKey,
		IOE.Map[error](decrypt),
		IOE.Ap[IOE.IOEither[error, []byte]](enc),
		IOE.Flatten[error, []byte],
	)

	return F.Pipe1(
		IOE.SequenceT2(data, dec),
		IOE.Map[error](T.Tupled2(func(exp, actual []byte) bool {
			return assert.Equal(t, exp, actual)
		})),
	)
}

type (
	// definition of an encryption
	SymmEncDecItem struct {
		Encrypt func(srcPlainBytes []byte) func([]byte) IOE.IOEither[error, string]
		Decrypt func(token string) func([]byte) IOE.IOEither[error, []byte]
	}

	// definition of an encryption
	AsymmEncDecItem struct {
		Encrypt func([]byte) func([]byte) IOE.IOEither[error, string]
		Decrypt func([]byte) func(string) IOE.IOEither[error, []byte]
	}
)

var (
	// test matrix for symmetric encryption combinations
	SymmEncDecMatrix = []SymmEncDecItem{
		{Encrypt: OpenSSLSymmetricEncrypt, Decrypt: OpenSSLSymmetricDecrypt},
		{Encrypt: CryptoSymmetricEncrypt, Decrypt: OpenSSLSymmetricDecrypt},
		{Encrypt: OpenSSLSymmetricEncrypt, Decrypt: CryptoSymmetricDecrypt},
		{Encrypt: CryptoSymmetricEncrypt, Decrypt: CryptoSymmetricDecrypt},
	}

	// test matrix for asymmetric encryption combinations
	AsymmEncDecMatrix = []AsymmEncDecItem{
		{Encrypt: OpenSSLAsymmetricEncryptPub, Decrypt: OpenSSLAsymmetricDecrypt},
		{Encrypt: CryptoAsymmetricEncryptPub, Decrypt: OpenSSLAsymmetricDecrypt},
		{Encrypt: OpenSSLAsymmetricEncryptPub, Decrypt: CryptoAsymmetricDecrypt},
		{Encrypt: CryptoAsymmetricEncryptPub, Decrypt: CryptoAsymmetricDecrypt},
	}
)

// TestSymmetricDecrypt checks if the symmetric decryption works
func TestSymmetricDecrypt(t *testing.T) {

	for i := 0; i < 10; i++ {

		len := rand.Intn(10000) + 1
		for idx, item := range SymmEncDecMatrix {

			t.Run(fmt.Sprintf("Message Size [%d], Combination [%d]", len, idx), func(t *testing.T) {
				res := testSymmetricDecrypt(t, len, item.Encrypt, item.Decrypt)
				assert.Equal(t, E.Of[error](true), res())
			})
		}

	}
}

func TestAsymmetricDecrypt(t *testing.T) {

	for i := 0; i < 2; i++ {

		len := rand.Intn(255) + 1
		for idx, item := range AsymmEncDecMatrix {

			t.Run(fmt.Sprintf("Message Size [%d], Combination [%d]", len, idx), func(t *testing.T) {
				res := testAsymmetricDecrypt(t, len, item.Encrypt, item.Decrypt)
				assert.Equal(t, E.Of[error](true), res())
			})
		}

	}
}
