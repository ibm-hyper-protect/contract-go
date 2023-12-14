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
	F "github.com/IBM/fp-go/function"
	IO "github.com/IBM/fp-go/io"
	IOE "github.com/IBM/fp-go/ioeither"
)

// Decryption captures the crypto functions required to implement the source providers
type Decryption struct {
	// DecryptBasic implements basic decryption given the private key
	DecryptBasic func(privKey []byte) func(string) IOE.IOEither[error, []byte]
}

var (

	// OpenSSLDecryption returns the decryption environment using OpenSSL
	OpenSSLDecryption = IO.MakeIO(func() Decryption {
		return Decryption{
			DecryptBasic: OpenSSLDecryptBasic,
		}
	})

	// CryptoDecryption returns the decryption environment using golang crypto
	CryptoDecryption = IO.MakeIO(func() Decryption {
		return Decryption{
			DecryptBasic: CryptoDecryptBasic,
		}
	})

	// DefaultDecryption detects the decryption environment
	DefaultDecryption = F.Pipe1(
		validOpenSSL,
		IOE.Fold(F.Constant1[error](CryptoDecryption), F.Constant1[string](OpenSSLDecryption)),
	)
)
