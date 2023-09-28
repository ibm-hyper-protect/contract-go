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
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IO "github.com/IBM/fp-go/io"
	IOE "github.com/IBM/fp-go/ioeither"
)

// Encryption captures the crypto functions required to implement the source providers
type Encryption struct {
	// EncryptBasic implements basic encryption given the certificate (side effect because of random passphrase)
	EncryptBasic func([]byte) func([]byte) IOE.IOEither[error, string]
	// CertFingerprint computes the fingerprint of a certificate
	CertFingerprint func([]byte) E.Either[error, []byte]
	// PrivKeyFingerprint computes the fingerprint of a private key
	PrivKeyFingerprint func([]byte) E.Either[error, []byte]
	// PrivKey computes a new private key
	PrivKey IOE.IOEither[error, []byte]
	// PubKey computes a public key from a private key
	PubKey func([]byte) E.Either[error, []byte]
	// SignDigest computes the sha256 signature using a private key (side effect because of RSA blinding)
	SignDigest func([]byte) func([]byte) IOE.IOEither[error, []byte]
}

var (
	// openSSLEncryption returns the encryption environment using OpenSSL
	openSSLEncryption = IO.MakeIO(func() Encryption {
		return Encryption{
			EncryptBasic:       OpenSSLEncryptBasic,
			CertFingerprint:    OpenSSLCertFingerprint,
			PrivKeyFingerprint: OpenSSLPrivKeyFingerprint,
			PrivKey:            OpenSSLPrivateKey,
			PubKey:             OpenSSLPublicKey,
			SignDigest:         OpenSSLSignDigest,
		}
	})

	// cryptoEncryption returns the encryption environment using golang crypto
	cryptoEncryption = IO.MakeIO(func() Encryption {
		return Encryption{
			EncryptBasic:       CryptoEncryptBasic,
			CertFingerprint:    CryptoCertFingerprint,
			PrivKeyFingerprint: CryptoPrivKeyFingerprint,
			PrivKey:            CryptoPrivateKey,
			PubKey:             CryptoPublicKey,
			SignDigest:         CryptoSignDigest,
		}
	})

	// DefaultEncryption detects the encryption environment
	DefaultEncryption = F.Pipe1(
		validOpenSSL,
		IOE.Fold(F.Constant1[error](cryptoEncryption), F.Constant1[string](openSSLEncryption)),
	)
)
