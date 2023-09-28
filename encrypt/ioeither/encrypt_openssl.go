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
	IOE "github.com/IBM/fp-go/ioeither"
)

// OpenSSLEncryptBasic implements basic encryption using openSSL given the certificate or public key
func OpenSSLEncryptBasic(pubOrCert []byte) func([]byte) IOE.IOEither[error, string] {
	return EncryptBasic(OpenSSLRandomPassword(keylen), AsymmetricEncryptPubOrCert(pubOrCert), SymmetricEncrypt)
}

// OpenSSLDecryptBasic implements basic decryption using openSSL given the private key
func OpenSSLDecryptBasic(privKey []byte) func(string) IOE.IOEither[error, []byte] {
	return DecryptBasic(AsymmerticDecrypt(privKey), SymmetricDecrypt)
}
