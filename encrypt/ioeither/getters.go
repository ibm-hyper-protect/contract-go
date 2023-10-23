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

// EncryptBasic implements basic encryption given the certificate (side effect because of random passphrase)
func (enc Encryption) GetEncryptBasic() EncryptBasicFunc {
	return enc.EncryptBasic
}

// CertFingerprint computes the fingerprint of a certificate
func (enc Encryption) GetCertFingerprint() CertFingerprintFunc {
	return enc.CertFingerprint
}

// PrivKeyFingerprint computes the fingerprint of a private key
func (enc Encryption) GetPrivKeyFingerprint() PrivKeyFingerprintFunc {
	return enc.PrivKeyFingerprint
}

// PrivKey computes a new private key
func (enc Encryption) GetPrivKey() Key {
	return enc.PrivKey
}

// PubKey computes a public key from a private key
func (enc Encryption) GetPubKey() PubKeyFunc {
	return enc.PubKey
}

// SignDigest computes the sha256 signature using a private key (side effect because of RSA blinding)
func (enc Encryption) GetSignDigest() SignDigestFunc {
	return enc.SignDigest
}
