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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	RA "github.com/IBM/fp-go/array"
	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	IOO "github.com/IBM/fp-go/iooption"
	L "github.com/IBM/fp-go/lazy"
	O "github.com/IBM/fp-go/option"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	"github.com/ibm-hyper-protect/contract-go/common"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	EC "github.com/ibm-hyper-protect/contract-go/encrypt/common"
	"golang.org/x/crypto/pbkdf2"
)

var (
	parseCertificateE     = E.Eitherize1(x509.ParseCertificate)
	parsePKIXPublicKeyE   = E.Eitherize1(x509.ParsePKIXPublicKey)
	parsePKCS1PrivateKeyE = E.Eitherize1(x509.ParsePKCS1PrivateKey)
	parsePKCS8PrivateKeyE = E.Eitherize1(x509.ParsePKCS8PrivateKey)
	marshalPKIXPublicKeyE = E.Eitherize1(x509.MarshalPKIXPublicKey)
	toRsaPublicKey        = Common.ToTypeE[*rsa.PublicKey]
	randomSaltIOE         = cryptoRandomIOE(saltlen)
	aesCipherE            = E.Eitherize1(aes.NewCipher)
	salted                = []byte("Salted__")
	pbkdf2Key             = F.Curry2(func(password, salt []byte) []byte {
		return pbkdf2.Key(password, salt, iterations, keylen+aes.BlockSize, sha256.New)
	})

	// certToRsaKey decodes a certificate into a public key
	certToRsaKey = F.Flow3(
		pemDecodeFirstCertificate,
		E.Chain(parseCertificateE),
		E.Chain(rsaFromCertificate),
	)

	// pubToRsaKey decodes a public key to rsa format
	pubToRsaKey = F.Flow3(
		pemDecodeFirstPublicKey,
		E.Chain(parsePKIXPublicKeyE),
		E.Chain(toRsaPublicKey),
	)

	// privToRsaKey decodes a pkcs file into a private key
	privToRsaKey = F.Flow2(
		pemDecodeE,
		E.Chain(parsePrivateKeyE),
	)

	// CryptoCertFingerprint computes the fingerprint of a certificate using the crypto library
	CryptoCertFingerprint = F.Flow5(
		pemDecodeFirstCertificate,
		E.Chain(parseCertificateE),
		E.Map[error](rawFromCertificate),
		E.Map[error](sha256.Sum256),
		E.Map[error](shaToBytes),
	)

	// CryptoPrivKeyFingerprint computes the fingerprint of a private key using the crypto library
	CryptoPrivKeyFingerprint = F.Flow7(
		pemDecodeE,
		E.Chain(parsePrivateKeyE),
		E.Map[error](privToPub),
		E.Map[error](pubToAny),
		E.Chain(marshalPKIXPublicKeyE),
		E.Map[error](sha256.Sum256),
		E.Map[error](shaToBytes),
	)

	// CryptoVerifyDigest verifies the signature of the input data against a signature
	CryptoVerifyDigest = F.Flow2(
		pubToRsaKey,
		E.Fold(errorValidator, verifyPKCS1v15),
	)

	// CryptoPublicKey extracts the public key from a private key
	CryptoPublicKey = F.Flow6(
		pemDecodeE,
		E.Chain(parsePrivateKeyE),
		E.Map[error](privToPub),
		E.Map[error](pubToAny),
		E.Chain(marshalPKIXPublicKeyE),
		E.Map[error](func(data []byte) []byte {
			return pem.EncodeToMemory(
				&pem.Block{
					Type:  EC.TypePublicKey,
					Bytes: data,
				},
			)
		}),
	)

	// IsPublicKey checks if a PEM block is a public key
	IsPublicKey = EC.IsType(EC.TypePublicKey)

	// IsCertificate checks if a PEM block is a certificate
	IsCertificate = EC.IsType(EC.TypeCertificate)

	pemDecodeFirstPublicKey   = pemDecodeFirstTypeE(EC.TypePublicKey)
	pemDecodeFirstCertificate = pemDecodeFirstTypeE(EC.TypeCertificate)
	decodeFirstPublicKey      = decodeFirstTypeO(EC.TypePublicKey)
	decodeFirstCertificate    = decodeFirstTypeO(EC.TypeCertificate)

	// CryptoAsymmetricEncryptPubOrCert encrypts a piece of text using a public key or a certificate
	CryptoAsymmetricEncryptPubOrCert = cryptoAsymmetricEncrypt(pubOrCertToRsaKey)

	// CryptoAsymmetricEncryptPub encrypts a piece of text using a public key
	CryptoAsymmetricEncryptPub = cryptoAsymmetricEncrypt(pubToRsaKey)

	// CryptoAsymmetricEncryptCert encrypts a piece of text using a certificate
	CryptoAsymmetricEncryptCert = cryptoAsymmetricEncrypt(certToRsaKey)

	// CryptoAsymmetricDecrypt decrypts a piece of text using a private key
	CryptoAsymmetricDecrypt = cryptoAsymmetricDecrypt(privToRsaKey)
)

func parsePrivateKeyE(data []byte) E.Either[error, *rsa.PrivateKey] {
	return F.Pipe2(
		data,
		parsePKCS1PrivateKeyE,
		E.Alt(F.Pipe1(
			L.Of(data),
			L.Map(F.Flow2(
				parsePKCS8PrivateKeyE,
				E.Chain(E.ToType[*rsa.PrivateKey](errors.OnSome[any]("Type [%T] cannot be converted to *rsa.PrivateKey"))),
			)),
		)),
	)
}

func pubOrCertToRsaKey(pubKeyOrCert []byte) E.Either[error, *rsa.PublicKey] {
	// decode all blocks
	return F.Pipe2(
		pubKeyOrCert,
		EC.PemDecodeAll,
		func(blocks []*pem.Block) E.Either[error, *rsa.PublicKey] {
			return F.Pipe4(
				blocks,
				decodeFirstCertificate,
				O.Map(F.Flow2(
					parseCertificateE,
					E.Chain(rsaFromCertificate),
				)),
				O.Alt(F.Nullary2(F.Constant(blocks), F.Flow2(
					decodeFirstPublicKey,
					O.Map(F.Flow2(
						parsePKIXPublicKeyE,
						E.Chain(toRsaPublicKey),
					)),
				))),
				O.GetOrElse(F.Nullary2(errors.OnNone("unable to decode neither a [%s] not a [%s] block from PEM file", EC.TypeCertificate, EC.TypePublicKey), E.Left[*rsa.PublicKey, error])),
			)
		},
	)
}

// cryptoRandomIOE returns a random sequence of bytes with the given length
func cryptoRandomIOE(n int) IOE.IOEither[error, []byte] {
	return IOE.TryCatchError(func() ([]byte, error) {
		buf := make([]byte, n)
		_, err := rand.Read(buf)
		return buf, err
	})
}

// CryptoRandomPassword creates a random password of given length using characters from the base64 alphabet only
func CryptoRandomPassword(count int) IOE.IOEither[error, []byte] {
	return F.Pipe1(
		cryptoRandomIOE(count),
		IOE.Map[error](F.Flow3(
			Common.Base64Encode,
			S.ToBytes,
			RA.Slice[byte](0, count),
		)),
	)
}

func getBytesFromBlock(block *pem.Block) []byte {
	return block.Bytes
}

// decodeFirstTypeO decodes the first occurrence of the given type from a PEM file
func decodeFirstTypeO(tp string) func(blocks []*pem.Block) O.Option[[]byte] {
	return F.Flow3(
		RA.Filter(EC.IsType(tp)),
		RA.Head[*pem.Block],
		O.Map(getBytesFromBlock),
	)
}

// pemDecodeType decodes the first occurrence of the given type from a PEM file
func pemDecodeFirstTypeE(tp string) func(data []byte) E.Either[error, []byte] {
	return F.Flow4(
		EC.PemDecodeAll,
		RA.Filter(EC.IsType(tp)),
		RA.Head[*pem.Block],
		O.Fold(F.Nullary2(errors.OnNone("unable to decode type [%s] from PEM", tp), E.Left[[]byte, error]), F.Flow2(
			getBytesFromBlock,
			E.Of[error, []byte],
		)),
	)
}

// pemDecode will find the next PEM formatted block (certificate, private key etc) in the input
func pemDecodeE(data []byte) E.Either[error, []byte] {
	block, _ := pem.Decode(data)
	return F.Pipe1(
		E.FromNillable[pem.Block](fmt.Errorf("unable to decode block from PEM"))(block),
		E.Map[error](func(b *pem.Block) []byte {
			return b.Bytes
		}),
	)
}

// encryptPKCS1v15 creates a function that encrypts a piece of text using a public key
func encryptPKCS1v15(pub *rsa.PublicKey) func([]byte) IOE.IOEither[error, []byte] {
	return func(origData []byte) IOE.IOEither[error, []byte] {
		return IOE.TryCatchError(func() ([]byte, error) {
			return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
		})
	}
}

// cryptoAsymmetricEncrypt creates a function that encrypts a piece of text using a public key
func cryptoAsymmetricEncrypt(decKey func([]byte) E.Either[error, *rsa.PublicKey]) func(publicKey []byte) func([]byte) IOE.IOEither[error, string] {
	// prepare the encryption callback
	enc := F.Flow3(
		decKey,
		E.Map[error](encryptPKCS1v15),
		IOE.FromEither[error, func([]byte) IOE.IOEither[error, []byte]],
	)
	return func(publicKey []byte) func([]byte) IOE.IOEither[error, string] {
		// decode the input to an RSA public key
		encE := F.Pipe1(
			publicKey,
			enc,
		)
		// returns the encryption function
		return func(data []byte) IOE.IOEither[error, string] {
			return F.Pipe2(
				encE,
				IOE.Chain(I.Ap[IOE.IOEither[error, []byte]](data)),
				IOE.Map[error](Common.Base64Encode),
			)
		}
	}
}

// cbcEncrypt creates a new encrypter and then encrypts a plaintext into a cyphertext
func cbcEncrypt(b cipher.Block, iv []byte) func([]byte) []byte {
	return func(src []byte) []byte {
		ciphertext := make([]byte, len(src))
		cipher.NewCBCEncrypter(b, iv).CryptBlocks(ciphertext, src)
		return ciphertext
	}
}

// cbcDecrypt creates a new decryptor and then decrypts ciphertext into plaintext
func cbcDecrypt(b cipher.Block, iv []byte) func([]byte) []byte {
	return func(src []byte) []byte {
		plaintext := make([]byte, len(src))
		cipher.NewCBCDecrypter(b, iv).CryptBlocks(plaintext, src)
		return plaintext
	}
}

// CryptoSymmetricEncrypt encrypts a set of bytes using a password
func CryptoSymmetricEncrypt(srcPlainbBytes []byte) func([]byte) IOE.IOEither[error, string] {
	// Pad plaintext to a multiple of BlockSize with random padding.
	bytesToPad := aes.BlockSize - (len(srcPlainbBytes) % aes.BlockSize)
	// pad the byte array
	paddedPlainBytes := B.Monoid.Concat(srcPlainbBytes, RA.Replicate(bytesToPad, byte(bytesToPad)))
	// length of plain text
	lenPlainBytes := len(paddedPlainBytes)
	// prepare the length buffer
	origSizeBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBuffer, uint64(lenPlainBytes))

	ivFromKey := RA.Slice[byte](keylen, keylen+aes.BlockSize)
	blockFromKey := RA.Slice[byte](0, keylen)

	return func(password []byte) IOE.IOEither[error, string] {
		// derive a key
		return F.Pipe1(
			randomSaltIOE,
			IOE.ChainEitherK(func(salt []byte) E.Either[error, string] {
				key := pbkdf2Key(password)(salt)
				iv := ivFromKey(key)
				prefix := B.Monoid.Concat(salted, salt)
				return F.Pipe3(
					key,
					blockFromKey,
					aesCipherE,
					E.Map[error](F.Flow4(
						F.Bind2nd(cbcEncrypt, iv),
						I.Ap[[]byte, []byte](paddedPlainBytes),
						F.Bind1st(B.Monoid.Concat, prefix),
						Common.Base64Encode,
					)),
				)
			}),
		)
	}
}

func rsaFromCertificate(cert *x509.Certificate) E.Either[error, *rsa.PublicKey] {
	return toRsaPublicKey(cert.PublicKey)
}

func rawFromCertificate(cert *x509.Certificate) []byte {
	return cert.Raw
}

// CryptoEncryptBasic implements basic encryption using golang crypto libraries given the public key or certificate
func CryptoEncryptBasic(pubKeyOrCert []byte) func([]byte) IOE.IOEither[error, string] {
	return EncryptBasic(CryptoRandomPassword(keylen), CryptoAsymmetricEncryptPubOrCert(pubKeyOrCert), CryptoSymmetricEncrypt)
}

// CryptoDecryptBasic implements basic decryption using golang crypto libraries given the private key
func CryptoDecryptBasic(privKey []byte) func(string) IOE.IOEither[error, []byte] {
	return DecryptBasic(CryptoAsymmetricDecrypt(privKey), CryptoSymmetricDecrypt)
}

func shaToBytes(sha [32]byte) []byte {
	return sha[:]
}

func privToPub(privKey *rsa.PrivateKey) *rsa.PublicKey {
	return &privKey.PublicKey
}

func pubToAny(pubKey *rsa.PublicKey) any {
	return pubKey
}

func privKeyToPem(privKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)
}

// CryptoPrivateKey generates a private key
var CryptoPrivateKey = F.Pipe1(
	IOE.TryCatchError(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 4096)
	}),
	IOE.Map[error](privKeyToPem),
)

// implements the signing operation in a functional way
func signPKCS1v15(privateKey *rsa.PrivateKey) func([]byte) IOE.IOEither[error, []byte] {
	return func(digest []byte) IOE.IOEither[error, []byte] {
		return IOE.TryCatchError(func() ([]byte, error) {
			return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
		})
	}
}

// CryptoSignDigest generates a signature across the sha256 of the message
// privkey - the private key used to compute the signature
// data - the message to be signed
func CryptoSignDigest(privKey []byte) func(data []byte) IOE.IOEither[error, []byte] {
	// parse the private key and derive the signer from it
	signerIOE := F.Pipe4(
		privKey,
		pemDecodeE,
		E.Chain(parsePrivateKeyE),
		E.Map[error](signPKCS1v15),
		IOE.FromEither[error, func([]byte) IOE.IOEither[error, []byte]],
	)
	return func(data []byte) IOE.IOEither[error, []byte] {
		// compute the digest
		digest := F.Pipe2(
			data,
			sha256.Sum256,
			shaToBytes,
		)
		// combine
		return F.Pipe1(
			signerIOE,
			IOE.Chain(I.Ap[IOE.IOEither[error, []byte]](digest)),
		)
	}
}

// implements the validation operation in a functional way
func verifyPKCS1v15(pubKey *rsa.PublicKey) func([]byte) func([]byte) IOO.IOOption[error] {
	return func(data []byte) func([]byte) IOO.IOOption[error] {
		digest := sha256.Sum256(data)
		return func(signature []byte) IOO.IOOption[error] {
			return func() O.Option[error] {
				return Common.FromErrorO(rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], signature))
			}
		}
	}
}

// errorValidator returns a validator that returns the orignal error
func errorValidator(err error) func([]byte) func([]byte) IOO.IOOption[error] {
	return func([]byte) func([]byte) IOO.IOOption[error] {
		return func([]byte) IOO.IOOption[error] {
			return F.Constant(O.Of(err))
		}
	}
}

// decryptPKCS1v15 creates a function that decrypts a piece of text using a private key
func decryptPKCS1v15(pub *rsa.PrivateKey) func([]byte) E.Either[error, []byte] {
	return func(ciphertext []byte) E.Either[error, []byte] {
		return E.TryCatchError(rsa.DecryptPKCS1v15(nil, pub, ciphertext))
	}
}

// cryptoAsymmetricDecrypt creates a function that encrypts a piece of text using a private key
func cryptoAsymmetricDecrypt(decKey func([]byte) E.Either[error, *rsa.PrivateKey]) func(privKey []byte) func(string) IOE.IOEither[error, []byte] {
	// prepare the decryption callback
	dec := F.Flow2(
		decKey,
		E.Map[error](decryptPKCS1v15),
	)

	return func(privKey []byte) func(string) IOE.IOEither[error, []byte] {
		// decode the input to an RSA public key
		// returns the encryption function
		return F.Flow4(
			Common.Base64DecodeE,
			F.Flip(E.Ap[E.Either[error, []byte], error, []byte])(F.Pipe1(
				privKey,
				dec,
			)),
			E.Flatten[error, []byte],
			IOE.FromEither[error, []byte],
		)
	}
}

func unpad(data []byte) []byte {
	size := len(data)
	count := int(data[size-1])
	return data[0 : size-count]
}

// CryptoSymmetricDecrypt encrypts a set of bytes using a password
func CryptoSymmetricDecrypt(srcText string) func([]byte) IOE.IOEither[error, []byte] {
	// some offsets
	offSalt := len(salted)
	offciphertext := offSalt + saltlen
	// decode the source (would start with `salted`)
	srcBytesE := common.Base64DecodeE(srcText)
	// get the salt
	saltE := F.Pipe1(
		srcBytesE,
		E.Map[error](RA.Slice[byte](offSalt, offciphertext)),
	)
	// get the ciphertext
	ciphertextE := F.Pipe1(
		srcBytesE,
		E.Map[error](RA.SliceRight[byte](offciphertext)),
	)

	return func(password []byte) IOE.IOEither[error, []byte] {
		// derive a key
		keyE := F.Pipe1(
			saltE,
			E.Map[error](pbkdf2Key(password)),
		)
		// the initialization vector
		ivE := F.Pipe1(
			keyE,
			E.Map[error](RA.Slice[byte](keylen, keylen+aes.BlockSize)),
		)
		// the block
		blockE := F.Pipe2(
			keyE,
			E.Map[error](RA.Slice[byte](0, keylen)),
			E.Chain(aesCipherE),
		)

		return F.Pipe2(
			E.SequenceT3(blockE, ivE, ciphertextE),
			E.Map[error](T.Tupled3(func(b cipher.Block, iv []byte, ciphertext []byte) []byte {
				return F.Pipe2(
					cbcDecrypt(b, iv),
					I.Ap[[]byte, []byte](ciphertext),
					unpad,
				)
			})),
			IOE.FromEither[error, []byte],
		)
	}
}
