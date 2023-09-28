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
	"io"
	"os"
	"strings"

	RA "github.com/IBM/fp-go/array"
	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	EX "github.com/IBM/fp-go/exec"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEX "github.com/IBM/fp-go/ioeither/exec"
	FIOE "github.com/IBM/fp-go/ioeither/file"
	GIOE "github.com/IBM/fp-go/ioeither/generic"
	IOO "github.com/IBM/fp-go/iooption"
	O "github.com/IBM/fp-go/option"
	P "github.com/IBM/fp-go/predicate"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	EC "github.com/ibm-hyper-protect/contract-go/encrypt/common"
)

type (
	// Executor is the signature of a function that executes a command with some input
	Executor = func([]byte) IOE.IOEither[error, EX.CommandOutput]
)

var (
	// the empty byte array
	emptyBytes = RA.Empty[byte]()

	// operator to extract stdout
	mapStdout = IOE.Map[error](EX.StdOut)

	// operator to convert stdout to base64
	base64StdOut = F.Flow2(
		mapStdout,
		IOE.Map[error](Common.Base64Encode),
	)

	// OpenSSLSignDigest signs the sha256 digest using a private key
	OpenSSLSignDigest = handle(signDigest)

	// AsymmetricEncryptPubOrCert implements asymmetric encryption based on a public key or certificate based on the input
	AsymmetricEncryptPubOrCert = handle(asymmetricEncryptPubOrCert)

	// AsymmetricEncryptPub implements asymmetric encryption based on a public key
	AsymmetricEncryptPub = handle(asymmetricEncryptPub)

	// AsymmetricEncryptCert implements asymmetric encryption based on a certificate
	AsymmetricEncryptCert = handle(asymmetricEncryptCert)

	AsymmerticDecrypt = handle(asymmetricDecrypt)

	SymmetricEncrypt = handle(symmetricEncrypt)

	// openSSLPublicKeyFromPrivateKey gets the public key from a private key
	openSSLPublicKeyFromPrivateKey = F.Flow2(
		OpenSSL("rsa", "-pubout"),
		mapStdout,
	)

	// openSSLPublicKeyFromCertificate gets the public key from a certificate
	openSSLPublicKeyFromCertificate = F.Flow2(
		OpenSSL("x509", "-pubkey", "-noout"),
		mapStdout,
	)

	// CertSerial gets the serial number from a certificate
	CertSerial = F.Flow2(
		OpenSSL("x509", "-serial", "-noout"),
		mapStdout,
	)

	// OpenSSLCertFingerprint gets the fingerprint of a certificate
	openSSLCertFingerprint = F.Flow4(
		OpenSSL("x509", "--outform", "DER"),
		mapStdout,
		IOE.Chain(OpenSSL("sha256", "--binary")),
		mapStdout,
	)

	// gets the fingerprint of the private key
	openSSLPrivKeyFingerprint = F.Flow4(
		OpenSSL("rsa", "-pubout", "-outform", "DER"),
		mapStdout,
		IOE.Chain(OpenSSL("sha256", "--binary")),
		mapStdout,
	)

	// version string of the openSSL binary together with the binary
	openSSLVersion = F.Pipe2(
		EC.OpenSSLBinary,
		IOE.FromIO[error, string],
		IOE.Chain(func(bin string) IOE.IOEither[error, EC.OpenSSLVersion] {
			return F.Pipe2(
				emptyBytes,
				IOEX.Command(bin)(RA.From("version")),
				IOE.Map[error](F.Flow4(
					EX.StdOut,
					B.ToString,
					strings.TrimSpace,
					F.Bind1st(T.MakeTuple2[string, string], bin),
				)),
			)
		}),
	)

	// command name of the valid openSSL binary
	validOpenSSL = F.Pipe2(
		openSSLVersion,
		IOE.ChainEitherK(func(version EC.OpenSSLVersion) E.Either[error, string] {
			return F.Pipe3(
				version,
				O.FromPredicate(P.ContraMap(EC.GetVersion)(EC.IncludesOpenSSL)),
				O.Map(EC.GetPath),
				E.FromOption[error, string](errors.OnNone("openSSL Version [%s] is unsupported", version)),
			)
		}),
		IOE.Memoize[error, string],
	)

	// OpenSSLPrivateKey generates a private key
	OpenSSLPrivateKey = F.Pipe2(
		emptyBytes,
		OpenSSL("genrsa", "4096"),
		mapStdout,
	)
)

func OpenSSLPublicKey(privKey []byte) E.Either[error, []byte] {
	return openSSLPublicKeyFromPrivateKey(privKey)()
}

func OpenSSLPublicKeyFromCertificate(certificate []byte) E.Either[error, []byte] {
	return openSSLPublicKeyFromCertificate(certificate)()
}

func OpenSSLPrivKeyFingerprint(privKey []byte) E.Either[error, []byte] {
	return openSSLPrivKeyFingerprint(privKey)()
}

func OpenSSLCertFingerprint(cert []byte) E.Either[error, []byte] {
	return openSSLCertFingerprint(cert)()
}

// helper to safely write data into a file
func writeData[W io.Writer](data []byte) func(w W) IOE.IOEither[error, int] {
	return func(w W) IOE.IOEither[error, int] {
		return IOE.TryCatchError(func() (int, error) {
			return w.Write(data)
		})
	}
}

// OpenSSL invokes the openSSL command using a fixed set of parameters
func OpenSSL(args ...string) Executor {
	// validate the version of openssl and make sure to use the right one
	cmdIOE := F.Pipe1(
		validOpenSSL,
		IOE.Map[error](F.Flow2(
			IOEX.Command,
			I.Ap[Executor](args),
		)),
	)
	// convert stdin to openssl output
	return func(dataIn []byte) IOE.IOEither[error, EX.CommandOutput] {
		return F.Pipe1(
			cmdIOE,
			IOE.Chain(I.Ap[IOE.IOEither[error, EX.CommandOutput]](dataIn)),
		)
	}
}

// OpenSSLRandomPassword creates a random password of given length using characters from the base64 alphabet only
func OpenSSLRandomPassword(count int) IOE.IOEither[error, []byte] {
	return F.Pipe3(
		emptyBytes,
		OpenSSL("rand", fmt.Sprintf("%d", count)),
		base64StdOut,
		IOE.Map[error](F.Flow2(
			S.ToBytes,
			RA.Slice[byte](0, count),
		)),
	)
}

// persists the data record for a minimal timespan in a temporary file and the invokes a callback
func handle[A, R any](cb func(string) func(A) IOE.IOEither[error, R]) func(data []byte) func(A) IOE.IOEither[error, R] {
	tmpFile := FIOE.WithTempFile[R]
	// handle temp file
	return func(data []byte) func(A) IOE.IOEither[error, R] {
		writeDataIOE := writeData[*os.File](data)
		return func(key A) IOE.IOEither[error, R] {
			mapToA := IOE.MapTo[error, int](key)
			return tmpFile(func(f *os.File) IOE.IOEither[error, R] {
				enc := cb(f.Name())
				return F.Pipe3(
					f,
					writeDataIOE,
					mapToA,
					IOE.Chain(enc),
				)
			})
		}
	}
}

func signDigest(keyFile string) func([]byte) IOE.IOEither[error, []byte] {
	return F.Flow2(
		OpenSSL("dgst", "-sha256", "-sign", keyFile),
		mapStdout,
	)
}

func asymmetricDecrypt(keyFile string) func(string) IOE.IOEither[error, []byte] {
	return F.Flow4(
		Common.Base64DecodeE,
		IOE.FromEither[error, []byte],
		IOE.Chain(OpenSSL("rsautl", "-decrypt", "-inkey", keyFile)),
		mapStdout,
	)
}

func encrypterForType(tp string, enc func([]byte) IOE.IOEither[error, string]) func(blocks []*pem.Block) O.Option[func([]byte) IOE.IOEither[error, string]] {
	return F.Flow3(
		RA.Filter(EC.IsType(tp)),
		RA.Head[*pem.Block],
		O.Map(F.Constant1[*pem.Block](enc)),
	)
}

func asymmetricEncryptPubOrCert(pubOrCertKeyFile string) func([]byte) IOE.IOEither[error, string] {
	// determine the type of encryption function based on the key file
	encrypter := F.Pipe2(
		FIOE.ReadFile(pubOrCertKeyFile),
		IOE.Map[error](EC.PemDecodeAll),
		IOE.ChainOptionK[[]*pem.Block, func([]byte) IOE.IOEither[error, string]](
			errors.OnNone("unable to decode neither a [%s] not a [%s] block from PEM file", EC.TypeCertificate, EC.TypePublicKey),
		)(func(blocks []*pem.Block) O.Option[func([]byte) IOE.IOEither[error, string]] {
			// prepare the encrypters
			encCert := encrypterForType(EC.TypeCertificate, asymmetricEncryptCert(pubOrCertKeyFile))
			pubCert := encrypterForType(EC.TypePublicKey, asymmetricEncryptPub(pubOrCertKeyFile))
			// handle
			return F.Pipe2(
				blocks,
				encCert,
				O.Alt(F.Nullary2(F.Constant(blocks), pubCert)),
			)
		}),
	)
	// implement encryption
	return func(data []byte) IOE.IOEither[error, string] {
		return F.Pipe1(
			encrypter,
			IOE.Chain(I.Ap[IOE.IOEither[error, string]](data)),
		)
	}
}

func asymmetricEncryptPub(pubKeyFile string) func([]byte) IOE.IOEither[error, string] {
	return F.Flow2(
		OpenSSL("rsautl", "-encrypt", "-pubin", "-inkey", pubKeyFile),
		base64StdOut,
	)
}

func asymmetricEncryptCert(certFile string) func([]byte) IOE.IOEither[error, string] {
	return F.Flow2(
		OpenSSL("rsautl", "-encrypt", "-certin", "-inkey", certFile),
		base64StdOut,
	)
}

func symmetricEncrypt(dataFile string) func([]byte) IOE.IOEither[error, string] {
	return F.Flow2(
		OpenSSL("enc", "-aes-256-cbc", "-pbkdf2", "-in", dataFile, "-pass", "stdin"),
		base64StdOut,
	)
}

func symmetricDecrypt(dataFile string) func([]byte) IOE.IOEither[error, []byte] {
	return F.Flow2(
		OpenSSL("aes-256-cbc", "-d", "-pbkdf2", "-in", dataFile, "-pass", "stdin"),
		mapStdout,
	)
}

func SymmetricDecrypt(token string) func([]byte) IOE.IOEither[error, []byte] {
	// decode the token and produce the decryption function
	dec := F.Pipe3(
		token,
		Common.Base64DecodeE,
		IOE.FromEither[error, []byte],
		IOE.Map[error](handle(symmetricDecrypt)),
	)
	// decrypt using the provided password
	return func(pwd []byte) IOE.IOEither[error, []byte] {
		return F.Pipe1(
			dec,
			IOE.Chain(I.Ap[IOE.IOEither[error, []byte]](pwd)),
		)
	}
}

// OpenSSLVerifyDigest verifies the signature of the input data against a signature
func OpenSSLVerifyDigest(pubKey []byte) func(data []byte) func(signature []byte) IOO.IOOption[error] {
	// shortcut for the fold operation
	foldIOE := GIOE.Fold[IOE.IOEither[error, EX.CommandOutput]](func(err error) IOO.IOOption[error] {
		return IOO.Of(err)
	}, func(a EX.CommandOutput) IOO.IOOption[error] {
		return IOO.None[error]()
	})
	// callback functions
	return func(data []byte) func([]byte) IOO.IOOption[error] {
		return func(signature []byte) IOO.IOOption[error] {
			return F.Pipe2(
				data,
				handle(func(pubKeyFile string) Executor {
					return handle(func(signatureFile string) Executor {
						return OpenSSL("dgst", "-verify", pubKeyFile, "-sha256", "-signature", signatureFile)
					})(signature)
				})(pubKey),
				foldIOE,
			)
		}
	}
}
