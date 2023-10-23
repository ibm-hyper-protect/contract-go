// Copyright (c) 2023 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IO "github.com/IBM/fp-go/io"
	IOE "github.com/IBM/fp-go/ioeither"
	O "github.com/IBM/fp-go/option"
	RR "github.com/IBM/fp-go/record"
	T "github.com/IBM/fp-go/tuple"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	SVIOE "github.com/ibm-hyper-protect/contract-go/service/ioeither"
	"github.com/ibm-hyper-protect/contract-go/types"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
	"github.com/urfave/cli/v2"
)

var (

	// modeToEncrypt is the mapping from encryption module identifier to
	modeToEncrypt = map[string]IO.IO[Encrypt.Encryption]{
		ModeCrypto:  Encrypt.CryptoEncryption,
		ModeOpenSSL: Encrypt.OpenSSLEncryption,
		ModeDefault: Encrypt.DefaultEncryption,
	}

	// getEncryption returns the configured encryption module
	getEncryption = F.Flow3(
		RR.Lookup[IO.IO[Encrypt.Encryption], string],
		I.Ap[O.Option[IO.IO[Encrypt.Encryption]]](modeToEncrypt),
		O.GetOrElse(F.Constant(Encrypt.DefaultEncryption)),
	)
)

func EncryptCommand() *cli.Command {
	return &cli.Command{
		Name:        "encrypt",
		Usage:       "encrypt a contract",
		Description: "Encypts an HPCR contract",
		Flags: []cli.Flag{
			flagInput,
			flagOutput,
			flagMode,
			flagPrivKey,
			flagPrivKeyFile,
			flagCert,
			flagCertFile,
		},
		Action: func(ctx *cli.Context) error {
			// encryption module
			encryption := F.Pipe2(
				ctx.String(flagMode.Name),
				getEncryption,
				IO.Memoize[Encrypt.Encryption],
			)

			// signing key
			privKey := F.Pipe3(
				encryption,
				IO.Map(Encrypt.Encryption.GetPrivKey),
				IOE.FromIO[error, Encrypt.Key],
				IOE.Chain(getKey(ctx.String(flagPrivKey.Name), ctx.String(flagPrivKeyFile.Name))),
			)

			// public encryption key or certificate
			pubCert := F.Pipe1(
				defaultCertificate,
				getKey(ctx.String(flagCert.Name), ctx.String(flagCertFile.Name)),
			)

			// input
			contractIn := F.Pipe2(
				ctx.String(flagInput.Name),
				U.ReadFromInput,
				IOE.ChainEitherK(F.Flow2(
					Y.Parse[types.AnyMap],
					E.Chain(types.ValidateContract),
				)),
			)

			// output
			contractOut := F.Pipe1(
				ctx.String(flagOutput.Name),
				U.WriteToOutput,
			)

			// encryption function
			enc := F.Pipe3(
				encryption,
				IO.Map(Encrypt.Encryption.GetEncryptBasic),
				IOE.FromIO[error, Encrypt.EncryptBasicFunc],
				IOE.Ap[func([]byte) IOE.IOEither[error, string]](pubCert),
			)
			// signing function
			signer := F.Pipe2(
				encryption,
				IO.Map(Encrypt.Encryption.GetSignDigest),
				IOE.FromIO[error, Encrypt.SignDigestFunc],
			)
			// public key extractor
			pubkey := F.Pipe2(
				encryption,
				IO.Map(Encrypt.Encryption.GetPubKey),
				IOE.FromIO[error, Encrypt.PubKeyFunc],
			)

			encryptAndWrite := F.Pipe6(
				IOE.SequenceTuple3(T.MakeTuple3(enc, signer, pubkey)),
				IOE.Map[error](T.Tupled3(SVIOE.EncryptAndSignContract)),
				IOE.Ap[SVIOE.ContractEncrypter](privKey),
				IOE.Ap[IOE.IOEither[error, SC.EncryptedContract]](contractIn),
				IOE.Flatten[error, SC.EncryptedContract],
				IOE.ChainEitherK(Y.Stringify[SC.EncryptedContract]),
				IOE.Chain(contractOut),
			)

			// finally execute
			_, err := E.Unwrap(encryptAndWrite())

			return err
		},
	}
}
