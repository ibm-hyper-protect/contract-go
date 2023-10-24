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
	IOE "github.com/IBM/fp-go/ioeither"
	T "github.com/IBM/fp-go/tuple"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	"github.com/ibm-hyper-protect/contract-go/types"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
	"github.com/urfave/cli/v2"
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

			// the encryption function
			encrypter := F.Flow2(
				EncryptAndSignConfigFromContext,
				ContractEncrypterFromConfig,
			)

			// input
			contractIn := F.Flow3(
				lookupInput,
				U.ReadFromInput,
				IOE.ChainEitherK(F.Flow2(
					Y.Parse[types.AnyMap],
					E.Chain(types.ValidateContract),
				)),
			)

			// output
			contractOut := F.Pipe2(
				ctx,
				lookupOutput,
				U.WriteToOutput,
			)

			encryptAndWrite := F.Pipe5(
				T.Replicate2(ctx),
				T.Map2(encrypter, contractIn),
				T.Tupled2(IOE.MonadAp[IOE.IOEither[error, SC.EncryptedContract], error, *types.Contract]),
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
