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
	F "github.com/IBM/fp-go/function"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	"github.com/urfave/cli/v2"
)

// EncryptAndSignCommand returns a command that encrypts and signs a contract
func EncryptAndSignCommand() *cli.Command {
	return &cli.Command{
		Name:        "encrypt",
		Usage:       "encrypt a contract",
		Description: "Encypts an HPCR contract",
		Flags: []cli.Flag{
			flagInput,
			flagOutput,
			flagFormat,
			flagMode,
			flagPrivKey,
			flagPrivKeyFile,
			flagCert,
			flagCertFile,
		},
		Action: F.Flow2(
			EncryptSignAndWriteFromContext,
			U.RunIOEither[[]byte],
		),
	}
}
