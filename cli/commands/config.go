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
	"fmt"
	"os"
	"path/filepath"

	A "github.com/IBM/fp-go/array"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	S "github.com/IBM/fp-go/string"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	"github.com/urfave/cli/v2"
)

const (
	ModeOpenSSL = "openssl"
	ModeCrypto  = "crypto"
	ModeDefault = "default"
)

var (
	// valid modes
	validModes = A.From(ModeOpenSSL, ModeCrypto, ModeDefault)
	// flagInput defines the CLI flag for the main input
	flagInput = &cli.StringFlag{
		Name: "in",
		Aliases: []string{
			"i",
		},
		Action:    validateInput,
		TakesFile: true,
		Value:     U.StdInOutIdentifier,
		Usage:     fmt.Sprintf("Name of the input file or '%s' for stdin", U.StdInOutIdentifier),
	}

	// flagOutput defines the CLI flag for the main output
	flagOutput = &cli.StringFlag{
		Name: "out",
		Aliases: []string{
			"o",
		},
		Action:    validateOutput,
		TakesFile: true,
		Value:     U.StdInOutIdentifier,
		Usage:     fmt.Sprintf("Name of the output file or '%s' for stdout", U.StdInOutIdentifier),
	}

	// flagPrivKey defines the CLI flag for the private key
	flagPrivKey = &cli.StringFlag{
		Name: "privkey",
		Aliases: []string{
			"p",
		},
		TakesFile: false,
		Usage:     "Content of the private signing key as a string. If absent the tool creates a transient key",
	}

	// flagPrivKeyFile defines the CLI flag for a private key file
	flagPrivKeyFile = &cli.StringFlag{
		Name: "privkeyfile",
		Aliases: []string{
			"pf",
		},
		Action:    validateInput,
		TakesFile: true,
		Usage:     "Content of the private signing key as a filepath. If absent the tool creates a transient key",
	}

	// flagCert defines the CLI flag for the public encryption certificate
	flagCert = &cli.StringFlag{
		Name: "cert",
		Aliases: []string{
			"c",
		},
		TakesFile: false,
		Usage:     "Content of the encryption certificate as a string. If absent the tool uses a built-in default",
	}

	// flagPrivKeyFile defines the CLI flag for a private key file
	flagCertFile = &cli.StringFlag{
		Name: "certfile",
		Aliases: []string{
			"cf",
		},
		Action:    validateInput,
		TakesFile: true,
		Usage:     "Content of the encryption certificate as a string. If absent the tool uses a built-in default",
	}

	// flagMode is the operation mode
	flagMode = &cli.StringFlag{
		Name: "mode",
		Aliases: []string{
			"m",
		},
		Action:   validateMode,
		Required: false,
		Value:    ModeDefault,
		Usage:    fmt.Sprintf("Operational mode, valid values are %s", validModes),
	}
)

func validateInput(ctx *cli.Context, value string) error {
	if value == U.StdInOutIdentifier {
		return nil
	}
	status, err := os.Stat(value)
	if err != nil {
		return err
	}
	if status.IsDir() {
		return fmt.Errorf("input [%s] must be a file not a directory", value)
	}
	return nil
}

func validateOutput(ctx *cli.Context, value string) error {
	if value == U.StdInOutIdentifier {
		return nil
	}
	parent := filepath.Dir(value)
	err := os.MkdirAll(parent, os.ModePerm)
	if err != nil {
		return err
	}
	status, err := os.Stat(value)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	if status.IsDir() {
		return fmt.Errorf("output [%s] must be a file not a directory", value)
	}
	return nil
}

func validateMode(ctx *cli.Context, value string) error {
	return F.Pipe3(
		validModes,
		A.Filter(S.Equals(value)),
		A.Head[string],
		O.Fold(errors.OnNone("value [%s] is not valid, valid values are %s", value, validModes), F.Constant1[string, error](nil)),
	)
}
