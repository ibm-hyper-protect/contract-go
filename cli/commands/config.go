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
	I "github.com/IBM/fp-go/identity"
	IO "github.com/IBM/fp-go/io"
	IOE "github.com/IBM/fp-go/ioeither"
	O "github.com/IBM/fp-go/option"
	RR "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	SVIOE "github.com/ibm-hyper-protect/contract-go/service/ioeither"
	"github.com/urfave/cli/v2"
)

const (
	ModeOpenSSL = "openssl"
	ModeCrypto  = "crypto"
	ModeAuto    = "auto"
)

type (
	KeyConfig struct {
		FromDirect O.Option[string] // key as a PEM encoded string
		FromFile   O.Option[string] // filename to a PEM encoded key
	}

	EncryptAndSignConfig struct {
		Mode    string    // one of the mode flags
		PrivKey KeyConfig // private key used for signing
		PubCert KeyConfig // public key used for encryption
	}
)

var (
	// valid modes
	validModes = A.From(ModeOpenSSL, ModeCrypto, ModeAuto)
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
	lookupInput = U.LookupStringFlag(flagInput.Name)

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
	lookupOutput = U.LookupStringFlag(flagOutput.Name)

	// flagPrivKey defines the CLI flag for the private key
	flagPrivKey = &cli.StringFlag{
		Name: "privkey",
		Aliases: []string{
			"p",
		},
		TakesFile: false,
		Usage:     "Content of the private signing key as a string. If absent the tool creates a transient key",
	}
	lookupPrivKey = U.LookupStringFlagOpt(flagPrivKey.Name)

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
	lookupPrivKeyFile = U.LookupStringFlagOpt(flagPrivKeyFile.Name)

	// flagCert defines the CLI flag for the public encryption certificate
	flagCert = &cli.StringFlag{
		Name: "cert",
		Aliases: []string{
			"c",
		},
		TakesFile: false,
		Usage:     "Content of the encryption certificate as a string. If absent the tool uses a built-in default",
	}
	lookupCert = U.LookupStringFlagOpt(flagCert.Name)

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
	lookupCertFile = U.LookupStringFlagOpt(flagCertFile.Name)

	// flagMode is the operation mode
	flagMode = &cli.StringFlag{
		Name: "mode",
		Aliases: []string{
			"m",
		},
		Action:   validateMode,
		Required: false,
		Value:    ModeAuto,
		Usage:    fmt.Sprintf("Operational mode, valid values are %s", validModes),
	}
	lookupMode = U.LookupStringFlag(flagMode.Name)

	// modeToEncrypt is the mapping from encryption module identifier to
	modeToEncrypt = map[string]IO.IO[Encrypt.Encryption]{
		ModeCrypto:  Encrypt.CryptoEncryption,
		ModeOpenSSL: Encrypt.OpenSSLEncryption,
		ModeAuto:    Encrypt.DefaultEncryption,
	}

	// getEncryption returns the configured encryption module
	getEncryption = F.Flow3(
		RR.Lookup[IO.IO[Encrypt.Encryption], string],
		I.Ap[O.Option[IO.IO[Encrypt.Encryption]]](modeToEncrypt),
		O.GetOrElse(F.Constant(Encrypt.DefaultEncryption)),
	)
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

// getKeyFromConfig returns key content, either from direct input, a file or as a fallback transiently
func getKeyFromConfig(cfg KeyConfig) func(Encrypt.Key) Encrypt.Key {
	return getKey(cfg.FromDirect, cfg.FromFile)
}

// EncryptAndSignConfigFromContext decodes an [EncryptAndSignConfig] from a [cli.Context]
func EncryptAndSignConfigFromContext(ctx *cli.Context) *EncryptAndSignConfig {
	return &EncryptAndSignConfig{
		Mode: lookupMode(ctx),
		PrivKey: KeyConfig{
			lookupPrivKey(ctx),
			lookupPrivKeyFile(ctx),
		},
		PubCert: KeyConfig{
			lookupCert(ctx),
			lookupCertFile(ctx),
		},
	}
}

// ContractEncrypterFromConfig constructs a [SVIOE.ContractEncrypter] based on a config object
func ContractEncrypterFromConfig(cfg *EncryptAndSignConfig) IOE.IOEither[error, SVIOE.ContractEncrypter] {
	// encryption module
	encryption := F.Pipe2(
		cfg.Mode,
		getEncryption,
		IO.Memoize[Encrypt.Encryption],
	)
	// signing key
	privKey := F.Pipe3(
		encryption,
		IO.Map(Encrypt.Encryption.GetPrivKey),
		IOE.FromIO[error, Encrypt.Key],
		IOE.Chain(getKeyFromConfig(cfg.PrivKey)),
	)

	// public encryption key or certificate
	pubCert := F.Pipe1(
		defaultCertificate,
		getKeyFromConfig(cfg.PubCert),
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

	return F.Pipe2(
		IOE.SequenceTuple3(T.MakeTuple3(enc, signer, pubkey)),
		IOE.Map[error](T.Tupled3(SVIOE.EncryptAndSignContract)),
		IOE.Ap[SVIOE.ContractEncrypter](privKey),
	)
}
