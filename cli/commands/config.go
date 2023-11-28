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
	"net/http"
	"os"
	"path/filepath"

	A "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IO "github.com/IBM/fp-go/io"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEH "github.com/IBM/fp-go/ioeither/http"
	J "github.com/IBM/fp-go/json"
	O "github.com/IBM/fp-go/option"
	RR "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	"github.com/Masterminds/semver"
	C "github.com/ibm-hyper-protect/contract-go/certificates"
	CE "github.com/ibm-hyper-protect/contract-go/certificates/either"
	CIOE "github.com/ibm-hyper-protect/contract-go/certificates/ioeither"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
	CF "github.com/ibm-hyper-protect/contract-go/file"
	CFIOE "github.com/ibm-hyper-protect/contract-go/file/ioeither"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	SVIOE "github.com/ibm-hyper-protect/contract-go/service/ioeither"
	"github.com/ibm-hyper-protect/contract-go/types"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
	"github.com/urfave/cli/v2"
)

const (
	// execution modes
	ModeOpenSSL = "openssl"
	ModeCrypto  = "crypto"
	ModeAuto    = "auto"

	// serialization formats
	FormatJson = "json"
	FormatYaml = "yaml"
)

type (
	KeyConfig struct {
		FromDirect O.Option[string] // key as a PEM encoded string
		FromFile   O.Option[string] // filename to a PEM encoded key
	}

	// OutputConfig specifies aspects of the output
	OutputConfig struct {
		Format string // output format (e.g. json, or yaml)
		Output string // target of the output (e.g. a filename, or stdout)
	}

	EncryptAndSignConfig struct {
		Mode    string    // one of the mode flags
		PrivKey KeyConfig // private key used for signing
		PubCert KeyConfig // public key used for encryption
	}

	DownloadCertificatesConfig struct {
		Versions    []string // possible versions to download
		UrlTemplate string   // the URL template for the download URL
	}
)

var (
	// valid modes
	validModes   = A.From(ModeOpenSSL, ModeCrypto, ModeAuto)
	validateMode = validateOneOfMany(validModes)
	// valid formats
	validFormats   = A.From(FormatJson, FormatYaml)
	validateFormat = validateOneOfMany(validFormats)

	// flagInput defines the CLI flag for the main input
	flagInput = &cli.StringFlag{
		Name: "in",
		Aliases: []string{
			"i",
		},
		Action:    validateInput,
		TakesFile: true,
		Value:     CF.StdInOutIdentifier,
		Usage:     fmt.Sprintf("Name of the input file or '%s' for stdin", CF.StdInOutIdentifier),
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
		Value:     CF.StdInOutIdentifier,
		Usage:     fmt.Sprintf("Name of the output file or '%s' for stdout", CF.StdInOutIdentifier),
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
		Usage:     "Private signing key as a filepath. If absent the tool creates a transient key",
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
		Usage:     "Encryption certificate as a filepath. If absent the tool uses a built-in default",
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

	// flagVersions depicts a range of potential versions
	flagVersions = &cli.StringSliceFlag{
		Name:     "versions",
		Action:   validateVersions,
		Required: false,
		Usage:    "List of possible versions",
	}
	lookupVersions = U.LookupStringSliceFlag(flagVersions.Name)

	// flagSpec is a semantic version range specifier
	flagSpec = &cli.StringFlag{
		Name:     "spec",
		Action:   validateSpec,
		Required: false,
		Value:    "*",
		Usage:    "Semantic version range specifier",
	}
	lookupSpec = U.LookupStringFlag(flagSpec.Name)

	// flagFormat is a format specifier for the output format
	flagFormat = &cli.StringFlag{
		Name:     "format",
		Action:   validateFormat,
		Required: false,
		Value:    FormatYaml,
		Usage:    fmt.Sprintf("Format specififiers, valid values are %s", validFormats),
	}
	lookupFormat = U.LookupStringFlag(flagFormat.Name)

	// flagUrlTemplate specifies an URL template used to download certificates
	flagUrlTemplate = &cli.StringFlag{
		Name:     "urltemplate",
		Required: false,
		Value:    CE.DefaultTemplate,
		Usage:    "The default URL template for downloading certificates",
	}
	lookupUrlTemplate = U.LookupStringFlag(flagUrlTemplate.Name)

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

	// ContractEncrypterFromContext returns a [SVIOE.ContractEncrypter] based on a [cli.Context]
	ContractEncrypterFromContext = F.Flow2(
		EncryptAndSignConfigFromContext,
		ContractEncrypterFromConfig,
	)

	// ValidatedContractFromContext returns a [types.Contract] from a [cli.Context] and validates it against the schema
	ValidatedContractFromContext = F.Flow3(
		lookupInput,
		CFIOE.ReadFromInput,
		IOE.ChainEitherK(F.Flow2(
			Y.Parse[types.AnyMap],
			E.Chain(types.ValidateContract),
		)),
	)

	// getWriter gets a writer method to the specified output
	getWriter = CFIOE.WriteToOutput

	// EncryptAndSignFromContext returns an [SC.EncryptedContract] from information on the [cli.Context]
	EncryptAndSignFromContext = F.Flow4(
		T.Replicate2[*cli.Context],
		T.Map2(ContractEncrypterFromContext, ValidatedContractFromContext),
		T.Tupled2(IOE.MonadAp[IOE.IOEither[error, SC.EncryptedContract], error, *types.Contract]),
		IOE.Flatten[error, SC.EncryptedContract],
	)

	// EncryptSignAndWriteFromContext transforms an unencrypted contract into an encrypted and signed contract from information on the [cli.Context]
	EncryptSignAndWriteFromContext = F.Flow3(
		T.Replicate2[*cli.Context],
		T.Map2(EncryptAndSignFromContext, writeFromContext[SC.EncryptedContract]),
		T.Tupled2(IOE.MonadChain[error, SC.EncryptedContract, []byte]),
	)

	DownloadCertificatesFromContext = F.Flow2(
		DownloadCertificatesConfigFromContext,
		DownloadCertificatesFromConfig,
	)

	DownloadCertificatesAndWriteFromContext = F.Flow3(
		T.Replicate2[*cli.Context],
		T.Map2(DownloadCertificatesFromContext, writeFromContext[map[string]string]),
		T.Tupled2(IOE.MonadChain[error, map[string]string, []byte]),
	)
)

// writeFromOutputConfig creates a writer based on an output config
func writeFromOutputConfig[T any](config *OutputConfig) func(T) IOE.IOEither[error, []byte] {
	return F.Flow2(
		getSerializer[T](config.Format),
		E.Fold(IOE.Left[[]byte, error], getWriter(config.Output)),
	)
}

// writeFromContext serializes a data structure and persists it to a location specified by the [cli.Context]
func writeFromContext[T any](ctx *cli.Context) func(T) IOE.IOEither[error, []byte] {
	return F.Pipe2(
		ctx,
		OutputConfigFromContext,
		writeFromOutputConfig[T],
	)
}

// getSerializer returns a serializer for the format string
func getSerializer[T any](format string) func(T) E.Either[error, []byte] {
	switch format {
	case FormatJson:
		return J.Marshal[T]
	case FormatYaml:
		return Y.Stringify[T]
	default:
		return J.Marshal[T]
	}
}

func validateSpec(ctx *cli.Context, value string) error {
	return F.Pipe2(
		value,
		CE.ParseConstraint,
		E.ToError[*semver.Constraints],
	)
}

func validateVersions(ctx *cli.Context, values []string) error {
	return F.Pipe2(
		values,
		E.TraverseArray(CE.ParseVersion),
		E.ToError[[]C.Version],
	)
}

func validateInput(ctx *cli.Context, value string) error {
	if value == CF.StdInOutIdentifier {
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
	if value == CF.StdInOutIdentifier {
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

func validateOneOfMany(validValues []string) func(ctx *cli.Context, value string) error {
	return func(ctx *cli.Context, value string) error {
		return F.Pipe3(
			validValues,
			A.Filter(S.Equals(value)),
			A.Head[string],
			O.Fold(errors.OnNone("value [%s] is not valid, valid values are %s", value, validValues), F.Constant1[string, error](nil)),
		)
	}
}

// getKeyFromConfig returns key content, either from direct input, a file or as a fallback transiently
func getKeyFromConfig(cfg KeyConfig) func(Encrypt.Key) Encrypt.Key {
	return getKey(cfg.FromDirect, cfg.FromFile)
}

// OutputConfigFromContext returns an [OutputConfig] based on the [cli.Context]
func OutputConfigFromContext(ctx *cli.Context) *OutputConfig {
	return &OutputConfig{
		Format: lookupFormat(ctx),
		Output: lookupOutput(ctx),
	}
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

// DownloadCertificatesConfigFromContext decodes the [DownloadCertificatesConfig] from a [cli.Context]
func DownloadCertificatesConfigFromContext(ctx *cli.Context) *DownloadCertificatesConfig {
	return &DownloadCertificatesConfig{
		Versions:    lookupVersions(ctx),
		UrlTemplate: lookupUrlTemplate(ctx),
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

// DownloadCertificatesFromConfig dowloads certificates based on some config
func DownloadCertificatesFromConfig(cfg *DownloadCertificatesConfig) IOE.IOEither[error, map[string]string] {
	download := CIOE.DownloadCertificates(IOEH.MakeClient(http.DefaultClient))
	resolver := CE.ParseResolver(cfg.UrlTemplate)

	return F.Pipe3(
		cfg.Versions,
		E.TraverseArray(CE.ParseVersion),
		E.Fold(IOE.Left[[]C.VersionCert, error], download(resolver)),
		IOE.Map[error](F.Flow2(
			A.Map(T.Map2(C.Version.String, F.Identity[string])),
			RR.FromEntries[string, string],
		)),
	)
}
