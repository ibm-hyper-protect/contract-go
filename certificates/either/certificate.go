// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package datasource

package either

import (
	"bytes"
	"fmt"
	"text/template"

	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	R "github.com/IBM/fp-go/record"
	T "github.com/IBM/fp-go/tuple"
	"github.com/Masterminds/semver"
	C "github.com/ibm-hyper-protect/contract-go/certificates"
)

const (
	// template key
	KeyMajor = "Major"
	KeyMinor = "Minor"
	KeyPatch = "Patch"
)

type (
	Resolver = func(version C.Version) E.Either[error, string]
)

var (
	// DefaultTemplate is the default template used to download certificates
	DefaultTemplate = fmt.Sprintf("https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-{{.%s}}-{{.%s}}-s390x-{{.%s}}-encrypt.crt", KeyMajor, KeyMinor, KeyPatch)

	// ParseConstraint parses a constraint string into a constraint object
	ParseConstraint = E.Eitherize1(semver.NewConstraint)

	// toCertificateMap performs a type conversion of the certificates
	toCertificateMap = E.TraverseRecord[string](E.ToType[string](errors.OnSome[any]("Cannot convert [%v] to a string")))

	// ParseVersion parses a version string into a version object
	ParseVersion = E.Eitherize1(semver.NewVersion)

	// ParseResolver parses a template string into a resolver function
	ParseResolver = F.Flow2(
		ParseTemplate("DownloadUrl"),
		E.Fold(F.Flow2(
			E.Left[string, error],
			F.Constant1[C.Version, E.Either[error, string]],
		), ResolveUrl),
	)
)

// ParseTemplate parses a template of the given name
func ParseTemplate(name string) func(string) E.Either[error, *template.Template] {
	return E.Eitherize1(template.New(name).Parse)
}

// parseEntry parses the version part of an entry
func parseEntry(entry T.Tuple2[string, string]) E.Either[error, C.VersionCert] {
	return F.Pipe2(
		entry.F1,
		ParseVersion,
		E.Map[error](F.Bind2nd(T.MakeTuple2[C.Version, string], entry.F2)),
	)
}

// ResolveUrl computes the download URL from a version number
func ResolveUrl(tmp *template.Template) Resolver {
	return func(version C.Version) E.Either[error, string] {
		ctx := map[string]int64{
			KeyMajor: version.Major(),
			KeyMinor: version.Minor(),
			KeyPatch: version.Patch(),
		}
		// execute and return
		var buffer bytes.Buffer
		err := tmp.Execute(&buffer, ctx)
		return E.TryCatchError(buffer.String(), err)
	}
}

// CertificateFromSpec selects the best matching certificate from a map out of string and certificate
func CertificateFromSpec(spec *semver.Constraints) func(certs map[string]string) E.Either[error, C.VersionCert] {
	return F.Flow4(
		R.ToEntries[string, string],
		E.TraverseArray(parseEntry),
		E.Map[error](C.SelectCertBySpec(spec)),
		E.Chain(E.FromOption[C.VersionCert](errors.OnNone("unable to select a version"))),
	)
}
