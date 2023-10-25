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

package ioeither

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEH "github.com/IBM/fp-go/ioeither/http"
	T "github.com/IBM/fp-go/tuple"
	C "github.com/ibm-hyper-protect/contract-go/certificates"
	CE "github.com/ibm-hyper-protect/contract-go/certificates/either"
)

// downloadTextFromUrl downloads textual content from a URL
func downloadTextFromUrl(client IOEH.Client) func(url string) IOE.IOEither[error, string] {
	return F.Flow2(
		makeGetRequest,
		IOE.Chain(IOEH.ReadText(client)),
	)
}

// downloadSingleVersion downloads the specified version and returns a tuple of version string and downloaded content
func downloadSingleVersion(client IOEH.Client) func(resolver CE.Resolver) func(version C.Version) IOE.IOEither[error, C.VersionCert] {
	download := downloadTextFromUrl(client)
	return func(resolver CE.Resolver) func(version C.Version) IOE.IOEither[error, C.VersionCert] {
		return F.Flow3(
			T.Replicate2[C.Version],
			T.Map2(
				F.Flow2(
					resolver,
					E.Fold(IOE.Left[string, error], download),
				),
				F.Curry2(T.MakeTuple2[C.Version, string]),
			),
			T.Tupled2(IOE.MonadMap[error, string, C.VersionCert]),
		)
	}
}

// DownloadCertificates downloads the certificates for the given versions
func DownloadCertificates(client IOEH.Client) func(resolver CE.Resolver) func(versions []C.Version) IOE.IOEither[error, []C.VersionCert] {
	return F.Flow2(
		downloadSingleVersion(client),
		IOE.TraverseArray[error, C.Version, C.VersionCert],
	)
}
