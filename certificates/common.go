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

package certificates

import (
	A "github.com/IBM/fp-go/array"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	O "github.com/IBM/fp-go/option"
	"github.com/IBM/fp-go/ord"
	P "github.com/IBM/fp-go/predicate"
	T "github.com/IBM/fp-go/tuple"
	"github.com/Masterminds/semver"
)

type (
	// Version identifier
	Version = *semver.Version
	// VersionCert is the pair out of version and certificate
	VersionCert = T.Tuple2[Version, string]
)

var (
	GetVersion = T.First[Version, string]

	OrdVersion = ord.MakeOrd(Version.Compare, Version.Equal)

	// SortCertByVersion sorts the structs by version in inverse order, i.e. the first item will be the latest version
	SortCertByVersion = A.SortByKey(ord.Reverse(OrdVersion), GetVersion)
)

func checkCertContraintPredicate(cstr *semver.Constraints) func(VersionCert) bool {
	return P.ContraMap(GetVersion)(cstr.Check)
}

// SelectCertBySpec selects the latest version that matches the specification
func SelectCertBySpec(spec *semver.Constraints) func(img []VersionCert) O.Option[VersionCert] {
	return F.Flow3(
		A.Filter(checkCertContraintPredicate(spec)),
		I.Map(SortCertByVersion),
		A.Head[VersionCert],
	)
}
