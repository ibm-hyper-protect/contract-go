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
	A "github.com/IBM/fp-go/array"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	L "github.com/IBM/fp-go/lazy"
	O "github.com/IBM/fp-go/option"
	S "github.com/IBM/fp-go/string"
	U "github.com/ibm-hyper-protect/contract-go/cli/utils"
	D "github.com/ibm-hyper-protect/contract-go/data"
	Encrypt "github.com/ibm-hyper-protect/contract-go/encrypt/ioeither"
)

var (
	// keyFromFile reads key data from a file or stdin
	keyFromFile = U.ReadFromInput

	// keyDirect is the key if provided directly as text
	keyDirect = F.Flow2(
		S.ToBytes,
		IOE.Of[error, []byte],
	)

	// defaultCertificate is the built-in certificate
	defaultCertificate = F.Pipe1(
		D.DefaultCertificate,
		keyDirect,
	)
)

// getKey returns key content, either from direct input, a file or as a fallback transiently
func getKey(direct, filename string) func(Encrypt.Key) Encrypt.Key {
	fromNonEmptyString := O.FromPredicate(S.IsNonEmpty)
	fromDirect := F.Pipe1(
		fromNonEmptyString(direct),
		O.Map(keyDirect),
	)
	fromFile := F.Pipe1(
		fromNonEmptyString(filename),
		O.Map(keyFromFile),
	)
	alt := O.AltMonoid[Encrypt.Key]()

	return func(defKey Encrypt.Key) Encrypt.Key {
		return F.Pipe2(
			A.From(fromDirect, fromFile),
			A.Fold(alt),
			O.GetOrElse(L.Of(defKey)),
		)
	}
}
