// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	B "github.com/IBM/fp-go/bytes"
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	T "github.com/ibm-hyper-protect/contract-go/types"
	Y "github.com/ibm-hyper-protect/contract-go/yaml"
)

func serializeYaml[A any](value *A) O.Option[string] {
	return F.Pipe3(
		value,
		O.FromNillable[A],
		O.Chain(F.Flow2(
			Y.Stringify[*A],
			E.ToOption[error, []byte],
		)),
		O.Map(B.ToString),
	)
}

var rawValue = F.Flow2(
	O.FromNillable[string],
	O.Map(F.Deref[string]),
)

type (
	// ContractSerializer is the type of a function that takes a contract and that encrypts it
	ContractSerializer = func(ctr *T.Contract) EncryptedContract
)

// SerializeContract serializes the fields of the contract into a string map
func SerializeContract(ctr *T.Contract) EncryptedContract {
	return F.Pipe1(
		map[string]O.Option[string]{
			KeyWorkload:             serializeYaml(ctr.Workload),
			KeyEnv:                  serializeYaml(ctr.Env),
			KeyAttestationPublicKey: rawValue(ctr.AttestationPublicKey),
			KeyEnvWorkloadSignature: rawValue(ctr.EnvWorkloadSignature),
		},
		O.CompactRecord[string, string],
	)
}
