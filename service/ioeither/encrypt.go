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

package ioeither

import (
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	R "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	SC "github.com/ibm-hyper-protect/contract-go/service/common"
	T "github.com/ibm-hyper-protect/contract-go/types"
)

type (
	// ContractEncrypter is the type of a function that takes a contract and that encrypts it
	ContractEncrypter = func(ctr *T.Contract) IOE.IOEither[error, SC.EncryptedContract]
)

// EncryptContract encrypts the field in a contract with the given public key
func EncryptContract(encBasic func(pubKey []byte) func(data []byte) IOE.IOEither[error, string]) func(pubkey []byte) ContractEncrypter {
	return func(pubkey []byte) ContractEncrypter {
		return F.Flow3(
			SC.SerializeContract,
			R.Map[string](F.Flow2(
				S.ToBytes,
				encBasic(pubkey),
			)),
			IOE.SequenceRecord[string, error, string],
		)
	}
}
