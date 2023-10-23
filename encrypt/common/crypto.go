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
	"encoding/pem"

	RA "github.com/IBM/fp-go/array"
	F "github.com/IBM/fp-go/function"
	P "github.com/IBM/fp-go/predicate"
	S "github.com/IBM/fp-go/string"
)

const (
	TypePublicKey   = "PUBLIC KEY"
	TypeCertificate = "CERTIFICATE"
)

func GetTypeFromBlock(block *pem.Block) string {
	return block.Type
}

var IsType = F.Flow2(
	S.Equals,
	P.ContraMap(GetTypeFromBlock),
)

// PemDecodeAll will decode the complete PEM structure
func PemDecodeAll(data []byte) []*pem.Block {
	// result
	res := RA.Empty[*pem.Block]()
	block, remainder := pem.Decode(data)
	for block != nil {
		res = append(res, block)
		block, remainder = pem.Decode(remainder)
	}
	// done
	return res
}
