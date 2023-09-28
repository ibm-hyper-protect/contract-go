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

package either

import (
	"fmt"
	"testing"

	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/IBM/fp-go/ioeither/file"
	L "github.com/IBM/fp-go/optics/lens"
	LR "github.com/IBM/fp-go/optics/lens/record"
	Types "github.com/ibm-hyper-protect/contract-go/types"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	// sample contract
	sample := F.Pipe1(
		file.ReadFile("../../samples/contracts/cidata.decrypted.yml"),
		IOE.ChainEitherK(ParseContract),
	)
	// check
	assert.True(t, E.IsRight(sample()))
}

func TestParseAndValidate(t *testing.T) {
	// sample contract
	sample := F.Pipe1(
		file.ReadFile("../../samples/contracts/cidata.decrypted.yml"),
		IOE.ChainEitherK(ParseAndValidateContract),
	)
	// check
	assert.True(t, E.IsRight(sample()))
}

func TestParseAndValidateWithSignings(t *testing.T) {
	// sample contract
	sample := F.Pipe1(
		file.ReadFile("../../samples/contracts/cidata.decrypted.with.rhs.yml"),
		IOE.ChainEitherK(ParseAndValidateContract),
	)
	// check
	assert.True(t, E.IsRight(sample()))
	// build a safe accessor to the desired key
	signingsFromContract := F.Pipe2(
		Types.OpticContract.Workload,
		L.ComposeOptions[*Types.Contract, *Types.Images](Types.MonoidContract.Workload.Empty())(Types.OpticWorkload.Images),
		L.ComposeOptions[*Types.Contract, Types.RedHatSignings](&Types.EmptyImages)(Types.OpticImages.RedHatSigning),
	)

	// select a particular signing key
	keyFromContract := F.Pipe2(
		signingsFromContract,
		L.ComposeOptions[*Types.Contract, *Types.RedHatSigning](Types.EmptyRedHatSignings)(LR.AtRecord[*Types.RedHatSigning]("de.icr.io/zaas-hpse-prod/hpse-docker-test-health-s390x:1.2.3")),
		L.ComposeOption[*Types.Contract, string](&Types.EmptyRedHatSigning)(Types.OpticRedHatSigning.PublicKey),
	)

	// read the key
	key := F.Pipe1(
		sample,
		IOE.ChainOptionK[*Types.Contract, string](errors.OnNone("unable to locate the public key"))(keyFromContract.Get),
	)

	fmt.Println(key())
	// check
	assert.True(t, E.IsRight(key()))
}
