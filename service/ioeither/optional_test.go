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
	"testing"

	A "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/IBM/fp-go/ioeither/file"
	J "github.com/IBM/fp-go/json"
	I "github.com/IBM/fp-go/optics/iso"
	L "github.com/IBM/fp-go/optics/lens"
	LI "github.com/IBM/fp-go/optics/lens/iso"
	O "github.com/IBM/fp-go/option"
	T "github.com/IBM/fp-go/tuple"
	Types "github.com/ibm-hyper-protect/contract-go/types"
	"github.com/qri-io/jsonschema"
	"github.com/stretchr/testify/assert"
)

type AllowedEndpoints struct {
	AllowedEndpoints []string `json:"allowedEndpoints" yaml:"allowedEndpoints"`
}

type ConfidentialContainers struct {
	Config *AllowedEndpoints `json:"config" yaml:"config"`
}

var (
	lensConfig           = L.MakeLensRef((*ConfidentialContainers).GetConfig, (*ConfidentialContainers).SetConfig)
	lensAllowedEndpoints = L.MakeLensRef((*AllowedEndpoints).GetAllowedEndpoints, (*AllowedEndpoints).SetAllowedEndpoints)

	allowedEndpointsFromConfig = L.Compose[*ConfidentialContainers](lensAllowedEndpoints)(lensConfig)
)

func (allowedendpoints *AllowedEndpoints) GetAllowedEndpoints() []string {
	return allowedendpoints.AllowedEndpoints
}

func (allowedendpoints *AllowedEndpoints) SetAllowedEndpoints(AllowedEndpoints []string) *AllowedEndpoints {
	allowedendpoints.AllowedEndpoints = AllowedEndpoints
	return allowedendpoints
}
func (confidentialcontainers *ConfidentialContainers) GetConfig() *AllowedEndpoints {
	return confidentialcontainers.Config
}

func (confidentialcontainers *ConfidentialContainers) SetConfig(Config *AllowedEndpoints) *ConfidentialContainers {
	confidentialcontainers.Config = Config
	return confidentialcontainers
}

// fromNillableAny converts between any and an `Option[any]`
var fromNillableAny = I.MakeIso(O.FromPredicate(func(s any) bool { return s != nil }), O.Fold(F.Constant((any)(nil)), F.Identity[any]))

func TestDecodeK8SContract(t *testing.T) {
	// load the schema
	optional := F.Pipe3(
		"../../samples/schema/k8s.json",
		file.ReadFile,
		IOE.ChainEitherK(J.Unmarshal[*jsonschema.Schema]),
		IOE.Map[error](func(schema *jsonschema.Schema) L.Lens[*Types.Workload, O.Option[*ConfidentialContainers]] {
			return F.Pipe2(
				L.MakeLensRef((*Types.Workload).GetConfidentialContainers, (*Types.Workload).SetConfidentialContainers),
				LI.Compose[*Types.Workload](fromNillableAny),
				Types.FromPredicate[*Types.Workload, *ConfidentialContainers](schema),
			)
		}),
	)
	// sample contract
	sample := ReadContract("../../samples/contracts/cidata.decrypted.k8s.yml")

	// decode and apply
	res := F.Pipe2(
		IOE.SequenceT2(optional, sample),
		IOE.ChainOptionK[T.Tuple2[L.Lens[*Types.Workload, O.Option[*ConfidentialContainers]], *Types.Contract], *ConfidentialContainers](errors.OnNone("unable to decode the contract"))(T.Tupled2(func(opt L.Lens[*Types.Workload, O.Option[*ConfidentialContainers]], ctr *Types.Contract) O.Option[*ConfidentialContainers] {
			// the lens
			containersFromContract := F.Pipe1(
				Types.OpticContract.Workload,
				L.ComposeOptions[*Types.Contract, *ConfidentialContainers](Types.MonoidContract.Workload.Empty())(opt),
			)
			// return the value
			return containersFromContract.Get(ctr)
		})),
		IOE.Map[error](allowedEndpointsFromConfig.Get),
	)

	assert.Equal(t, E.Of[error](A.From("a", "b", "c")), res())

}
