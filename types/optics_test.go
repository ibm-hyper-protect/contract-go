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

package types

import (
	"testing"

	F "github.com/IBM/fp-go/function"
	L "github.com/IBM/fp-go/optics/lens"
	LR "github.com/IBM/fp-go/optics/lens/record"
	O "github.com/IBM/fp-go/option"
	"github.com/stretchr/testify/assert"
)

var (
	// lenses that focus on the desired subsections

	// focus on the workload volumes map in the contract
	//
	// OpticContract.Workload selects the workload from a contract. Workload is optional, so this yields an `Option[*Workload]`
	// OpticWorkload.Volumes selects the volumes map from the workload. Volumes are optional, so this yields an `Option[WorkloadVolumes] aka Option[map[string]WorkloadVolume]`
	// L.ComposeOptions combines boths selectors such that the volumes map is selected directly from the contract.
	// - since the selector can also be used to write the volumes map, we need to specify a default value for the parent value (*Workload) in case it is missing. This is `MonoidContract.Workload.Empty()`
	// - the signature looks a bit lengthy because we need to explicitly pass the types of the involved layers. Hopefully this can be auto detected in a future version of go
	//
	// the final type of the selector is `Lens[*Contract, Option[WorkloadVolumes]]`, so it appears as if the volumes map can be selected directly from the contract. It "focusses"
	// on this field, hence the name `Lens`
	workloadVolumesFromContract = F.Pipe1(
		OpticContract.Workload,
		L.ComposeOptions[*Contract, WorkloadVolumes](MonoidContract.Workload.Empty())(OpticWorkload.Volumes),
	)

	// atWorkloadVolume is a composer for a particular volume
	//
	// this is a function that accepts the volume name as a string. It returns a transform that focusses from a lens to a volumes map to a lens to that specific
	// volume in the map. Hence the final composition will select one particular volume directly from the contract
	atWorkloadVolume = F.Flow2(
		LR.AtRecord[WorkloadVolume, string],
		L.ComposeOptions[*Contract, WorkloadVolume](MonoidWorkload.Volumes.Empty()),
	)

	// focus on the env volumes map in the contract
	envVolumesFromContract = F.Pipe1(
		OpticContract.Env,
		L.ComposeOptions[*Contract, EnvVolumes](MonoidContract.Env.Empty())(OpticEnv.Volumes),
	)
)

// TestContractWithOptics tests if a contract can be manipulated via optics
func TestContractWithOptics(t *testing.T) {
	// start with an empty contract
	empty := ContractMonoid.Empty()

	// focus on a particlar volume, i.e. "test"
	// this lens can read and write the desired volume. When writing it automatically creates
	// all intermediate data structures if required
	testVolumeFromContract := F.Pipe1(
		workloadVolumesFromContract,
		atWorkloadVolume("test"),
	)

	// the empty record should not contain the volume
	fromEmpty := testVolumeFromContract.Get(empty)
	assert.Equal(t, O.None[WorkloadVolume](), fromEmpty)

	// setter for actual volume data
	// note that we use a `O.Some` because we can use the setter to both set and delete the volume. For deletion we'd pass in a `O.None`
	// note that the setter will never modify the original data structure but it creates a copy instead (only copying the fields along the path of modification)
	volumeSetter := testVolumeFromContract.Set(O.Some(WorkloadVolume{
		Seed: "workloadSeed",
	}))

	// deleter for the volume
	volumeUnsetter := testVolumeFromContract.Set(O.None[WorkloadVolume]())

	// actually set the volume
	contractWithVolume := volumeSetter(empty)
	// the empty contract should not have changed
	assert.Equal(t, O.None[WorkloadVolume](), testVolumeFromContract.Get(empty))
	assert.Equal(t, O.Some(WorkloadVolume{Seed: "workloadSeed"}), testVolumeFromContract.Get(contractWithVolume))

	// unset the volume
	contractWithoutVolume := volumeUnsetter(contractWithVolume)
	// the contracts so far should not have changed
	assert.Equal(t, O.None[WorkloadVolume](), testVolumeFromContract.Get(empty))
	assert.Equal(t, O.Some(WorkloadVolume{Seed: "workloadSeed"}), testVolumeFromContract.Get(contractWithVolume))
	assert.Equal(t, O.None[WorkloadVolume](), testVolumeFromContract.Get(contractWithoutVolume))
}
