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

	"github.com/stretchr/testify/assert"
)

// TestMergeContract tests if two contract documents can be merged together
func TestMergeContract(t *testing.T) {

	// hardcode contracts
	ctr1 := &Contract{
		Workload: &Workload{
			Type: TypeWorkload,
			Volumes: WorkloadVolumes{
				"test": WorkloadVolume{
					Seed: "workloadSeed",
				},
			},
		},
		Env: &Env{
			Type: TypeEnv,
			Volumes: EnvVolumes{
				"test": EnvVolume{
					Seed: "envSeed",
				},
			},
		},
	}
	ctr2 := &Contract{
		Workload: &Workload{
			Type: TypeWorkload,
			Volumes: WorkloadVolumes{
				"test1": WorkloadVolume{
					Seed: "workloadSeed1",
				},
				"test": WorkloadVolume{
					Seed:       "workloadSeed",
					Filesystem: &FilesystemExt4,
				},
			},
		},
		Env: &Env{
			Type: TypeEnv,
			Volumes: EnvVolumes{
				"test1": EnvVolume{
					Seed: "envSeed1",
				},
			},
		},
	}

	// combine contracts
	combined := ContractMonoid.Concat(ctr1, ctr2)

	// expected
	expected := &Contract{
		Workload: &Workload{
			Type: TypeWorkload,
			Volumes: WorkloadVolumes{
				"test1": WorkloadVolume{
					Seed: "workloadSeed1",
				},
				"test": WorkloadVolume{
					Seed:       "workloadSeed",
					Filesystem: &FilesystemExt4,
				},
			},
		},
		Env: &Env{
			Type: TypeEnv,
			Volumes: EnvVolumes{
				"test1": EnvVolume{
					Seed: "envSeed1",
				},
				"test": EnvVolume{
					Seed: "envSeed",
				},
			},
		},
	}

	assert.Equal(t, expected, combined)
}
