package types

import (
	F "github.com/IBM/fp-go/function"
	M "github.com/IBM/fp-go/monoid"
	R "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
)

type (
	TypeMonoidEnvVolume struct {
		Seed M.Monoid[string]
	}

	TypeMonoidWorkloadVolume struct {
		Seed       M.Monoid[string]
		Filesystem M.Monoid[*string]
		Mount      M.Monoid[*string]
	}

	TypeMonoidWorkloadVolumes struct {
		Volume M.Monoid[WorkloadVolume]
	}

	TypeMonoidEnvVolumes struct {
		Volume M.Monoid[EnvVolume]
	}

	TypeMonoidWorkload struct {
		Type    M.Monoid[string]
		Volumes M.Monoid[WorkloadVolumes]
	}

	TypeMonoidEnv struct {
		Type    M.Monoid[string]
		Volumes M.Monoid[EnvVolumes]
	}

	TypeMonoidContract struct {
		Workload             M.Monoid[*Workload]
		Env                  M.Monoid[*Env]
		AttestationPublicKey M.Monoid[*string]
		EnvWorkloadSignature M.Monoid[*string]
	}
)

var (
	stringMonoid    = M.MakeMonoid(F.Second[string, string], S.Monoid.Empty())
	stringRefMonoid = M.MakeMonoid(func(left, right *string) *string {
		if right == nil {
			return left
		}
		return right
	}, nil)

	MonoidEnvVolume = TypeMonoidEnvVolume{
		Seed: stringMonoid,
	}

	MonoidWorkloadVolume = TypeMonoidWorkloadVolume{
		Seed:       stringMonoid,
		Filesystem: stringRefMonoid,
		Mount:      stringRefMonoid,
	}

	MonoidWorkloadVolumes = TypeMonoidWorkloadVolumes{
		Volume: M.MakeMonoid(func(left, right WorkloadVolume) WorkloadVolume {
			return WorkloadVolume{
				Seed:       MonoidWorkloadVolume.Seed.Concat(left.Seed, right.Seed),
				Filesystem: MonoidWorkloadVolume.Filesystem.Concat(left.Filesystem, right.Filesystem),
				Mount:      MonoidWorkloadVolume.Mount.Concat(left.Mount, right.Mount),
			}
		}, WorkloadVolume{
			Seed:       MonoidWorkloadVolume.Seed.Empty(),
			Filesystem: MonoidWorkloadVolume.Filesystem.Empty(),
			Mount:      MonoidWorkloadVolume.Mount.Empty(),
		}),
	}

	MonoidEnvVolumes = TypeMonoidEnvVolumes{
		Volume: M.MakeMonoid(func(left, right EnvVolume) EnvVolume {
			return EnvVolume{
				Seed: MonoidEnvVolume.Seed.Concat(left.Seed, right.Seed),
			}
		}, EnvVolume{
			Seed: MonoidEnvVolume.Seed.Empty(),
		}),
	}

	// MonoidWorkload contains the monoids for the fields in the workload
	MonoidWorkload = TypeMonoidWorkload{
		Type:    M.MakeMonoid(F.Second[string, string], TypeWorkload),
		Volumes: R.UnionMonoid[string, WorkloadVolume](MonoidWorkloadVolumes.Volume),
	}

	// MonoidEnv contains the monoids for the fields in the env type
	MonoidEnv = TypeMonoidEnv{
		Type:    M.MakeMonoid(F.Second[string, string], TypeEnv),
		Volumes: R.UnionMonoid[string, EnvVolume](MonoidEnvVolumes.Volume),
	}

	MonoidContract = TypeMonoidContract{
		Workload: M.MakeMonoid(func(left, right *Workload) *Workload {
			if left == nil {
				return right
			}
			if right == nil {
				return left
			}
			return &Workload{
				Type:    MonoidWorkload.Type.Concat(left.Type, right.Type),
				Volumes: MonoidWorkload.Volumes.Concat(left.Volumes, right.Volumes),
			}
		}, &Workload{
			Type:    MonoidWorkload.Type.Empty(),
			Volumes: MonoidWorkload.Volumes.Empty(),
		}),
		Env: M.MakeMonoid(func(left, right *Env) *Env {
			if left == nil {
				return right
			}
			if right == nil {
				return left
			}
			return &Env{
				Type:    MonoidEnv.Type.Concat(left.Type, right.Type),
				Volumes: MonoidEnv.Volumes.Concat(left.Volumes, right.Volumes),
			}
		}, &Env{
			Type:    MonoidEnv.Type.Empty(),
			Volumes: MonoidEnv.Volumes.Empty(),
		}),
		AttestationPublicKey: stringRefMonoid,
		EnvWorkloadSignature: stringRefMonoid,
	}

	// ContractMonoid is a monoid that allows to merge contracts
	ContractMonoid = M.MakeMonoid(func(left, right *Contract) *Contract {
		if left == nil {
			return right
		}
		if right == nil {
			return left
		}
		return &Contract{
			Workload:             MonoidContract.Workload.Concat(left.Workload, right.Workload),
			Env:                  MonoidContract.Env.Concat(left.Env, right.Env),
			AttestationPublicKey: MonoidContract.AttestationPublicKey.Concat(left.AttestationPublicKey, right.AttestationPublicKey),
			EnvWorkloadSignature: MonoidContract.EnvWorkloadSignature.Concat(left.EnvWorkloadSignature, right.EnvWorkloadSignature),
		}
	}, &Contract{
		Workload:             MonoidContract.Workload.Empty(),
		Env:                  MonoidContract.Env.Empty(),
		AttestationPublicKey: MonoidContract.AttestationPublicKey.Empty(),
		EnvWorkloadSignature: MonoidContract.EnvWorkloadSignature.Empty(),
	})
)
