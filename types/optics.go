package types

import (
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/optics/iso"
	L "github.com/IBM/fp-go/optics/lens"
	LI "github.com/IBM/fp-go/optics/lens/iso"
	O "github.com/IBM/fp-go/option"
	R "github.com/IBM/fp-go/record/generic"
	ENV "github.com/ibm-hyper-protect/contract-go/environment"
)

type (
	TypeOpticEnvVolume struct {
		Seed L.Lens[*EnvVolume, string]
	}

	TypeOpticWorkloadVolume struct {
		Seed       L.Lens[*WorkloadVolume, string]
		Filesystem L.Lens[*WorkloadVolume, O.Option[string]]
		Mount      L.Lens[*WorkloadVolume, O.Option[string]]
	}

	TypeOpticLogDNA struct {
		IngestionKey L.Lens[*LogDNA, string]
		Hostname     L.Lens[*LogDNA, string]
		Port         L.Lens[*LogDNA, O.Option[int]]
		Tags         L.Lens[*LogDNA, O.Option[[]string]]
	}

	TypeOpticSysLog struct {
		Server   L.Lens[*SysLog, string]
		Hostname L.Lens[*SysLog, string]
		Port     L.Lens[*SysLog, O.Option[int]]
		Cert     L.Lens[*SysLog, O.Option[string]]
		Key      L.Lens[*SysLog, O.Option[string]]
	}

	TypeOpticRedHatSigning struct {
		PublicKey L.Lens[*RedHatSigning, string]
	}

	TypeOpticDockerContentTrust struct {
		Notary    L.Lens[*DockerContentTrust, string]
		PublicKey L.Lens[*DockerContentTrust, string]
	}

	TypesOpticImages struct {
		DockerContentTrust L.Lens[*Images, O.Option[DockerContentTrusts]]
		RedHatSigning      L.Lens[*Images, O.Option[RedHatSignings]]
	}

	TypeOpticWorkload struct {
		Type                   L.Lens[*Workload, string]
		Volumes                L.Lens[*Workload, O.Option[WorkloadVolumes]]
		Auths                  L.Lens[*Workload, O.Option[Auths]]
		Images                 L.Lens[*Workload, O.Option[*Images]]
		Env                    L.Lens[*Workload, O.Option[ENV.Env]]
		Compose                L.Lens[*Workload, O.Option[*Compose]]
		Play                   L.Lens[*Workload, O.Option[*Play]]
		ConfidentialContainers L.Lens[*Workload, any]
	}

	TypeOpticEnv struct {
		Type    L.Lens[*Env, string]
		Volumes L.Lens[*Env, O.Option[EnvVolumes]]
		Env     L.Lens[*Env, O.Option[ENV.Env]]
	}

	TypeOpticContract struct {
		Workload             L.Lens[*Contract, O.Option[*Workload]]
		Env                  L.Lens[*Contract, O.Option[*Env]]
		AttestationPublicKey L.Lens[*Contract, O.Option[string]]
		EnvWorkloadSignature L.Lens[*Contract, O.Option[string]]
	}
)

// fromNillableSlice converts a nillable value to an option and back
func fromNillableSlice[M ~[]T, T any]() I.Iso[M, O.Option[M]] {
	return I.MakeIso(
		O.FromPredicate(func(s M) bool { return s != nil }),
		O.Fold(F.Constant((M)(nil)), F.Identity[M]),
	)
}

// fromNillableMap converts a nillable value to an option and back
func fromNillableMap[M ~map[K]V, K comparable, V any]() I.Iso[M, O.Option[M]] {
	return I.MakeIso(
		O.FromPredicate(R.IsNonNil[M, K, V]),
		O.Fold(R.ConstNil[M, K, V], F.Identity[M]),
	)
}

var (
	intIso    = LI.FromNillable[int]()
	stringIso = LI.FromNillable[string]()

	// OpticEnvVolume contains the optical elements to access fields in an env volume
	OpticEnvVolume = TypeOpticEnvVolume{
		Seed: L.MakeLensRef((*EnvVolume).GetSeed, (*EnvVolume).SetSeed),
	}

	fromNillableWorkloadVolumeString = LI.Compose[*WorkloadVolume](stringIso)

	// OpticWorkloadVolume contains the optical elements to access fields in a workload volume
	OpticWorkloadVolume = TypeOpticWorkloadVolume{
		Seed:       L.MakeLensRef((*WorkloadVolume).GetSeed, (*WorkloadVolume).SetSeed),
		Filesystem: fromNillableWorkloadVolumeString(L.MakeLensRef((*WorkloadVolume).GetFilesystem, (*WorkloadVolume).SetFilesystem)),
		Mount:      fromNillableWorkloadVolumeString(L.MakeLensRef((*WorkloadVolume).GetMount, (*WorkloadVolume).SetMount)),
	}

	// OpticLogDNA contains the optical elements to access fields in the logDNA section
	OpticLogDNA = TypeOpticLogDNA{
		IngestionKey: L.MakeLensRef((*LogDNA).GetIngestionKey, (*LogDNA).SetIngestionKey),
		Hostname:     L.MakeLensRef((*LogDNA).GetHostname, (*LogDNA).SetHostname),
		Port:         LI.Compose[*LogDNA](intIso)(L.MakeLensRef((*LogDNA).GetPort, (*LogDNA).SetPort)),
		Tags:         LI.Compose[*LogDNA](fromNillableSlice[[]string]())(L.MakeLensRef((*LogDNA).GetTags, (*LogDNA).SetTags)),
	}

	fromNillableSysLogString = LI.Compose[*SysLog](stringIso)
	fromNillableSysLogInt    = LI.Compose[*SysLog](intIso)

	// OpticSysLog contains the optical elements to access fields in the syslog section
	OpticSysLog = TypeOpticSysLog{
		Server:   L.MakeLensRef((*SysLog).GetServer, (*SysLog).SetServer),
		Hostname: L.MakeLensRef((*SysLog).GetHostname, (*SysLog).SetHostname),
		Port:     fromNillableSysLogInt(L.MakeLensRef((*SysLog).GetPort, (*SysLog).SetPort)),
		Cert:     fromNillableSysLogString(L.MakeLensRef((*SysLog).GetCert, (*SysLog).SetCert)),
		Key:      fromNillableSysLogString(L.MakeLensRef((*SysLog).GetKey, (*SysLog).SetKey)),
	}

	// OpticRedHatSigning contains the optical elements to access fields in the red had signing section
	OpticRedHatSigning = TypeOpticRedHatSigning{
		PublicKey: L.MakeLensRef((*RedHatSigning).GetPublicKey, (*RedHatSigning).SetPublicKey),
	}

	// OpticDockerContentTrust contains the optical elements to access fields in the docker content trust section
	OpticDockerContentTrust = TypeOpticDockerContentTrust{
		Notary:    L.MakeLensRef((*DockerContentTrust).GetNotary, (*DockerContentTrust).SetNotary),
		PublicKey: L.MakeLensRef((*DockerContentTrust).GetPublicKey, (*DockerContentTrust).SetPublicKey),
	}

	// OpticImages contains the optical elements to access fields in the images section
	OpticImages = TypesOpticImages{
		DockerContentTrust: LI.Compose[*Images](fromNillableMap[DockerContentTrusts]())(L.MakeLensRef((*Images).GetDockerContentTrust, (*Images).SetDockerContentTrust)),
		RedHatSigning:      LI.Compose[*Images](fromNillableMap[RedHatSignings]())(L.MakeLensRef((*Images).GetRedHatSigning, (*Images).SetRedHatSigning)),
	}

	// OpticWorkload contains the optical elements to access fields in the workload section
	OpticWorkload = TypeOpticWorkload{
		Type:                   L.MakeLensRef((*Workload).GetType, (*Workload).SetType),
		Volumes:                LI.Compose[*Workload](fromNillableMap[WorkloadVolumes]())(L.MakeLensRef((*Workload).GetVolumes, (*Workload).SetVolumes)),
		Auths:                  LI.Compose[*Workload](fromNillableMap[Auths]())(L.MakeLensRef((*Workload).GetAuths, (*Workload).SetAuths)),
		Images:                 L.FromNillable(L.MakeLensRef((*Workload).GetImages, (*Workload).SetImages)),
		Env:                    LI.Compose[*Workload](fromNillableMap[ENV.Env]())(L.MakeLensRef((*Workload).GetEnv, (*Workload).SetEnv)),
		Compose:                L.FromNillable(L.MakeLensRef((*Workload).GetCompose, (*Workload).SetCompose)),
		Play:                   L.FromNillable(L.MakeLensRef((*Workload).GetPlay, (*Workload).SetPlay)),
		ConfidentialContainers: L.MakeLensRef((*Workload).GetConfidentialContainers, (*Workload).SetConfidentialContainers),
	}

	// OpticEnv contains the optical elements to access fields in the env section
	OpticEnv = TypeOpticEnv{
		Type:    L.MakeLensRef((*Env).GetType, (*Env).SetType),
		Volumes: LI.Compose[*Env](fromNillableMap[EnvVolumes]())(L.MakeLensRef((*Env).GetVolumes, (*Env).SetVolumes)),
		Env:     LI.Compose[*Env](fromNillableMap[ENV.Env]())(L.MakeLensRef((*Env).GetEnv, (*Env).SetEnv)),
	}

	fromNillableContractString = LI.Compose[*Contract](stringIso)

	// OpticContract contains the optical elements to access fields in the contract
	OpticContract = TypeOpticContract{
		Workload:             L.FromNillable(L.MakeLensRef((*Contract).GetWorkload, (*Contract).SetWorkload)),
		Env:                  L.FromNillable(L.MakeLensRef((*Contract).GetEnv, (*Contract).SetEnv)),
		AttestationPublicKey: fromNillableContractString(L.MakeLensRef((*Contract).GetAttestationPublicKey, (*Contract).SetAttestationPublicKey)),
		EnvWorkloadSignature: fromNillableContractString(L.MakeLensRef((*Contract).GetEnvWorkloadSignature, (*Contract).SetEnvWorkloadSignature)),
	}
)
