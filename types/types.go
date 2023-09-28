package types

import (
	R "github.com/IBM/fp-go/record"
	ENV "github.com/ibm-hyper-protect/contract-go/environment"
)

const (
	TypeEnv      = "env"
	TypeWorkload = "workload"
)

var (
	EmptyImages         = Images{}
	EmptyRedHatSignings = R.Empty[string, *RedHatSigning]()
	EmptyRedHatSigning  = RedHatSigning{}

	FilesystemExt4  = "ext4"
	FilesystemXFS   = "xfs"
	FilesystemBtrFS = "btrfs"
)

type (
	LogDNA struct {
		IngestionKey string   `json:"ingestionKey" yaml:"ingestionKey"`
		Hostname     string   `json:"hostname" yaml:"hostname"`
		Port         *int     `json:"port,omitempty" yaml:"port,omitempty"`
		Tags         []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	}

	SysLog struct {
		Server   string  `json:"server" yaml:"server"`
		Hostname string  `json:"hostname" yaml:"hostname"`
		Port     *int    `json:"port,omitempty" yaml:"port,omitempty"`
		Cert     *string `json:"cert,omitempty" yaml:"cert,omitempty"`
		Key      *string `json:"key,omitempty" yaml:"key,omitempty"`
	}

	Logging struct {
		LogDNA *LogDNA `json:"logDNA,omitempty" yaml:"logDNA,omitempty"`
		SysLog *SysLog `json:"syslog,omitempty" yaml:"syslog,omitempty"`
	}

	EnvVolume struct {
		Seed string `json:"seed" yaml:"seed"`
	}

	WorkloadVolume struct {
		Seed       string  `json:"seed" yaml:"seed"`
		Filesystem *string `json:"filesystem,omitempty" yaml:"filesystem,omitempty"`
		Mount      *string `json:"mount,omitempty" yaml:"mount,omitempty"`
	}

	WorkloadVolumes = map[string]WorkloadVolume
	EnvVolumes      = map[string]EnvVolume

	Credential struct {
		Username string `json:"username" yaml:"username"`
		Password string `json:"password" yaml:"password"`
	}
	Auths = map[string]Credential

	Compose struct {
		Archive string `json:"archive" yaml:"archive"`
	}

	Play struct {
		Archive string `json:"archive" yaml:"archive"`
	}

	DockerContentTrust struct {
		Notary    string `json:"notary" yaml:"notary"`
		PublicKey string `json:"publicKey" yaml:"publicKey"`
	}

	RedHatSigning struct {
		PublicKey string `json:"publicKey" yaml:"publicKey"`
	}

	DockerContentTrusts = map[string]*DockerContentTrust
	RedHatSignings      = map[string]*RedHatSigning

	Images struct {
		DockerContentTrust DockerContentTrusts `json:"dct,omitempty" yaml:"dct,omitempty"`
		RedHatSigning      RedHatSignings      `json:"rhs,omitempty" yaml:"rhs,omitempty"`
	}

	Workload struct {
		Type                   string          `json:"type" yaml:"type"`
		Volumes                WorkloadVolumes `json:"volumes,omitempty" yaml:"volumes,omitempty"`
		Auths                  Auths           `json:"auths,omitempty" yaml:"auths,omitempty"`
		Images                 *Images         `json:"images,omitempty" yaml:"images,omitempty"`
		Env                    ENV.Env         `json:"env,omitempty" yaml:"env,omitempty"`
		Compose                *Compose        `json:"compose,omitempty" yaml:"compose,omitempty"`
		Play                   *Play           `json:"play,omitempty" yaml:"play,omitempty"`
		ConfidentialContainers any             `json:"confidential-containers,omitempty" yaml:"confidential-containers,omitempty"`
	}

	Env struct {
		Type                   string     `json:"type" yaml:"type"`
		Logging                *Logging   `json:"logging,omitempty" yaml:"logging,omitempty"`
		Volumes                EnvVolumes `json:"volumes,omitempty" yaml:"volumes,omitempty"`
		Env                    ENV.Env    `json:"env,omitempty" yaml:"env,omitempty"`
		SigningKey             *string    `json:"signingKey,omitempty" yaml:"signingKey,omitempty"`
		ConfidentialContainers any        `json:"confidential-containers,omitempty" yaml:"confidential-containers,omitempty"`
	}

	Contract struct {
		Workload             *Workload `json:"workload,omitempty" yaml:"workload,omitempty"`
		Env                  *Env      `json:"env,omitempty" yaml:"env,omitempty"`
		AttestationPublicKey *string   `json:"attestationPublicKey,omitempty" yaml:"attestationPublicKey,omitempty"`
		EnvWorkloadSignature *string   `json:"envWorkloadSignature,omitempty" yaml:"envWorkloadSignature,omitempty"`
	}
)
