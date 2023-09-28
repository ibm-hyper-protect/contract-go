package common

const (
	KeyWorkload             = "workload"
	KeyEnv                  = "env"
	KeyAttestationPublicKey = "attestationPublicKey"
	KeyEnvWorkloadSignature = "envWorkloadSignature"
)

type (
	EncryptedContract = map[string]string
)
