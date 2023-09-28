package ioeither

import (
	"path/filepath"

	"github.com/joho/godotenv"

	ENV "github.com/ibm-hyper-protect/contract-go/environment"

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
)

func readEnv(filename string) IOE.IOEither[error, ENV.Env] {
	return IOE.TryCatchError(func() (ENV.Env, error) {
		return godotenv.Read(filename)
	})
}

func joinEnv(root string) string {
	return filepath.Join(root, ".env")
}

// EnvFromDotEnv parses a ".env" file in the given directory into an environment map
var EnvFromDotEnv = F.Flow3(
	joinEnv,
	filepath.Clean,
	readEnv,
)
