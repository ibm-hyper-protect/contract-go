package utils

import (
	"os"

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	O "github.com/IBM/fp-go/option"
)

var (
	// ReadFromStdIn reads the data blob from stdin
	ReadFromStdIn = IOEF.ReadAll(IOE.Of[error](os.Stdin))

	// ReadFromInput reads a byte array either from a file or from stdin (using "-" as the stdout identifier)
	ReadFromInput = F.Flow2(
		IsNotStdinNorStdout,
		O.Fold(F.Constant(ReadFromStdIn), IOEF.ReadFile),
	)
)
