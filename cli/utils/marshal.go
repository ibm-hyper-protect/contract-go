package utils

import (
	"os"

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	O "github.com/IBM/fp-go/option"
)

// WriteToStdOut writes the data blob to stdout
func WriteToStdOut(data []byte) IOE.IOEither[error, []byte] {
	return IOEF.WriteAll[*os.File](data)(IOE.Of[error](os.Stdout))
}

// WriteToOutput stores a file list either to a regular file or stdout (using "-" as the stdout identifier)
var WriteToOutput = F.Flow2(
	IsNotStdinNorStdout,
	O.Fold(F.Constant(WriteToStdOut), F.Bind2nd(IOEF.WriteFile, os.ModePerm)),
)
