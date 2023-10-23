package utils

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/stretchr/testify/assert"
)

func TestWriteToFile(t *testing.T) {
	data := []byte("Carsten")
	res := F.Pipe2(
		"../../build/TestWriteToFile.txt",
		WriteToOutput,
		I.Ap[IOE.IOEither[error, []byte]](data),
	)
	assert.Equal(t, E.Of[error](data), res())
}
