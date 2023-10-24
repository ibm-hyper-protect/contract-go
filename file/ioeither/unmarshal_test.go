package ioeither

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/identity"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/stretchr/testify/assert"
)

func TestReadFromFile(t *testing.T) {
	name := "../../build/TestReadFromFile.txt"
	data := []byte("Carsten")
	res := F.Pipe3(
		name,
		WriteToOutput,
		I.Ap[IOE.IOEither[error, []byte]](data),
		IOE.Chain(F.Constant1[[]byte](ReadFromInput(name))),
	)
	assert.Equal(t, E.Of[error](data), res())
}
