package either

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	T "github.com/ibm-hyper-protect/contract-go/tar"
	"github.com/stretchr/testify/assert"
)

func TestMarshalUnmarshal(t *testing.T) {
	// some test data
	src := T.FileList{
		"file1.txt": []byte("file1"),
		"file2.txt": []byte("file2"),
	}
	// serialize and deserialize
	res := F.Pipe2(
		src,
		Marshal,
		E.Chain(Unmarshal),
	)
	assert.Equal(t, E.Of[error](src), res)
}
