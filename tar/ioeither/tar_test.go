package ioeither

import (
	"os"
	"testing"

	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	R "github.com/IBM/fp-go/record"
	"github.com/IBM/fp-go/tuple"
	T "github.com/ibm-hyper-protect/contract-go/tar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	res := F.Pipe2(
		"../../samples/tar/sample1.tar",
		UnmarshalFromFile,
		IOE.ChainOptionK[T.FileList, []byte](errors.OnNone("file is missing"))(R.Lookup[[]byte]("var/hyperprotect/cidata.decrypted.yml")),
	)

	assert.True(t, E.IsRight(res()))
}

func TestMarshalToFile(t *testing.T) {
	require.NoError(t, os.MkdirAll("../../build", os.ModePerm))

	src := "../../samples/tar/sample1.tar"
	dst := "../../build/TestMarshalToFile.tar"

	fromFile := F.Pipe1(
		src,
		UnmarshalFromFile,
	)

	writeFile := F.Pipe2(
		fromFile,
		IOE.Chain(MarshalToFile(dst)),
		IOE.Chain(F.Constant1[[]byte](F.Pipe1(
			dst,
			UnmarshalFromFile,
		))),
	)

	res := F.Pipe1(
		IOE.SequenceT2(fromFile, writeFile),
		IOE.Map[error](tuple.Tupled2(func(exp, real T.FileList) bool {
			return assert.Equal(t, exp, real)
		})),
	)

	assert.Equal(t, E.Of[error](true), res())
}

func TestExtractToFolder(t *testing.T) {
	// target directory
	dstDir := "../../build/TestExtractToFolder"
	src := "../../samples/tar/sample1.tar"

	res := F.Pipe2(
		src,
		UnmarshalFromFile,
		IOE.Chain(ExtractToFolder(dstDir, os.ModePerm)),
	)

	assert.True(t, E.IsRight(res()))

}
