package ioeither

import (
	"io"
	"os"
	"path/filepath"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	O "github.com/IBM/fp-go/option"
	CF "github.com/ibm-hyper-protect/contract-go/file"
	T "github.com/ibm-hyper-protect/contract-go/tar"
	C "github.com/ibm-hyper-protect/contract-go/tar/either"
)

var (
	onGetStdIn  = IOE.Of[error](os.Stdin)
	onGetStdOut = IOE.Of[error](os.Stdout)
	mkdirAll    = func(dstFolder string, perm os.FileMode) IOE.IOEither[error, string] {
		return IOE.TryCatchError(func() (string, error) {
			return dstFolder, os.MkdirAll(dstFolder, perm)
		})
	}

	// UnmarshalFromStdIn loads a tar file from stdin
	UnmarshalFromStdIn = Unmarshal(onGetStdIn)

	// UnmarshalFromInput loads a tar file into a file list from either a file or stdin (using "-" as the stdin identifier)
	UnmarshalFromInput = F.Flow2(
		CF.IsNotStdinNorStdout,
		O.Fold(F.Constant(UnmarshalFromStdIn), UnmarshalFromFile),
	)

	// UnmarshalFromFile loads a tar file into a file list
	UnmarshalFromFile = F.Flow2(
		IOEF.Open,
		Unmarshal[*os.File],
	)

	// MarshalToStdOut stores a a tar file to stdout
	MarshalToStdOut = Marshal(onGetStdOut)

	// MarshalToFile stores a file list to a file in tar format
	MarshalToFile = F.Flow2(
		IOEF.Create,
		Marshal[*os.File],
	)

	// MarshalToInput stores a file list either to a tar file or stdout (using "-" as the stdout identifier)
	MarshalToOutput = F.Flow2(
		CF.IsNotStdinNorStdout,
		O.Fold(F.Constant(MarshalToStdOut), MarshalToFile),
	)
)

// Unmarshal parses the content of a reader of a tar file into an in-memory copy
func Unmarshal[R io.ReadCloser](acquire IOE.IOEither[error, R]) IOE.IOEither[error, T.FileList] {
	return F.Pipe2(
		acquire,
		IOEF.ReadAll[R],
		IOE.ChainEitherK(C.Unmarshal),
	)
}

// Marshal serializes a [T.FileList] as a tar file onto a [io.WriteCloser]
func Marshal[W io.WriteCloser](acquire IOE.IOEither[error, W]) func(T.FileList) IOE.IOEither[error, []byte] {
	return F.Flow4(
		C.Marshal,
		E.Map[error](IOEF.WriteAll[W]),
		E.Flap[error, IOE.IOEither[error, []byte]](acquire),
		E.GetOrElse(IOE.Left[[]byte, error]),
	)
}

// extractFile extracts a file as a child of the parent folder and makes sure the folder structure exists
func extractFile(dstFolder string, perm os.FileMode) func(string, []byte) IOE.IOEither[error, []byte] {
	return func(name string, data []byte) IOE.IOEither[error, []byte] {
		// full path
		fullPath := filepath.Clean(filepath.Join(dstFolder, name))
		// create the parent directory
		return F.Pipe1(
			mkdirAll(filepath.Dir(fullPath), perm),
			IOE.Chain(F.Constant1[string](IOEF.WriteFile(fullPath, perm)(data))),
		)
	}
}

// ExtractToFolder extracts the file list to the file system in the given folder
func ExtractToFolder(dstFolder string, perm os.FileMode) func(T.FileList) IOE.IOEither[error, T.FileList] {
	return F.Pipe1(
		extractFile(dstFolder, perm),
		IOE.TraverseRecordWithIndex[string, error, []byte, []byte],
	)
}
