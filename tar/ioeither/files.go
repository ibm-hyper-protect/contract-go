package ioeither

import (
	"io/fs"
	"os"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	T "github.com/ibm-hyper-protect/contract-go/tar"
)

// WalkFolder walks the files in the file system
func WalkFolder[T any](read func(string) T) func(fs.FS) IOE.IOEither[error, map[string]T] {
	return func(fileSystem fs.FS) IOE.IOEither[error, map[string]T] {
		// just walk the files
		return IOE.MakeIO(func() E.Either[error, map[string]T] {
			// prepare the files for reading
			res := make(map[string]T)
			// iterate over all files
			err := fs.WalkDir(fileSystem, ".", func(path string, d os.DirEntry, err error) error {
				if d.Type().IsRegular() {
					// read the full file
					res[path] = read(path)
				}
				return nil
			})
			if err != nil {
				return E.Left[map[string]T](err)
			}
			// returns the result
			return E.Of[error](res)
		})
	}
}

// FromFolder reads the content of the given filder into a file list
func FromFolder(folder string) IOE.IOEither[error, T.FileList] {
	// prep the filesystem
	fileSystem := os.DirFS(folder)
	// compose
	return F.Pipe2(
		fileSystem,
		WalkFolder(F.Flow2(IOE.Eitherize1(fileSystem.Open), IOEF.ReadAll[fs.File])),
		IOE.Chain(IOE.SequenceRecord[string, error, []byte]),
	)
}
