package tar

import (
	T "github.com/IBM/fp-go/tuple"
)

type (
	// FileList represents a mapping from filepath to the byte value of a file
	FileList = map[string][]byte
	// one entry in the file list
	FileEntry = T.Tuple2[string, []byte]
)
