package optional

import (
	OPT "github.com/IBM/fp-go/optics/optional"
	T "github.com/ibm-hyper-protect/contract-go/tar"
)

// Bytes returns an optional that manipulates a file as bytes
func Bytes(path string) OPT.Optional[T.FileList, []byte] {
	get := T.LookupBytes(path)
	set := T.UpsertBytes(path)
	return OPT.MakeOptional(
		get,
		func(files T.FileList, data []byte) T.FileList {
			return set(data)(files)
		},
	)
}

// String returns an optional that manipulates a file as string
func String(path string) OPT.Optional[T.FileList, string] {
	get := T.LookupString(path)
	set := T.UpsertString(path)
	return OPT.MakeOptional(
		get,
		func(files T.FileList, data string) T.FileList {
			return set(data)(files)
		},
	)
}
