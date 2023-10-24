package tar

import (
	"path/filepath"
	"strings"

	A "github.com/IBM/fp-go/array"
	B "github.com/IBM/fp-go/bytes"
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	RR "github.com/IBM/fp-go/record"
	SG "github.com/IBM/fp-go/semigroup"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
)

var (
	// the empty file list
	Empty = RR.Empty[string, []byte]()
	// LookupBytes accesses a file as bytes from a file list
	LookupBytes = F.Flow2(
		cleanPath,
		RR.Lookup[[]byte, string],
	)
	// the monoid used to merge FileList objects
	Monoid = RR.UnionMonoid[string](SG.Last[[]byte]())
)

func cleanPath(path string) string {
	return strings.Trim(filepath.ToSlash(filepath.Clean(path)), "/")
}

// UpsertBytes adds a file by path to a file list
func UpsertBytes(path string) func([]byte) func(FileList) FileList {
	return F.Bind1st(RR.UpsertAt[string, []byte], cleanPath(path))
}

// UpsertString adds a file by path to a file list
func UpsertString(path string) func(string) func(FileList) FileList {
	return F.Flow2(
		S.ToBytes,
		UpsertBytes(path),
	)
}

// LookupString accesses a file as string from a file list
func LookupString(path string) func(FileList) O.Option[string] {
	return F.Flow2(
		LookupBytes(path),
		O.Map(B.ToString),
	)
}

// FromEntries creates a file list from a set of entries
func FromEntries(entries []FileEntry) FileList {
	return RR.FromEntries(entries)
}

// CreateEntry constructs a file entry with byte content
func CreateEntry(path string) func([]byte) FileEntry {
	return F.Bind1st(T.MakeTuple2[string, []byte], cleanPath(path))
}

// Singleton returns a file list with one single entry
func Singleton(path string) func([]byte) FileList {
	return F.Flow3(
		CreateEntry(path),
		A.Of[FileEntry],
		FromEntries,
	)
}
