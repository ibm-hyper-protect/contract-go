// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ioeither

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	T "github.com/IBM/fp-go/tuple"
	Archive "github.com/ibm-hyper-protect/contract-go/archive"
)

var (
	fileInfoHeaderE    = E.Eitherize2(tar.FileInfoHeader)
	relE               = F.Curry2(E.Eitherize2(filepath.Rel))
	copyIOE            = F.Curry2(IOE.Eitherize2(io.Copy))
	skipDirIOE         = IOE.Of[error, int64](-1)
	CreateBase64Writer = IOE.FromIO[error](Archive.CreateBase64Writer)
	onOpenFile         = F.Flow2(filepath.Clean, IOEF.Open)
)

func toReader[A io.Reader](a A) io.Reader {
	return a
}

// constructs a function that copies the content of a file into the writer
func copyFile(w io.Writer) func(string, os.FileInfo) IOE.IOEither[error, int64] {

	copyTo := copyIOE(w)

	return func(file string, fi os.FileInfo) IOE.IOEither[error, int64] {
		// do not copy for directories
		if fi.IsDir() {
			return skipDirIOE
		}
		// copy the file content
		return F.Pipe1(
			F.Flow2(
				toReader[*os.File],
				copyTo,
			),
			IOE.WithResource[int64](onOpenFile(file), IOEF.Close[*os.File]),
		)
	}
}

func writeHeader(src string) func(*tar.Writer) func(file string, fi os.FileInfo) IOE.IOEither[error, *tar.Writer] {
	// callback to get the relative path
	rel := relE(src)

	fixHeader := func(file string) func(*tar.Header) IOE.IOEither[error, *tar.Header] {
		return func(hdr *tar.Header) IOE.IOEither[error, *tar.Header] {
			return F.Pipe4(
				file,
				rel,
				E.Map[error](filepath.ToSlash),
				IOE.FromEither[error, string],
				IOE.Map[error](func(relName string) *tar.Header {
					hdr.Name = relName
					return hdr
				}),
			)
		}
	}

	return func(w *tar.Writer) func(file string, fi os.FileInfo) IOE.IOEither[error, *tar.Writer] {

		// callback to write the header
		writeHeader := func(hdr *tar.Header) IOE.IOEither[error, *tar.Writer] {
			return IOE.TryCatchError(func() (*tar.Writer, error) {
				return w, w.WriteHeader(hdr)
			})
		}

		return func(file string, fi os.FileInfo) IOE.IOEither[error, *tar.Writer] {
			return F.Pipe3(
				fileInfoHeaderE(fi, file),
				IOE.FromEither[error, *tar.Header],
				IOE.Chain(fixHeader(file)),
				IOE.Chain(writeHeader),
			)
		}
	}
}

func gzipStream[W io.Writer](streams T.Tuple3[*gzip.Writer, *tar.Writer, W]) *gzip.Writer {
	return streams.F1
}

func tarStream[W io.Writer](streams T.Tuple3[*gzip.Writer, *tar.Writer, W]) *tar.Writer {
	return streams.F2
}

func origStream[W io.Writer](streams T.Tuple3[*gzip.Writer, *tar.Writer, W]) W {
	return streams.F3
}

func onCreateStreams[W io.Writer](buf IOE.IOEither[error, W]) IOE.IOEither[error, T.Tuple3[*gzip.Writer, *tar.Writer, W]] {
	return F.Pipe1(
		buf,
		IOE.Map[error](func(buf W) T.Tuple3[*gzip.Writer, *tar.Writer, W] {
			gz := gzip.NewWriter(buf)
			return T.MakeTuple3(gz, tar.NewWriter(gz), buf)
		}),
	)
}

func onCloseStreams[W io.Writer](streams T.Tuple3[*gzip.Writer, *tar.Writer, W]) IOE.IOEither[error, any] {
	tar := F.Pipe2(
		streams,
		tarStream[W],
		IOEF.Close[*tar.Writer],
	)
	gz := F.Pipe2(
		streams,
		gzipStream[W],
		IOEF.Close[*gzip.Writer],
	)
	return F.Pipe1(
		tar,
		IOE.Chain(F.Constant1[any](gz)),
	)
}

func TarFolder[W io.Writer](src string) func(IOE.IOEither[error, W]) IOE.IOEither[error, W] {

	writeRel := writeHeader(src)
	walk := F.Bind1st(filepath.Walk, src)

	return func(buf IOE.IOEither[error, W]) IOE.IOEither[error, W] {

		return F.Pipe1(
			func(streams T.Tuple3[*gzip.Writer, *tar.Writer, W]) IOE.IOEither[error, W] {
				// prepare some context
				tw := tarStream(streams)
				copy := copyFile(tw)
				header := writeRel(tw)

				walkFunc := func(file string, fi os.FileInfo, e error) error {
					// header
					return E.ToError(F.Pipe1(
						header(file, fi),
						IOE.Chain(func(_ *tar.Writer) IOE.IOEither[error, int64] {
							return copy(file, fi)
						}),
					)())
				}

				return IOE.TryCatchError(func() (W, error) {
					// walk through every file in the folder
					return origStream(streams), walk(walkFunc)

				})
			},
			IOE.WithResource[W](
				onCreateStreams(buf),
				onCloseStreams[W],
			),
		)
	}
}
