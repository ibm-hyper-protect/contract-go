package either

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"time"

	E "github.com/IBM/fp-go/either"
	T "github.com/ibm-hyper-protect/contract-go/tar"
)

// Unmarshal converts a TAR file into an untarred file list
func Unmarshal(data []byte) E.Either[error, T.FileList] {
	var total int64
	res := make(T.FileList)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return E.Left[T.FileList](err)
		}
		if hdr.Typeflag == tar.TypeReg {
			// TODO validate total sizes and apply limits
			total = total + hdr.Size
			// read the content
			data, err := io.ReadAll(tr)
			if err != nil {
				return E.Left[T.FileList](err)
			}
			// record this
			res[filepath.ToSlash(filepath.Clean(hdr.Name))] = data
		}
	}
	return E.Of[error](res)
}

// Marshal converts a [T.FileList] into a TAR buffer
func Marshal(files T.FileList) E.Either[error, []byte] {
	current := time.Now()
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for name, data := range files {

		header := &tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			ModTime:  current,
			Mode:     0444,
		}

		err := tw.WriteHeader(header)
		if err != nil {
			return E.Left[[]byte](err)
		}

		_, err = tw.Write(data)
		if err != nil {
			return E.Left[[]byte](err)
		}
	}
	// close
	err := tw.Close()
	if err != nil {
		return E.Left[[]byte](err)
	}
	// returns the file list
	return E.Of[error](buffer.Bytes())
}
