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

package Archive

import (
	"bytes"
	"encoding/base64"
	"io"

	E "github.com/IBM/fp-go/either"
)

type Base64Writer struct {
	body   *bytes.Buffer
	base64 io.WriteCloser
}

func (wrt *Base64Writer) Write(p []byte) (n int, err error) {
	return wrt.base64.Write(p)
}

func (wrt *Base64Writer) Close() E.Either[error, *bytes.Buffer] {
	return E.TryCatchError(func() (*bytes.Buffer, error) {
		return wrt.body, wrt.base64.Close()
	})
}

// CreateBase64Writer creates a writer that encodes its input as base64 into a buffer
func CreateBase64Writer() *Base64Writer {
	body := &bytes.Buffer{}
	return &Base64Writer{body, base64.NewEncoder(base64.StdEncoding, body)}
}
