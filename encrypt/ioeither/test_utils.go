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
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IO "github.com/IBM/fp-go/io"
	GIO "github.com/IBM/fp-go/io/generic"
	IOE "github.com/IBM/fp-go/ioeither"
	IOO "github.com/IBM/fp-go/iooption"
	O "github.com/IBM/fp-go/option"
	"github.com/stretchr/testify/assert"
)

func SignatureTest(
	privateKey IOE.IOEither[error, []byte],
	pubKey func([]byte) E.Either[error, []byte],
	randomData IOE.IOEither[error, []byte],
	signer func([]byte) func([]byte) IOE.IOEither[error, []byte],
	validator func([]byte) func([]byte) func([]byte) IOO.IOOption[error],
) func(t *testing.T) {
	return func(t *testing.T) {
		// generate a random key
		privKeyE := privateKey()
		privKeyIOE := IOE.FromEither(privKeyE)
		// generate some random data
		dataE := randomData()
		dataIOE := IOE.FromEither(dataE)
		// construct the signature
		signIOE := F.Pipe1(
			privKeyIOE,
			IOE.Map[error](signer),
		)
		// signature
		resE := F.Pipe2(
			signIOE,
			IOE.Ap[IOE.IOEither[error, []byte]](dataIOE),
			IOE.Flatten[error, []byte],
		)
		// validate the signature
		validO := F.Pipe7(
			privKeyE,
			E.Chain(pubKey),
			IOE.FromEither[error, []byte],
			IOE.Map[error](validator),
			IOE.Ap[func([]byte) IOO.IOOption[error]](dataIOE),
			IOE.Ap[IOO.IOOption[error]](resE),
			IOE.GetOrElse(F.Flow2(
				IOO.Of[error],
				IO.Of[IOO.IOOption[error]],
			)),
			GIO.Flatten[IOO.IOOption[error], IO.IO[IOO.IOOption[error]], O.Option[error]],
		)
		// handle the option
		assert.Equal(t, O.None[error](), validO())
	}
}
