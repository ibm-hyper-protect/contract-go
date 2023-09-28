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
	"os"
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/stretchr/testify/assert"

	ENV "github.com/ibm-hyper-protect/contract-go/environment"
)

var (
	getwd = IOE.TryCatchError(os.Getwd)
)

func TestReadDotEnv(t *testing.T) {
	// read from current directory
	res := F.Pipe1(
		getwd,
		IOE.Chain(EnvFromDotEnv),
	)
	// validate the environment
	assert.Equal(t, E.Of[error](ENV.Env{"a": "a1", "b": "b1"}), res())
}
