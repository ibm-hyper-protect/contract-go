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

	A "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	EX "github.com/IBM/fp-go/ioeither/exec"
	"github.com/stretchr/testify/assert"
)

func TestCommandOk(t *testing.T) {

	cmdIOE := EX.Command("openssl")(A.From("help"))(make([]byte, 0))

	assert.True(t, E.IsRight(cmdIOE()))
}

func TestCommandFail(t *testing.T) {

	cmdIOE := EX.Command("openssl")(A.From("help1"))(make([]byte, 0))

	assert.True(t, E.IsLeft(cmdIOE()))
}
