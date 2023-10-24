// Copyright (c) 2023 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"fmt"
	"os"
	"testing"

	A "github.com/IBM/fp-go/array"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestEncryptCommand(t *testing.T) {

	require.NoError(t, os.MkdirAll("../../build", os.ModePerm))

	inName := "../samples/simple.yaml"
	outName := "../../build/TestEncryptCommand.yaml"

	cmd := EncryptAndSignCommand()

	app := &cli.App{
		Name:     "contract-cli",
		Commands: A.Of(cmd),
	}

	args := A.From(os.Args[0], cmd.Name, fmt.Sprintf("--%s", flagInput.Name), inName, fmt.Sprintf("--%s", flagOutput.Name), outName)
	assert.NoError(t, app.Run(args))

	// TODO validate output here
}
