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

package utils

import (
	"os"

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEF "github.com/IBM/fp-go/ioeither/file"
	O "github.com/IBM/fp-go/option"
)

// WriteToStdOut writes the data blob to stdout
func WriteToStdOut(data []byte) IOE.IOEither[error, []byte] {
	return IOEF.WriteAll[*os.File](data)(IOE.Of[error](os.Stdout))
}

// WriteToOutput stores a file list either to a regular file or stdout (using "-" as the stdout identifier)
var WriteToOutput = F.Flow2(
	IsNotStdinNorStdout,
	O.Fold(F.Constant(WriteToStdOut), F.Bind2nd(IOEF.WriteFile, os.ModePerm)),
)
