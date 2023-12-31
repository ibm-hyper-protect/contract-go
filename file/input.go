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

package file

import (
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	P "github.com/IBM/fp-go/predicate"
	S "github.com/IBM/fp-go/string"
)

const (
	// StdInOutIdentifier is the CLI identifier for stdin or stdout
	StdInOutIdentifier = "-"
)

var (
	// IsNotStdinNorStdout tests if a stream identifier does not match stdin or stdout
	IsNotStdinNorStdout = F.Pipe3(
		StdInOutIdentifier,
		S.Equals,
		P.Not[string],
		O.FromPredicate[string],
	)
)
