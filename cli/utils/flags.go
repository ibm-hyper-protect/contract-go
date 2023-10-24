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
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	S "github.com/IBM/fp-go/string"
	"github.com/urfave/cli/v2"
)

var (
	// fromNonEmptyString converts a non empty string to an [O.Option]
	fromNonEmptyString = O.FromPredicate(S.IsNonEmpty)
)

// LookupStringFlag returns a string flag from the [cli.Context] as a string
func LookupStringFlag(name string) func(ctx *cli.Context) string {
	return F.Bind2nd((*cli.Context).String, name)
}

// LookupStringFlagOpt returns a string flag from the [cli.Context] as an [O.Option[string]]
func LookupStringFlagOpt(name string) func(ctx *cli.Context) O.Option[string] {
	return func(ctx *cli.Context) O.Option[string] {
		return F.Pipe2(
			name,
			ctx.String,
			fromNonEmptyString,
		)
	}
}
