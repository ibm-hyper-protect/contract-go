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

func Reflow2[T0, T1, R any](f func(T1) R) func(func(T0) T1) func(T0) R {
	return F.Pipe1(
		f,
		F.Flip(F.Curry2(F.Flow2[func(T0) T1, func(T1) R])),
	)
}

func Reflow[T0, T1, R any](f func(T1) R) func(func(T0) T1) func(T0) R {
	return F.Pipe1(
		f,
		F.Flip(F.Curry2(F.Flow2[func(T0) T1, func(T1) R])),
	)
}

func Reflow1[T0, T1, R any](f1 func(T1) R) func(func(T0) T1) func(T0) R {
	return func(f0 func(T0) T1) func(T0) R {
		return F.Flow2(
			f0,
			f1,
		)
	}
}

var (
	// fromNonEmptyString converts a non empty string to an [O.Option]
	fromNonEmptyString = O.FromPredicate(S.IsNonEmpty)

	getGetString = func(ctx *cli.Context) func(string) string {
		return ctx.String
	}

	// LookupStringFlagOpt returns a string flag from the [cli.Context] as an [O.Option[string]]
	LookupStringFlagOpt = F.Flip(F.Flow2(
		getGetString,
		Reflow1[string](fromNonEmptyString),
	))
)

// LookupStringFlag returns a string flag from the [cli.Context] as a string
func LookupStringFlag(name string) func(ctx *cli.Context) string {
	return F.Bind2nd((*cli.Context).String, name)
}

// LookupStringSliceFlag returns a string flag from the [cli.Context] as a []string
func LookupStringSliceFlag(name string) func(ctx *cli.Context) []string {
	return F.Bind2nd((*cli.Context).StringSlice, name)
}
