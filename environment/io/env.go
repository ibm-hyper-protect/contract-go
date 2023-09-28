package io

import (
	"os"
	"strings"

	A "github.com/IBM/fp-go/array"
	F "github.com/IBM/fp-go/function"
	IO "github.com/IBM/fp-go/io"
	O "github.com/IBM/fp-go/option"
	R "github.com/IBM/fp-go/record"
	T "github.com/IBM/fp-go/tuple"
)

var (
	environ      = IO.MakeIO(os.Environ)
	envFromLines = F.Flow3(
		A.Map(splitLine),
		O.CompactArray[T.Tuple2[string, string]],
		R.FromEntries[string, string],
	)
	// EnvFromOs creates an environment map from the actual environment
	EnvFromOs = F.Pipe1(
		environ,
		IO.Map(envFromLines),
	)
)

func splitLine(line string) O.Option[T.Tuple2[string, string]] {
	splits := strings.SplitN(line, "=", 2)
	if len(splits) != 2 {
		return O.None[T.Tuple2[string, string]]()
	}
	return O.Of(T.MakeTuple2(splits[0], splits[1]))
}
