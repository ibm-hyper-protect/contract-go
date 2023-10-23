package utils

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
