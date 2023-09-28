package types

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	J "github.com/IBM/fp-go/json"
)

func transcode[A, B any](a A) E.Either[error, B] {
	return F.Pipe1(
		J.Marshal(a),
		E.Chain(J.Unmarshal[B]),
	)
}
