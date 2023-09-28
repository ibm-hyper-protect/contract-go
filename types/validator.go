/*
 * =============================================================================================
 * IBM Confidential
 * © Copyright IBM Corp. 2022
 * The source code for this program is not published or otherwise divested of its trade secrets,
 * irrespective of what has been deposited with the U.S. Copyright Office.
 * =============================================================================================
 */

package types

import (
	"context"

	A "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	J "github.com/IBM/fp-go/json"
	O "github.com/IBM/fp-go/option"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	D "github.com/ibm-hyper-protect/contract-go/data"

	"github.com/qri-io/jsonschema"
)

// validate validates a type against a schema.
// note that we use the background context by design. The context is passed on
// because in principle the schema might contain external references that need to be
// resolved. But we know that this is not the case in our implementation
func validate[A any](schema *jsonschema.Schema) func(A) []jsonschema.KeyError {
	return func(data A) []jsonschema.KeyError {
		return *schema.Validate(context.Background(), data).Errs
	}
}

type (
	AnyMap    = map[string]any
	StringMap = map[string]string
)

// schemaE is the parsed schema
var schemaE = F.Pipe2(
	D.ContractSchema,
	S.ToBytes,
	J.Unmarshal[*jsonschema.Schema],
)

func handleValidationErrors[T any](contract T, errs []jsonschema.KeyError) E.Either[error, T] {
	return F.Pipe4(
		errs,
		A.Head[jsonschema.KeyError],
		O.Map(F.ToAny[jsonschema.KeyError]),
		O.Chain(O.ToType[error]),
		O.Fold(F.Nullary2(F.Constant(contract), E.Right[error, T]), E.Left[T, error]),
	)
}

// ValidateAndDecode validates a data structure against a schema and then decodes it
func ValidateAndDecode[T any](schema *jsonschema.Schema) func(data any) E.Either[error, T] {
	// capture the validation scope
	val := validate[any](schema)
	// parses and validates the data
	return func(data any) E.Either[error, T] {
		// parse the data
		return F.Pipe2(
			data,
			transcode[any, T],
			E.Chain(F.Bind2nd(handleValidationErrors[T], val(data))),
		)
	}
}

// ValidateContract validates the given contract against the contract schema
func ValidateContract(raw AnyMap) E.Either[error, *Contract] {

	// validate the raw map against the schema
	validatedE := F.Pipe2(
		schemaE,
		E.Map[error](validate[AnyMap]),
		E.Ap[[]jsonschema.KeyError](E.Of[error](raw)),
	)

	// parse the data
	parsedE := F.Pipe2(
		raw,
		J.Marshal[AnyMap],
		E.Chain(J.Unmarshal[*Contract]),
	)

	return F.Pipe1(
		E.SequenceT2(parsedE, validatedE),
		E.Chain(T.Tupled2(handleValidationErrors[*Contract])),
	)
}
