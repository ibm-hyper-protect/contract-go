package types

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	I "github.com/IBM/fp-go/optics/iso"
	L "github.com/IBM/fp-go/optics/lens"
	LI "github.com/IBM/fp-go/optics/lens/iso"
	O "github.com/IBM/fp-go/option"
	"github.com/qri-io/jsonschema"
)

func isoFromSchema[A any](schema *jsonschema.Schema) I.Iso[O.Option[any], O.Option[A]] {

	// decode the value
	decode := F.Flow2(
		ValidateAndDecode[A](schema),
		E.Fold(F.Ignore1of1[error](O.None[A]), O.Of[A]),
	)

	return I.MakeIso(O.Fold(O.None[A], func(a any) O.Option[A] {
		return F.Pipe2(
			a,
			O.ToType[A],
			O.Alt(F.Bind1of1(decode)(a)),
		)
	}), O.Fold(O.None[any], O.ToAny[A]))
}

// FromPredicate creates an option to focus on a property type any. The data will be validated against a json schema and
// converted into the desired type
func FromPredicate[S, A any](schema *jsonschema.Schema) func(sa L.Lens[S, O.Option[any]]) L.Lens[S, O.Option[A]] {
	return LI.Compose[S](isoFromSchema[A](schema))
}
