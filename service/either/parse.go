package either

import (
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	C "github.com/ibm-hyper-protect/contract-go/service/common"
	T "github.com/ibm-hyper-protect/contract-go/types"
	"gopkg.in/yaml.v3"
)

// ParseContract converts a []byte into a map
// trying to write this in functional style breaks the runtime
func ParseContract(data []byte) E.Either[error, T.AnyMap] {
	var strgMap T.StringMap
	err := yaml.Unmarshal(data, &strgMap)
	if err != nil {
		return E.Left[T.AnyMap](err)
	}
	// result
	resMap := make(T.AnyMap)
	for key, value := range strgMap {
		switch key {
		case C.KeyEnv:
		case C.KeyWorkload:
			var inner T.AnyMap
			err := yaml.Unmarshal([]byte(value), &inner)
			if err != nil {
				return E.Left[T.AnyMap](err)
			}
			resMap[key] = inner
		default:
			resMap[key] = value
		}
	}
	return E.Of[error](resMap)
}

// ParseAndValidateContract parses the contract into a validated
// strongly typed data structure
var ParseAndValidateContract = F.Flow2(
	ParseContract,
	E.Chain(T.ValidateContract),
)
