package Option

import (
	"os"

	O "github.com/IBM/fp-go/option"
)

var (
	// LookupEnv performs a lookup of a variable in the environment
	LookupEnv = O.Optionize1(os.LookupEnv)
)
