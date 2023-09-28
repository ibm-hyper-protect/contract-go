package ioOption

import (
	"os"

	IOO "github.com/IBM/fp-go/iooption"
)

var (
	// LookupEnv performs a lookup of a variable in the environment
	LookupEnv = IOO.Optionize1(os.LookupEnv)
)
