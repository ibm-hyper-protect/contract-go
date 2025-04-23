package schema

import (
	_ "embed"
)

//go:embed hpse-contract-schema.json
var ContractSchema string
