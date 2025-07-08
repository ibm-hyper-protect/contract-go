package network_schema

import (
	_ "embed"
)

//go:embed hpse-network-config-schema.json
var NetworkConfigSchema string
