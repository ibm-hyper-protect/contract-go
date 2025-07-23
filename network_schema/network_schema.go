package network_schema

import (
	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

func HpcrVerifyNetworkConfig(network_config string) error {
	return gen.VerifyNetworkSchema(network_config)
}
