package network_schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	validNetworkConfigFile = `
network:
  version: 2
  ethernets:
    enc1:
      dhcp4: false
      addresses:
        - 192.168.122.110/24 
      gateway4: 192.168.122.1
      nameservers:
        addresses:
          - 8.8.8.8
`

	invalidNetworkConfigFile = `
network:
  version: 2
  ethernets:
    enc:
      dhcp4: false
      addresses:
        - 192.168.122.110/24 
      gateway4: 192.168.122.1
      nameservers:
        addresses:
          - 8.8.8.8
`
)

func TestProcessNetworkSchemaValid(t *testing.T) {
	err := HpcrVerifyNetworkConfig(validNetworkConfigFile)
	assert.NoError(t, err)
}

func TestProcessNetworkSchemaInvalid(t *testing.T) {
	err := HpcrVerifyNetworkConfig(invalidNetworkConfigFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "additionalProperties 'enc' not allowed")
}
