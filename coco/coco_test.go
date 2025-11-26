package coco

import (
	"testing"

	"github.com/ibm-hyper-protect/contract-go/common/general"
	"github.com/stretchr/testify/assert"
)

const (
	// Hpcc Test Case. 
	sampleSignedEncryptedContract = "../samples/signed-encrypt-hpcc.yaml"
)

// Testcase to check HpccGzippedInitdata() is able to gzip data. 
func TestHpccGzippedInitdata(t *testing.T) {
	if !general.CheckFileFolderExists(sampleSignedEncryptedContract) {
		t.Errorf("failed, file does not exits on defined path")
	}

	inputData, err := general.ReadDataFromFile(sampleSignedEncryptedContract)
	if err != nil {
		t.Errorf("failed to read content form encrypted contract - %v", err)
	}
	
	encodedString, err := HpccGzippedInitdata(inputData)
	if err != nil {
		t.Errorf("failed to gzipped encoded initdata - %v", err)
	}

	assert.NotEmpty(t, encodedString)
} 