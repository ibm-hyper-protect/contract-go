package coco

import (
	"os"
	"fmt"

	"text/template"

	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)
const (
	emptyParameterErrStatement = "required parameter is empty"
)

const tomlTemplate = `
algorithm = "sha384"
version = "0.1.0"

[data]
"contract.yaml" = '''{{ .Encrypted_contract }}'''
`
// HpccGzippedInitdata - Function to generate gzipped initdata value. 
func HpccGzippedInitdata(contract string) (string , error) {

	if gen.CheckIfEmpty(contract) {
		return "", fmt.Errorf(emptyParameterErrStatement)
	}

	tomlFile, err := generateTomlFile(contract)
	if err != nil {
		return "", err
	}

	_, err = os.Stat(tomlFile)
	if err != nil {
		return "", fmt.Errorf("Failed to check the toml file")
	}

	if os.IsNotExist(err){
		return "", fmt.Errorf("Toml file is not created")
	}

	// Read data from toml file.
	tomlString , err := gen.ReadDataFromFile(tomlFile)
	if err != nil {
		return "", fmt.Errorf("Failed Reading initdata toml file %v", err)
	}

	compressedBytes, err := gen.GzipInitData(tomlString)
	if err != nil {
		return "", fmt.Errorf("Failed while gzip initdata %v", err)
	}
	encodedString := gen.EncodeToBase64(compressedBytes)

	err = gen.RemoveTempFile(tomlFile)
	if err != nil {
		return "", fmt.Errorf("failed to remove file - %v", err)
	}

	return encodedString , nil
}

// generateTomlFile - Function to generate initdata.toml file.
func generateTomlFile(contract string) (string, error) {

	data := struct {
        Encrypted_contract string
    }{
        Encrypted_contract: contract,
    }

	tmpl, err := template.New("config").Parse(tomlTemplate)
    if err != nil {
       return "", err
    }

	tempTomlFile := "/tmp/initdata.toml"

	file , err := os.Create(tempTomlFile)
	if err != nil {
		return "", err
	}

	defer file.Close()

	tmpl.Execute(file, data)

	return tempTomlFile , nil
}