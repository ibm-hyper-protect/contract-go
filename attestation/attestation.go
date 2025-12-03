// Copyright (c) 2025 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestation

import (
	"fmt"

	attest "github.com/ibm-hyper-protect/contract-go/v2/common/decrypt"
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	missingParameterErrStatement = "required parameter is missing"
)

// HpcrGetAttestationRecords - function to get attestation records from encrypted data
func HpcrGetAttestationRecords(data, privateKey string) (string, error) {
	if gen.CheckIfEmpty(data, privateKey) {
		return "", fmt.Errorf(missingParameterErrStatement)
	}
	encodedEncryptedPassword, encodedEncryptedData := gen.GetEncryptPassWorkload(data)

	password, err := attest.DecryptPassword(encodedEncryptedPassword, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password - %v", err)
	}

	attestationRecords, err := attest.DecryptWorkload(password, encodedEncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt attestation records - %v", err)
	}

	return attestationRecords, nil
}
