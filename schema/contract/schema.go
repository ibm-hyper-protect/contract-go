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

package schema

import (
	_ "embed"
)

//go:embed hpse-contract-schema-1.0.116.json
var ContractSchemaCcrt string

//go:embed hpse-contract-schema-1.0.116-rhel.json
var ContractSchemaCcrv string

//go:embed hpse-contract-schema-coco-1.0.93-rhel.json
var ContractSchemaCcco string

// RetrievableSecretsSchemaCcrv adds prepared-request rules to the original CCRV
// platform schema. Validate against both schemas when using these assets directly.
//
//go:embed retrievable-secrets-ccrv.json
var RetrievableSecretsSchemaCcrv string
