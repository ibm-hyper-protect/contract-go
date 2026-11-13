// Copyright (c) 2026 IBM Corp.
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

package general

import (
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestSectionValidationKeepsAllSchemaRules(t *testing.T) {
	workload := "type: workload\nplay:\n  archive: YWJjZA==\n"
	environment := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n    port: 443\n"
	for _, tc := range []struct{ name, section, input string }{
		{"missing logging", "env", "type: env\n"},
		{"logging type", "env", "type: env\nlogging: 42\n"},
		{"variable type", "env", environment + "env:\n  PORT: 8080\n"},
		{"short seed", "env", environment + "volumes:\n  data:\n    seed: short\n"},
		{"play type", "workload", "type: workload\nplay: 42\n"},
		{"compose type", "workload", "type: workload\ncompose: 42\n"},
		{"second document", "workload", workload + "---\n" + workload},
		{"duplicate key", "env", environment + "type: env\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyContractWithSchema(tc.input, ConfidentialComputingOsCcrt, tc.section); err == nil {
				t.Fatal("invalid raw section accepted")
			}
		})
	}
	if err := VerifyContractWithSchema(environment, ConfidentialComputingOsCcrt, "env"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContractWithSchema(workload, ConfidentialComputingOsCcrt, "workload"); err != nil {
		t.Fatal(err)
	}
	// Nested environment variables named env are not a complete-contract wrapper.
	if err := VerifyContractWithSchema(environment+"env:\n  env: value\n", ConfidentialComputingOsCcrt, "env"); err != nil {
		t.Fatal(err)
	}
}

func TestContractRejectsNonStringMappingKeys(t *testing.T) {
	environment := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n"
	workload := "type: workload\nplay:\n  archive: YWJjZA==\n"
	for _, contents := range []string{
		"env:\n  true: test\n",
		"env:\n  true: test\n  \"true\": 42\n",
		"env:\n  123: test\n  \"123\": other\n",
		"volumes:\n  123:\n    seed: EnvironmentSeed12345\n",
	} {
		t.Run(contents, func(t *testing.T) {
			input := environment + contents
			wrapped, err := yaml.Marshal(map[string]string{"env": input, "workload": workload})
			if err != nil {
				t.Fatal(err)
			}
			for section, source := range map[string]string{"env": input, "": string(wrapped)} {
				for i := 0; i < 20; i++ {
					if err := VerifyContractWithSchema(source, ConfidentialComputingOsCcrv, section); err == nil {
						t.Fatalf("section %q accepted non-string/colliding keys", section)
					}
				}
			}
		})
	}
}

func TestContractMappingAliases(t *testing.T) {
	environment := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n"
	workload := "type: workload\nplay:\n  archive: YWJjZA==\n"
	for _, tc := range []struct {
		name, contents string
		valid          bool
	}{
		{"quoted boolean name", "env:\n  \"true\": test\n", true},
		{"scalar alias key", "env:\n  FIRST: &variable_name SECOND\n  *variable_name: test\n", true},
		{"alias label matches another key", "env:\n  FIRST: &FIRST SECOND\n  *FIRST: test\n", true},
		{"merge with explicit override", "env:\n  <<: &defaults\n    FIRST: original\n  FIRST: replacement\n", true},
		{"alias hides invalid duplicate", "env:\n  FIRST: &variable_name SECOND\n  SECOND: 42\n  *variable_name: test\n", false},
		{"non-string alias key", "env:\n  FIRST: &boolean true\n  *boolean: test\n", false},
		{"complex key", "env:\n  ? [FIRST, SECOND]\n  : test\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := environment + tc.contents
			wrapped, err := yaml.Marshal(map[string]string{"env": input, "workload": workload})
			if err != nil {
				t.Fatal(err)
			}
			for section, source := range map[string]string{"env": input, "": string(wrapped)} {
				if err := VerifyContractWithSchema(source, ConfidentialComputingOsCcrv, section); (err == nil) != tc.valid {
					t.Fatalf("section %q: valid=%t, error=%v", section, tc.valid, err)
				}
			}
		})
	}
}

func TestNestedPodmanResourceValidation(t *testing.T) {
	environment := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-key\n"
	resources := `  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: secret-reference
    data:
      reference.yaml: |
        id: nonsecret-reference
  - apiVersion: v1
    kind: Pod
    metadata:
      name: test-workload
    spec:
      containers:
        - name: app
          image: example.invalid/test:1
          env:
            - name: VALUE
              value: test
`
	for _, platform := range []string{ConfidentialComputingOsCcrt, ConfidentialComputingOsCcrv} {
		for _, field := range []string{"resources", "templates"} {
			for _, tc := range []struct {
				name, contents string
				valid          bool
			}{
				{"pod and configmap", resources, true},
				{"wrong image type", strings.ReplaceAll(resources, "image: example.invalid/test:1", "image: 123"), false},
				{"wrong variable type", strings.ReplaceAll(resources, "value: test", "value: [test]"), false},
				{"wrong reference type", strings.ReplaceAll(resources, "reference.yaml: |\n        id: nonsecret-reference", "reference.yaml: 123"), false},
				{"unsupported resource", strings.ReplaceAll(resources, "kind: Pod", "kind: Deployment"), false},
			} {
				t.Run(platform+"/"+field+"/"+tc.name, func(t *testing.T) {
					workload := "type: workload\nplay:\n  " + field + ":\n" + tc.contents
					wrapped, err := yaml.Marshal(map[string]string{"env": environment, "workload": workload})
					if err != nil {
						t.Fatal(err)
					}
					for section, input := range map[string]string{"workload": workload, "": string(wrapped)} {
						err := VerifyContractWithSchema(input, platform, section)
						if (err == nil) != tc.valid {
							t.Fatalf("section %q: valid=%t, error=%v", section, tc.valid, err)
						}
					}
				})
			}
		}
	}
}
