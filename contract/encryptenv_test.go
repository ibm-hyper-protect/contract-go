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

package contract

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

// ─── fixtures ────────────────────────────────────────────────────────────────

const (
	// fixture paths relative to this file's package root
	encryptEnvBaseEnvPath     = "../samples/ccco/encrypt-env/base-env.yaml"
	encryptEnvBaseEnvVolPath  = "../samples/ccco/encrypt-env/base-env-with-volumes.yaml"
	encryptEnvMissingTypePath = "../samples/ccco/encrypt-env/base-env-missing-type.yaml"
	encryptEnvHKD38Path       = "../samples/ccco/encrypt-env/HKD-AlphaNode-Primary.cert"
	encryptEnvHKD39Path       = "../samples/ccco/encrypt-env/HKD-BetaNode-Secondary.cert"

	// Reuse the sample public key from existing encrypt samples.
	encryptEnvSigningKeyPath = "../samples/encrypt/public.pem"

	// ccco is the platform used in all encrypt-env tests.
	cccoOs = "ccco"

	// The expected output prefix for hyper-protect-basic encrypted strings.
	cccoEncryptPrefix = "hyper-protect-basic."
)

// minimalValidEnvYAML is an inline env YAML accepted by the CCCO schema.
// It carries only the mandatory `logging.logRouter` block so tests that exercise
// pure injection logic can work without touching the filesystem.
const minimalValidEnvYAML = `type: env
logging:
  logRouter:
    hostname: 5c2d6b69-c7f0-41bd-b69b-240695369d6e.ingress.us-south.logs.cloud.ibm.com
    iamApiKey: ab00e3c09p1d4ff7fff9f04c12183413
`

// ─── helpers ─────────────────────────────────────────────────────────────────

// unmarshalYAMLMap is a test-only helper that parses a YAML string into a
// map[string]interface{} and fails the test on error.
func unmarshalYAMLMap(t *testing.T, yamlStr string) map[string]interface{} {
	t.Helper()
	m := make(map[string]interface{})
	require.NoError(t, yaml.Unmarshal([]byte(yamlStr), &m), "failed to unmarshal test YAML")
	return m
}

// readFixture reads a test fixture file and fails the test if it cannot be read.
func readFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := gen.ReadDataFromFile(path)
	require.NoError(t, err, "failed to read fixture %s", path)
	return data
}

// ─── buildHKDEntries ─────────────────────────────────────────────────────

// TestBuildHKDEntries_success verifies that a valid list of HKD paths
// produces the correct Stem values and non-empty Content.
func TestBuildHKDEntries_success(t *testing.T) {
	paths := []string{encryptEnvHKD38Path, encryptEnvHKD39Path}
	entries, err := buildHKDEntries(paths)

	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "HKD-AlphaNode-Primary", entries[0].Stem)
	assert.NotEmpty(t, entries[0].Content)

	assert.Equal(t, "HKD-BetaNode-Secondary", entries[1].Stem)
	assert.NotEmpty(t, entries[1].Content)
}

// TestBuildHKDEntries_tooMany verifies that providing more than 10 paths is rejected.
func TestBuildHKDEntries_tooMany(t *testing.T) {
	paths := make([]string, maxHKDCount+1)
	for i := range paths {
		paths[i] = encryptEnvHKD38Path
	}

	_, err := buildHKDEntries(paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many")
}

// TestBuildHKDEntries_missingFile verifies that a non-existent path produces an error.
func TestBuildHKDEntries_missingFile(t *testing.T) {
	_, err := buildHKDEntries([]string{"/does/not/exist.cert"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read HKD file")
}

// TestBuildHKDEntries_stemExtraction verifies stem derivation for various filename patterns.
func TestBuildHKDEntries_stemExtraction(t *testing.T) {
	// both paths point to the same file; only the stem derivation is tested here
	tests := []struct {
		name         string
		path         string
		expectedStem string
	}{
		{"with .cert suffix", encryptEnvHKD38Path, "HKD-AlphaNode-Primary"},
		{"second hkd", encryptEnvHKD39Path, "HKD-BetaNode-Secondary"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := buildHKDEntries([]string{tc.path})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedStem, entries[0].Stem)
		})
	}
}

// ─── validateEncryptEnvInput ─────────────────────────────────────────────────

// TestValidateEncryptEnvInput_emptyEnvYAML verifies that an empty EnvYAML is rejected.
func TestValidateEncryptEnvInput_emptyEnvYAML(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{EnvYAML: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EnvYAML must not be empty")
}

// TestValidateEncryptEnvInput_tooManyHKDs verifies that > 10 HKD entries are rejected.
func TestValidateEncryptEnvInput_tooManyHKDs(t *testing.T) {
	hkds := make([]HKDEntry, maxHKDCount+1)
	for i := range hkds {
		hkds[i] = HKDEntry{Stem: "HKD-A", Content: []byte("data")}
	}
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		HKDs:    hkds,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many HKD entries")
}

// TestValidateEncryptEnvInput_hkdEmptyStem verifies that a HKD with a blank Stem is rejected.
func TestValidateEncryptEnvInput_hkdEmptyStem(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		HKDs:    []HKDEntry{{Stem: "   ", Content: []byte("data")}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty Stem")
}

// TestValidateEncryptEnvInput_hkdEmptyContent verifies that a HKD with empty content is rejected.
func TestValidateEncryptEnvInput_hkdEmptyContent(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		HKDs:    []HKDEntry{{Stem: "HKD-A", Content: nil}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty content")
}

// TestValidateEncryptEnvInput_sealedSecretOnlyVerify verifies that providing only
// the verification key (without the decryption key) is rejected.
func TestValidateEncryptEnvInput_sealedSecretOnlyVerify(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		SealedSecrets: &SealedSecretKeys{
			VerificationKey: "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----",
			DecryptionKey:   "",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be provided together")
}

// TestValidateEncryptEnvInput_sealedSecretOnlyDecrypt verifies the symmetric case.
func TestValidateEncryptEnvInput_sealedSecretOnlyDecrypt(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		SealedSecrets: &SealedSecretKeys{
			VerificationKey: "",
			DecryptionKey:   "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be provided together")
}

// TestValidateEncryptEnvInput_valid verifies that a fully valid input does not error.
func TestValidateEncryptEnvInput_valid(t *testing.T) {
	err := validateEncryptEnvInput(EncryptEnvInput{
		EnvYAML: minimalValidEnvYAML,
		HKDs: []HKDEntry{
			{Stem: "HKD-A", Content: []byte("cert data")},
			{Stem: "HKD-B", Content: []byte("cert data")},
		},
		SealedSecrets: &SealedSecretKeys{
			VerificationKey: "verify-pem",
			DecryptionKey:   "decrypt-pem",
		},
	})
	require.NoError(t, err)
}

// ─── injectSigningKey ────────────────────────────────────────────────────────

// TestInjectSigningKey verifies that the signing key is base64-encoded and set in the map.
func TestInjectSigningKey(t *testing.T) {
	m := make(map[string]interface{})
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMIIBIj\n-----END PUBLIC KEY-----\n")

	injectSigningKey(m, pub)

	got, ok := m["signingKey"].(string)
	require.True(t, ok, "signingKey must be a string")
	assert.Equal(t, gen.EncodeToBase64(pub), got)

	// Verify the value is valid base64.
	_, err := base64.StdEncoding.DecodeString(got)
	assert.NoError(t, err, "signingKey value must be valid base64")
}

// ─── injectHostAttestation ───────────────────────────────────────────────────

// TestInjectHostAttestation_singleEntry verifies injection of one HKD.
func TestInjectHostAttestation_singleEntry(t *testing.T) {
	m := make(map[string]interface{})
	hkds := []HKDEntry{
		{Stem: "HKD-AlphaNode-Primary", Content: []byte("cert-content-38")},
	}

	injectHostAttestation(m, hkds)

	attestation, ok := m["host-attestation"].(map[string]interface{})
	require.True(t, ok, "host-attestation must be a map")
	require.Contains(t, attestation, "HKD-AlphaNode-Primary")

	entry, ok := attestation["HKD-AlphaNode-Primary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "HKD-AlphaNode-Primary", entry["description"])
	assert.Equal(t, gen.EncodeToBase64([]byte("cert-content-38")), entry["host-key-doc"])
}

// TestInjectHostAttestation_multipleEntries verifies that multiple HKDs are injected
// and that each has an independent entry keyed by its stem.
func TestInjectHostAttestation_multipleEntries(t *testing.T) {
	m := make(map[string]interface{})
	hkds := []HKDEntry{
		{Stem: "HKD-A", Content: []byte("certA")},
		{Stem: "HKD-B", Content: []byte("certB")},
		{Stem: "HKD-C", Content: []byte("certC")},
	}

	injectHostAttestation(m, hkds)

	attestation, ok := m["host-attestation"].(map[string]interface{})
	require.True(t, ok)
	assert.Len(t, attestation, 3)

	for _, h := range hkds {
		entry, ok := attestation[h.Stem].(map[string]interface{})
		require.True(t, ok, "entry for %s missing", h.Stem)
		assert.Equal(t, h.Stem, entry["description"])
		assert.Equal(t, gen.EncodeToBase64(h.Content), entry["host-key-doc"])
	}
}

// TestInjectHostAttestation_preservesOrder verifies that multiple entries are
// independently addressable (order doesn't matter in a Go map, but all must be present).
func TestInjectHostAttestation_preservesOrder(t *testing.T) {
	m := make(map[string]interface{})
	hkds := make([]HKDEntry, maxHKDCount)
	for i := range hkds {
		hkds[i] = HKDEntry{
			Stem:    "HKD-" + strings.Repeat("X", i+1),
			Content: []byte("data"),
		}
	}

	injectHostAttestation(m, hkds)

	attestation := m["host-attestation"].(map[string]interface{})
	assert.Len(t, attestation, maxHKDCount)
}

// ─── injectSealedSecrets ─────────────────────────────────────────────────────

// TestInjectSealedSecrets_mergesIntoExistingSection verifies that when the env map
// already contains a confidential-containers block, injectSealedSecrets preserves
// all existing keys and only replaces the "secret" sub-key.
// This covers the case where the user's env.yaml already carries the section.
func TestInjectSealedSecrets_mergesIntoExistingSection(t *testing.T) {
	// Pre-populate the map with a confidential-containers block that has an
	// extra field beyond "secret" (mirrors a real env.yaml with regoValidator, etc.)
	m := map[string]interface{}{
		"confidential-containers": map[string]interface{}{
			"regoValidator": map[string]interface{}{
				"policy": "existing-policy",
			},
			"secret": map[string]interface{}{
				"verificationKey": "OLD-VERIFY",
				"decryptionKey":   "OLD-DECRYPT",
			},
		},
	}

	ss := &SealedSecretKeys{
		VerificationKey: `-----BEGIN PUBLIC KEY-----\nnewverify\n-----END PUBLIC KEY-----`,
		DecryptionKey:   `-----BEGIN PRIVATE KEY-----\nnewdecrypt\n-----END PRIVATE KEY-----`,
	}

	injectSealedSecrets(m, ss)

	cc, ok := m["confidential-containers"].(map[string]interface{})
	require.True(t, ok)

	// The pre-existing regoValidator must still be present.
	regos, ok := cc["regoValidator"].(map[string]interface{})
	require.True(t, ok, "regoValidator must be preserved")
	assert.Equal(t, "existing-policy", regos["policy"])

	// The secret sub-key must carry the new values, not the old ones.
	secret, ok := cc["secret"].(map[string]interface{})
	require.True(t, ok)

	verNode, ok := secret["verificationKey"].(*yaml.Node)
	require.True(t, ok)
	assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nnewverify\n-----END PUBLIC KEY-----", verNode.Value)

	decNode, ok := secret["decryptionKey"].(*yaml.Node)
	require.True(t, ok)
	assert.Equal(t, "-----BEGIN PRIVATE KEY-----\nnewdecrypt\n-----END PRIVATE KEY-----", decNode.Value)
}

// TestInjectSealedSecrets verifies that both PEM strings land in the correct nested path
// and that the yaml.Node wrapper produces double-quoted scalar output.
//
// Input keys use literal \n sequences (as delivered by cat-ing a PEM file that stores
// newlines as backslash-n).  The expected behaviour is:
//   - The yaml.Node value has real newlines (literal \n → 0x0A normalisation applied).
//   - The marshalled YAML uses double-quoted style: decryptionKey: "...\n..."
//   - No single-quoted style is emitted.
func TestInjectSealedSecrets(t *testing.T) {
	m := make(map[string]interface{})
	// Use literal \n sequences to simulate what ReadDataFromFile returns for such files.
	ss := &SealedSecretKeys{
		VerificationKey: `-----BEGIN PUBLIC KEY-----\nverify\n-----END PUBLIC KEY-----`,
		DecryptionKey:   `-----BEGIN PRIVATE KEY-----\ndecrypt\n-----END PRIVATE KEY-----`,
	}

	injectSealedSecrets(m, ss)

	cc, ok := m["confidential-containers"].(map[string]interface{})
	require.True(t, ok, "confidential-containers must be a map")

	secret, ok := cc["secret"].(map[string]interface{})
	require.True(t, ok, "secret must be a map")

	// Values are stored as *yaml.Node; literal \n must be normalised to real newlines.
	verNode, ok := secret["verificationKey"].(*yaml.Node)
	require.True(t, ok, "verificationKey must be a *yaml.Node")
	assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nverify\n-----END PUBLIC KEY-----", verNode.Value)
	assert.Equal(t, yaml.DoubleQuotedStyle, verNode.Style)

	decNode, ok := secret["decryptionKey"].(*yaml.Node)
	require.True(t, ok, "decryptionKey must be a *yaml.Node")
	assert.Equal(t, "-----BEGIN PRIVATE KEY-----\ndecrypt\n-----END PRIVATE KEY-----", decNode.Value)
	assert.Equal(t, yaml.DoubleQuotedStyle, decNode.Style)

	// Marshal and verify double-quoted output with \n — not single-quoted, not \\n.
	out, err := gen.MapToYaml(m)
	require.NoError(t, err)
	assert.Contains(t, out, `verificationKey: "`)
	assert.Contains(t, out, `decryptionKey: "`)
	assert.NotContains(t, out, `verificationKey: '`)
	assert.NotContains(t, out, `decryptionKey: '`)
	assert.NotContains(t, out, `\\n`) // no double-escaped backslash
}

// ─── EncryptEnv — input validation ───────────────────────────────────────

// TestEncryptEnv_emptyEnvYAML verifies that an empty EnvYAML input is rejected
// before any crypto work is attempted.
func TestEncryptEnv_emptyEnvYAML(t *testing.T) {
	_, _, _, err := EncryptEnv(EncryptEnvInput{EnvYAML: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EnvYAML must not be empty")
}

// TestEncryptEnv_missingTypeField verifies that an env YAML without
// "type: env" at the root is rejected before schema validation.
func TestEncryptEnv_missingTypeField(t *testing.T) {
	envYAML := readFixture(t, encryptEnvMissingTypePath)

	_, _, _, err := EncryptEnv(EncryptEnvInput{EnvYAML: envYAML})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"type"`)
}

// TestEncryptEnv_sealedSecretPairViolation verifies that providing only one
// of the sealed-secret flags is rejected.
func TestEncryptEnv_sealedSecretPairViolation(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	_, _, _, err := EncryptEnv(EncryptEnvInput{
		EnvYAML: envYAML,
		SealedSecrets: &SealedSecretKeys{
			VerificationKey: "verify",
			DecryptionKey:   "",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be provided together")
}

// TestEncryptEnv_tooManyHKDs verifies that > 10 HKD entries are rejected.
func TestEncryptEnv_tooManyHKDs(t *testing.T) {
	hkds := make([]HKDEntry, maxHKDCount+1)
	for i := range hkds {
		hkds[i] = HKDEntry{Stem: "HKD-" + strings.Repeat("A", i+1), Content: []byte("data")}
	}
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	_, _, _, err := EncryptEnv(EncryptEnvInput{
		EnvYAML: envYAML,
		HKDs:    hkds,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many HKD entries")
}

// ─── EncryptEnv — full pipeline (requires openssl) ───────────────────────

// TestEncryptEnv_minimalEnv encrypts a base env with no injections.
// This is the simplest possible happy path.
func TestEncryptEnv_minimalEnv(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	result, inputSHA, outputSHA, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:                 envYAML,
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix),
		"expected %q prefix, got %q", cccoEncryptPrefix, result[:min(len(result), 30)])
	assert.NotEmpty(t, inputSHA, "input SHA must not be empty")
	assert.NotEmpty(t, outputSHA, "output SHA must not be empty")
	assert.NotEqual(t, inputSHA, outputSHA, "input and output SHAs must differ")
}

// TestEncryptEnv_withSigningKey verifies that a signing key is base64-injected
// and the assembled env still passes schema validation before encryption.
func TestEncryptEnv_withSigningKey(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)
	signingKeyContent := readFixture(t, encryptEnvSigningKeyPath)

	result, inputSHA, outputSHA, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:                 envYAML,
		SigningKeyPub:           []byte(signingKeyContent),
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
	assert.NotEmpty(t, inputSHA)
	assert.NotEmpty(t, outputSHA)
}

// TestEncryptEnv_withHKDs verifies that host-attestation entries are injected
// and the env passes schema validation before encryption.
func TestEncryptEnv_withHKDs(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)
	hkd38Content := readFixture(t, encryptEnvHKD38Path)
	hkd39Content := readFixture(t, encryptEnvHKD39Path)

	result, inputSHA, outputSHA, err := EncryptEnv(EncryptEnvInput{
		EnvYAML: envYAML,
		HKDs: []HKDEntry{
			{Stem: "HKD-AlphaNode-Primary", Content: []byte(hkd38Content)},
			{Stem: "HKD-BetaNode-Secondary", Content: []byte(hkd39Content)},
		},
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
	assert.NotEmpty(t, inputSHA)
	assert.NotEmpty(t, outputSHA)
}

// TestEncryptEnv_withSigningKeyAndHKDs combines signing key + HKD injection.
func TestEncryptEnv_withSigningKeyAndHKDs(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)
	signingKeyContent := readFixture(t, encryptEnvSigningKeyPath)
	hkd38Content := readFixture(t, encryptEnvHKD38Path)

	result, _, _, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:       envYAML,
		SigningKeyPub: []byte(signingKeyContent),
		HKDs: []HKDEntry{
			{Stem: "HKD-AlphaNode-Primary", Content: []byte(hkd38Content)},
		},
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
}

// TestEncryptEnv_withVolumes verifies that a base env containing volumes
// is accepted and encrypted correctly.
func TestEncryptEnv_withVolumes(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvVolPath)

	result, _, _, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:                 envYAML,
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
}

// TestEncryptEnv_defaultOsCcco verifies that omitting ConfidentialComputingOs
// defaults to "ccco" and produces the hyper-protect-basic prefix.
func TestEncryptEnv_defaultOsCcco(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	// Leave ConfidentialComputingOs empty — the implementation should default to ccco.
	result, _, _, err := EncryptEnv(EncryptEnvInput{EnvYAML: envYAML})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
}

// TestEncryptEnv_twoCallsProduceDifferentCiphertext verifies that two calls
// with identical inputs produce different ciphertext (random AES key per call).
func TestEncryptEnv_twoCallsProduceDifferentCiphertext(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)
	input := EncryptEnvInput{
		EnvYAML:                 envYAML,
		ConfidentialComputingOs: cccoOs,
	}

	result1, _, _, err1 := EncryptEnv(input)
	require.NoError(t, err1)

	result2, _, _, err2 := EncryptEnv(input)
	require.NoError(t, err2)

	assert.NotEqual(t, result1, result2,
		"two encryptions of the same plaintext must produce different ciphertext")
}

// TestEncryptEnv_outputChecksumMatchesSHAOfResult verifies that the returned
// outputSHA is the SHA-256 of the encrypted output string itself.
func TestEncryptEnv_outputChecksumMatchesSHAOfResult(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	result, _, outputSHA, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:                 envYAML,
		ConfidentialComputingOs: cccoOs,
	})
	require.NoError(t, err)

	assert.Equal(t, gen.GenerateSha256(result), outputSHA)
}

// ─── buildHKDEntries + EncryptEnv integration ────────────────────────

// TestEncryptEnv_buildAndEncryptTwoHKDs is an end-to-end test that uses
// buildHKDEntries to build the HKD slice from real fixture files and then
// calls EncryptEnv.
func TestEncryptEnv_buildAndEncryptTwoHKDs(t *testing.T) {
	envYAML := readFixture(t, encryptEnvBaseEnvPath)

	hkds, err := buildHKDEntries([]string{encryptEnvHKD38Path, encryptEnvHKD39Path})
	require.NoError(t, err)
	require.Len(t, hkds, 2)

	result, inputSHA, outputSHA, err := EncryptEnv(EncryptEnvInput{
		EnvYAML:                 envYAML,
		HKDs:                    hkds,
		ConfidentialComputingOs: cccoOs,
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, cccoEncryptPrefix))
	assert.NotEmpty(t, inputSHA)
	assert.NotEmpty(t, outputSHA)
}

// ─── min helper (pre-Go 1.21 compat) ─────────────────────────────────────────

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
