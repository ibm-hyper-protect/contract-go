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

package contract

import (
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	// maxHKDCount is the maximum number of HKD files accepted per invocation.
	maxHKDCount = 10

	// envTypeField is the mandatory root field that every CCCO env section must carry.
	envTypeField = "type"
	// envTypeValue is the expected value of the type field.
	envTypeValue = "env"
)

// HKDEntry describes one Hardware Key Document to inject into the env map.
// The Stem field is derived automatically from the filename when using
// [HpcrBuildHKDEntries]; callers that provide entries directly must populate
// both fields.
//
// YAML output per entry:
//
//	<Stem>:
//	  description: <Description or Stem>
//	  host-key-doc: "<base64(Content)>"
type HKDEntry struct {
	// It becomes the YAML map key.
	Stem string

	// Content is the raw bytes of the HKD certificate file.
	Content []byte

	// Description overrides the value of the description field in the YAML output.
	// When empty, Stem is used as the description (original behaviour).
	Description string
}

// SealedSecretKeys holds the raw PEM strings for sealed-secret injection.
// Both fields must be non-empty if sealed-secret injection is requested.
type SealedSecretKeys struct {
	// VerificationKey is the raw PEM content of the sealed-secret verification key.
	VerificationKey string

	// DecryptionKey is the raw PEM content of the sealed-secret decryption key.
	DecryptionKey string
}

// EncryptEnvInput is the self-documenting input type for [EncryptEnv].
// Every optional field has a clearly documented zero-value behaviour so callers
// never need to guess what "leave it empty" means.
type EncryptEnvInput struct {
	// EnvYAML is the base env YAML string provided by the customer.
	// Must contain "type: env" at the root.  Required.
	EnvYAML string

	// SigningKeyPub is the content of the public key (.pub) file.
	// When non-empty it is base64-encoded and injected as envMap["signingKey"].
	// When empty the signingKey field is not injected.
	SigningKeyPub []byte

	// HKDs is the ordered list of Hardware Key Document entries to inject.
	// Processed in slice order; must contain 0–10 entries.
	// When empty the host-attestation section is not injected.
	HKDs []HKDEntry

	// SealedSecrets holds the two sealed-secret PEM keys.
	// When both fields are non-empty they are injected as raw PEM strings under
	// confidential-containers.secret.  When nil or both fields are empty the
	// section is not injected.
	SealedSecrets *SealedSecretKeys

	// ConfidentialComputingOs is the target platform.
	// Defaults to "ccco" when empty.
	ConfidentialComputingOs string

	// CertVersion selects a specific IBM encryption certificate version (e.g. "26.7.1").
	// Uses the latest embedded CCCO certificate when empty.
	CertVersion string

	// EncryptionCertificate is a custom IBM encryption certificate PEM string.
	// Uses the latest embedded CCCO certificate when empty.
	EncryptionCertificate string
}

// buildHKDEntries derives [HKDEntry] values from a slice of filesystem paths.
// It reads each file, strips the ".cert" extension from the filename to produce
// the Stem, and returns the populated slice ready to pass into [EncryptEnv].
//
// Parameters:
//   - hkdPaths: Ordered slice of paths to HKD certificate files (e.g. "HKD-AlphaNode-Primary.cert").
//     Must not exceed 10 entries.
//
// Returns:
//   - []HKDEntry populated from the files, in the same order as hkdPaths.
//   - Error if any path cannot be read.
func buildHKDEntries(hkdPaths []string) ([]HKDEntry, error) {
	if len(hkdPaths) > maxHKDCount {
		return nil, fmt.Errorf("too many --hkd flags: %d provided, maximum is %d", len(hkdPaths), maxHKDCount)
	}

	entries := make([]HKDEntry, 0, len(hkdPaths))
	for _, p := range hkdPaths {
		raw, err := gen.ReadDataFromFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read HKD file %q: %w", p, err)
		}
		stem := strings.TrimSuffix(filepath.Base(p), ".cert")
		entries = append(entries, HKDEntry{Stem: stem, Content: []byte(raw)})
	}

	return entries, nil
}

// EncryptEnv is the single public API for the encrypt-env CCCO feature.
//
// It follows the inject → validate → encrypt pipeline defined in the feature design:
//  1. Validates the input (type check, HKD count, sealed-secret pair).
//  2. Unmarshals the base env YAML into a mutable Go map.
//  3. Injects signingKey, host-attestation, and confidential-containers.secret
//     from the caller-supplied inputs (each injection is skipped when the
//     corresponding field is absent / empty).
//  4. Marshals the fully-assembled map back to YAML.
//  5. Schema-validates the assembled env section against the CCCO JSON schema.
//  6. Encrypts the env YAML using the IBM CCCO encryption certificate.
//
// Parameters:
//   - input: [EncryptEnvInput] carrying all flags / file contents.
//
// Returns:
//   - Encrypted env string in "hyper-protect-basic.<enc-key>.<enc-data>" format.
//   - SHA256 of the assembled plain-text env YAML (before encryption).
//   - SHA256 of the encrypted output string.
//   - Error describing the first failing step with enough context to pinpoint the problem.
func EncryptEnv(input EncryptEnvInput) (string, string, string, error) {
	_, encrypted, inputSHA, outputSHA, err := encryptEnvCore(input)
	return encrypted, inputSHA, outputSHA, err
}

// EncryptEnvWithPlain is a temporary variant of [EncryptEnv] that additionally
// returns the fully-assembled plain-text env YAML produced by the inject step,
// before encryption.  This is intended for debugging and testing workflows only.
//
// Returns:
//   - assembledYAML: the fully assembled plain-text env YAML (before encryption).
//   - encrypted: the encrypted env string in "hyper-protect-basic.<enc-key>.<enc-data>" format.
//   - inputSHA: SHA256 of assembledYAML.
//   - outputSHA: SHA256 of encrypted.
//   - error: first failing step, or nil.
//
// TODO(temp): remove once --plain testing flag is no longer needed.
func EncryptEnvWithPlain(input EncryptEnvInput) (assembledYAML, encrypted, inputSHA, outputSHA string, err error) {
	return encryptEnvCore(input)
}

// encryptEnvCore runs the full inject → validate → encrypt pipeline and returns
// all intermediate and final values.  Both [EncryptEnv] and [EncryptEnvWithPlain]
// delegate to this function to avoid duplicating the pipeline.
func encryptEnvCore(input EncryptEnvInput) (assembledYAML, encrypted, inputSHA, outputSHA string, err error) {
	// ── Step 1: Validate inputs ──────────────────────────────────────────────
	if err = validateEncryptEnvInput(input); err != nil {
		return
	}

	// ── Step 2 & 3: Unmarshal base YAML → mutable map ───────────────────────
	envMap := make(map[string]interface{})
	if err = yaml.Unmarshal([]byte(input.EnvYAML), &envMap); err != nil {
		err = fmt.Errorf("failed to parse env YAML: %w", err)
		return
	}

	// Verify the mandatory "type: env" root field.
	if t, ok := envMap[envTypeField]; !ok || t != envTypeValue {
		err = fmt.Errorf("env YAML must have %q: %q at the root", envTypeField, envTypeValue)
		return
	}

	// ── Step 4: Inject signingKey ────────────────────────────────────────────
	if len(input.SigningKeyPub) > 0 {
		injectSigningKey(envMap, input.SigningKeyPub)
	}

	// ── Step 5: Inject host-attestation ─────────────────────────────────────
	if len(input.HKDs) > 0 {
		injectHostAttestation(envMap, input.HKDs)
	}

	// ── Step 6: Inject confidential-containers.secret ───────────────────────
	if input.SealedSecrets != nil &&
		!gen.CheckIfEmpty(input.SealedSecrets.VerificationKey, input.SealedSecrets.DecryptionKey) {
		injectSealedSecrets(envMap, input.SealedSecrets)
	}

	// ── Step 7: Marshal assembled map → YAML string ──────────────────────────
	assembledYAML, err = gen.MapToYaml(envMap)
	if err != nil {
		err = fmt.Errorf("failed to marshal assembled env map to YAML: %w", err)
		return
	}

	// ── Step 8: Schema-validate against CCCO schema ──────────────────────────
	osName := input.ConfidentialComputingOs
	if osName == "" {
		osName = gen.ConfidentialComputingOsCcco
	}

	if err = HpcrVerifyContract(assembledYAML, osName, SectionEnv); err != nil {
		err = fmt.Errorf("env YAML schema validation failed: %w", err)
		return
	}

	// ── Step 9: Encrypt ───────────────────────────────────────────────────────
	encrypted, inputSHA, outputSHA, err = HpcrTextEncrypted(assembledYAML, osName, input.CertVersion, input.EncryptionCertificate)
	if err != nil {
		err = fmt.Errorf("failed to encrypt env YAML: %w", err)
		return
	}

	return
}

// ─── internal helpers ────────────────────────────────────────────────────────

// validateEncryptEnvInput performs all pre-flight checks before touching the env map.
func validateEncryptEnvInput(input EncryptEnvInput) error {
	if gen.CheckIfEmpty(input.EnvYAML) {
		return fmt.Errorf("EnvYAML must not be empty")
	}

	if len(input.HKDs) > maxHKDCount {
		return fmt.Errorf("too many HKD entries: %d provided, maximum is %d", len(input.HKDs), maxHKDCount)
	}

	// Each HKD entry must have a non-empty Stem.
	for i, h := range input.HKDs {
		if strings.TrimSpace(h.Stem) == "" {
			return fmt.Errorf("HKD entry at index %d has an empty Stem", i)
		}
		if len(h.Content) == 0 {
			return fmt.Errorf("HKD entry %q has empty content", h.Stem)
		}
	}

	// Sealed-secret keys must be provided as a pair.
	if input.SealedSecrets != nil {
		hasVerify := !gen.CheckIfEmpty(input.SealedSecrets.VerificationKey)
		hasDecrypt := !gen.CheckIfEmpty(input.SealedSecrets.DecryptionKey)
		if hasVerify != hasDecrypt {
			return fmt.Errorf("--ss-verification-key and --ss-decryption-key must be provided together or not at all")
		}
	}

	return nil
}

// injectSigningKey base64-encodes the public key bytes and sets envMap["signingKey"].
func injectSigningKey(envMap map[string]interface{}, pubKeyBytes []byte) {
	envMap["signingKey"] = gen.EncodeToBase64(pubKeyBytes)
}

// injectHostAttestation builds the host-attestation sub-map and injects it into envMap.
// Each HKD produces one entry whose YAML map key is HKDEntry.Stem.
// The description field uses HKDEntry.Description when non-empty, falling back to Stem.
func injectHostAttestation(envMap map[string]interface{}, hkds []HKDEntry) {
	attestation := make(map[string]interface{}, len(hkds))
	for _, h := range hkds {
		desc := h.Description
		if desc == "" {
			desc = h.Stem
		}
		attestation[h.Stem] = map[string]interface{}{
			"description":  desc,
			"host-key-doc": gen.EncodeToBase64(h.Content),
		}
	}
	envMap["host-attestation"] = attestation
}

// injectSealedSecrets sets the confidential-containers.secret block with raw PEM strings.
// The schema accepts raw PEM — no base64 encoding is applied here.
//
// If a confidential-containers map already exists in envMap (e.g. the user's env.yaml
// already carries that section), its existing keys are preserved and only the "secret"
// sub-key is replaced.  This prevents silently dropping other valid fields (e.g.
// config, allowedContainers, regoValidator) that may already be present.
//
// PEM files supplied via --ss-* flags may contain literal \n two-character sequences
// (backslash + n) instead of real newline bytes.  pemDoubleQuotedNode normalises them
// to real newlines before marshalling so that go-yaml v3 emits a standard
// double-quoted scalar:
//
//	decryptionKey: "-----BEGIN PRIVATE KEY-----\nMIIJ...\n-----END PRIVATE KEY-----\n"
//
// A YAML double-quoted scalar represents \n as a real newline on parse, which is
// exactly what every PEM consumer expects.
func injectSealedSecrets(envMap map[string]interface{}, ss *SealedSecretKeys) {
	// Preserve any existing confidential-containers fields; only overwrite "secret".
	existing, _ := envMap["confidential-containers"].(map[string]interface{})
	if existing == nil {
		existing = make(map[string]interface{})
	}
	existing["secret"] = map[string]interface{}{
		"verificationKey": pemDoubleQuotedNode(ss.VerificationKey),
		"decryptionKey":   pemDoubleQuotedNode(ss.DecryptionKey),
	}
	envMap["confidential-containers"] = existing
}

// pemDoubleQuotedNode converts any literal \n sequences in the PEM string to real
// newline bytes, then wraps the value in a yaml.Node with DoubleQuotedStyle so that
// go-yaml v3 marshals it as:
//
//	"-----BEGIN ...-----\nMIIJ...\n-----END ...-----\n"
//
// This produces the canonical, copy-pasteable single-line double-quoted form that
// is unambiguous regardless of whether the source file used real or escaped newlines.
func pemDoubleQuotedNode(s string) *yaml.Node {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: strings.ReplaceAll(s, `\n`, "\n"),
		Style: yaml.DoubleQuotedStyle,
	}
}
