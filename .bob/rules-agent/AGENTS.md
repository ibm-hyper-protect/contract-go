# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Coding Rules (Non-Obvious Only)

- **OpenSSL passwords**: always `gen.ExecCommandWithPassword` + `gen.AppendPasswordFdArgs` (delivered via fd 3 pipe, `-passin fd:3`). Never put a password in the args slice.
- **Temp files**: `defer gen.RemoveTempFile(path)` immediately after `gen.CreateTempFile(...)` (files are prefixed `ccrt-`, `gen.TempFolderNamePrefix`).
- **Adding embedded assets**:
  - New `.crt`: just drop it in `encryption/{ccrt,ccrv,ccco,hpvs}/` — embed is a glob and `init()` in `encryption/cert.go` picks up the version from the filename. No code change.
  - New schema `.json`: needs a new `//go:embed` + var in `schema/contract/schema.go` (names are version-pinned) and wiring in `gen` schema selection.
  - New CCCO release mapping: `encryption/ccco/release-map.yaml`.
- **Template indentation**: `indentTemplateContent` prefixes two spaces so templates embed as YAML block scalars; changing it breaks generated contracts.
- **Sign+encrypt flows** (`HpcrContractSignedEncrypted`, `...ContractExpiry`) both go through `encryptWrapper` in `contract/contract.go` — change shared behaviour there.
