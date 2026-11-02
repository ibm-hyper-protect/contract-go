# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Build / Test / Lint

```bash
make test               # go test ./... -v
make fmt                # go fmt ./... (only formatter/lint step; no golangci-lint/vet config)
make test-cover         # coverage → build/cover.out (build/ must exist)
go test ./contract/... -v -run TestFunctionName      # single test (any package path works)
```

- Tests shell out to **OpenSSL** (PATH or `OPENSSL_BIN` env var). Make sure it is installed before trusting test results.
- Tests reference fixtures via relative paths like `../samples/...` — run from the package dir or via `go test ./pkg/...`.

## Architecture

- **`contract/contract.go`** — public API for contracts (`Hpcr*`, `HpccInitdata`). Other public packages: `attestation/`, `certificate/`, `image/`, `imagespec/`, `network/`, `secrets/`, `crypto/`, `rego/`.
- **`common/general/general.go`** (~1300 lines, aliased `gen`) — catch-all utilities: exec, temp files, checksums, YAML↔JSON, schema validation, cert fetching. Check here before writing a helper.
- **`common/{encrypt,decrypt,cert,secrets}/`** — internal helpers behind the public packages.
- **`encryption/`** and **`schema/{contract,network}/`** — leaf packages with only embedded assets (`//go:embed`), no logic besides cert map init.
- **`contract/template/*.yaml`** — templates read at runtime via `runtime.Caller(0)` (`readHpcrTemplateFile`), so they are tied to source location. Don't move/rename without updating that function.

## Conventions

- **Return shape**: `Hpcr*` functions in `contract/` return `(result, inputChecksum, outputChecksum, error)` (SHA256 hex). Other packages (`certificate`, `image`, `attestation`) have their own signatures — match the neighbouring functions.
- **Import aliases** (always used): `gen` common/general, `enc` common/encrypt, `dec` common/decrypt, `cert` encryption, `crt` common/cert, `csecrets` common/secrets, `sch`/`schn` schema/contract / schema/network.
- **Errors**: `fmt.Errorf("context - %v", err)` (dash separator, not colon, `%v` not `%w`).
- **Empty checks**: `gen.CheckIfEmpty(a, b, ...)`, not `== ""`.
- **GoDoc** on all exported symbols with multi-line parameter/return sections.
- **Platform constants**: `gen.ConfidentialComputingOsCcrt/Ccrv/Ccco`, `gen.HyperProtectOsHpvs` — no raw strings.

## Git / PR (enforced by CI)

- Branch prefix: `Feature/ Fix/ Docs/ Refactor/ Performance/ Test/ Chore/ CI/`
- Conventional Commits (`feat:`, `fix:`, …); all commits must be GPG/SSH signed; no force-push to PR branches (`git pull --rebase`).

## Module

`github.com/ibm-hyper-protect/contract-go/v3`, Go 1.27.1 (go.mod and CI agree).
