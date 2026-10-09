# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Build / Test / Lint

```bash
make test               # Run all tests (go test ./... -v)
make fmt                # Format all Go files (go fmt ./...)
make tidy               # Tidy go.mod/go.sum
make test-cover         # Coverage report → build/cover.out
```

Run a **single test** by name:
```bash
go test ./contract/... -v -run TestFunctionName
go test ./common/general/... -v -run TestFunctionName
```

Tests require **OpenSSL** on PATH (or override via `OPENSSL_BIN` env var). Missing OpenSSL causes silent failures, not compile errors.

## Architecture

- **`contract/`** — public API; all exported `Hpcr*` functions live here (signing, encryption, validation, templates, initdata)
- **`common/general/`** — central utility package aliased as `gen` everywhere; contains `ExecCommand`, `ExecCommandWithPassword`, schema validation, cert fetching, temp file helpers
- **`common/encrypt/`** / **`common/decrypt/`** — encrypt/decrypt helpers, aliased `enc`/`dec` in `contract/`
- **`encryption/`** — embedded `.crt` files via `//go:embed`; `CertificateMap`, `LatestEncryptionCertificate*` vars populated at init
- **`schema/contract/`** / **`schema/network/`** — JSON schemas embedded via `//go:embed`; used by `VerifyContractWithSchema`
- **`attestation/`**, **`certificate/`**, **`crypto/`**, **`image/`**, **`imagespec/`**, **`network/`**, **`rego/`**, **`secrets/`** — domain packages, each with `_test.go` co-located

**Function return convention** — all public `Hpcr*` functions return `(result, inputChecksum, outputChecksum, error)` — three strings then error. Checksums are SHA256 hex strings.

## Code Style

- **Import aliases**: internal packages are always aliased at import — `gen`, `enc`, `dec`, `cert`, `sch`, `schn`. Follow the same alias if importing those packages.
- **GoDoc on all exported symbols** with parameter/return sections in multi-line format (see existing functions).
- **Error wrapping**: use `fmt.Errorf("context - %v", err)` (dash separator, not colon).
- **Empty-check**: use `gen.CheckIfEmpty(val1, val2...)` instead of manual `== ""` comparisons.
- **Temp files**: always `defer gen.RemoveTempFile(path)` immediately after `gen.CreateTempFile`.
- **Password passing to OpenSSL**: always use `gen.ExecCommandWithPassword` + `gen.AppendPasswordFdArgs`; never pass passwords via command-line args.
- **Template files**: `contract/template/` contains YAML templates read at runtime via `runtime.Caller(0)` to resolve relative paths — do not move or rename template files without updating `readHpcrTemplateFile`.

## Git / PR Conventions

- **Branch names**: `Feature/`, `Fix/`, `Docs/`, `Refactor/`, `Performance/`, `Test/`, `Chore/`, `CI/` prefix required (enforced by CI)
- **Commit messages**: Conventional Commits — `feat:`, `fix:`, `docs:`, `refactor:`, `perf:`, `test:`, `chore:`, `ci:`
- **All commits must be GPG or SSH signed** (enforced by CI — PRs with unsigned commits are rejected)
- **No force pushes** to PR branches; use `git pull --rebase` instead

## Module

Module path: `github.com/ibm-hyper-protect/contract-go/v2`  
Go version: `1.27.1` (go.mod); CI currently runs `1.26.4`
