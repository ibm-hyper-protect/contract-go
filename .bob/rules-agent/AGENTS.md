# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Coding Rules

- **Import aliases are mandatory**: `gen` for `common/general`, `enc` for `common/encrypt`, `dec` for `common/decrypt`, `cert` for `encryption`. Deviation breaks readability conventions.
- **Public Hpcr* function signature**: always return `(string, string, string, error)` — (result, inputChecksum, outputChecksum, error). Don't change this pattern.
- **Empty validation**: use `gen.CheckIfEmpty(...)` not raw `== ""`. It accepts variadic `interface{}`.
- **OpenSSL subprocess calls**: passwords MUST go through `gen.ExecCommandWithPassword` + `gen.AppendPasswordFdArgs` (passes via fd 3, not command line). Never inline passwords in args slice.
- **Temp file lifecycle**: `defer gen.RemoveTempFile(path)` must immediately follow `gen.CreateTempFile(...)` — temp files have the `ccrt-` prefix (`TempFolderNamePrefix`).
- **Schema/cert data is embedded**: `schema/contract/schema.go` and `encryption/cert.go` use `//go:embed` — adding new `.crt` or `.json` files requires matching embed directives, not code changes.
- **Template path resolution**: `readHpcrTemplateFile` uses `runtime.Caller(0)` to locate `contract/template/` relative to the source file — templates are tied to source location, not CWD.
- **Error message format**: `fmt.Errorf("description - %v", err)` (dash separator). Keep consistent.
- **Platform constants**: use `gen.ConfidentialComputingOsCcrt/Ccrv/Ccco` and `gen.HyperProtectOsHpvs`; don't use raw strings.
- **Commit signing required**: all commits must be GPG/SSH signed or CI will reject the PR.
