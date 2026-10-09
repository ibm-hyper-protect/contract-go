# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Documentation Context

- **`common/general/general.go`** is a large (~1300 line) catch-all utility package — most utility functions (exec, checksum, base64, YAML↔JSON, schema validation, cert fetch, tgz) live there, not in dedicated small files.
- **`contract/contract.go`** is the single public API surface for the entire library — all `Hpcr*` functions that callers use are in this one file.
- **`encryption/`** does NOT contain logic — only embedded `.crt` files and the `CertificateMap`/`LatestEncryptionCertificate*` vars populated by `init()`.
- **`samples/`** contains the canonical test fixtures (private keys, contracts, TGZ folder, certs) that test files reference with relative paths like `../../samples/`.
- **Supported platforms**: `ccrt` (IBM CCRT), `ccrv` (CCRT for Red Hat Virtualization), `ccco` (Containers for OpenShift), `hpvs` (legacy HyperProtect). The `ccco` platform has two sub-variants `ccco-peerpod` and `ccco-bmtl` (only used for template selection).
- **`HpccInitdata`** is specific to CCCO peer pods (Kata Containers/OpenShift) — not general-purpose; generates TOML initdata, gzipped+base64.
- API docs are in `docs/README.md`; samples are in `samples/` with subdirectories per feature.
