# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Documentation Context (Non-Obvious Only)

- `common/general/general.go` (~1300 lines) holds most utilities (exec, checksum, base64, YAML↔JSON, schema validation, cert fetch, tgz) — there are no small dedicated util files.
- `contract/contract.go` is the API surface for contract functions only; certificate/image/attestation/network/secrets APIs live in their own top-level packages.
- `encryption/` has no logic beyond cert map init — it's embedded `.crt` files + `ccco/release-map.yaml`.
- `samples/` (subdir per feature) is the canonical fixture set used by tests via relative paths; API docs are in `docs/README.md`.
- Platforms: `ccrt`, `ccrv` (RHEL virtualization), `ccco` (OpenShift containers; template variants `ccco-peerpod`, `ccco-bmtl`), `hpvs` (legacy HyperProtect). Empty/unknown version resolves to `ccrt`/`hpvs` defaults in `common/general`.
- `HpccInitdata` is CCCO peer-pod specific (TOML initdata, gzipped + base64), not general purpose.
