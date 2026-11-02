# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Architectural Constraints (Non-Obvious Only)

- **Layering**: public packages → `common/*` → `common/general` → `encryption/` + `schema/*` (leaf packages, no internal imports). Keep it acyclic; `gen` must not import public packages.
- **No interfaces/mocks**: all concrete. Crypto is done by shelling out to the `openssl` binary (`gen.ExecCommand*`); Go `crypto/x509` is only used for certificate parsing. Swapping this out means changing `common/general`, `common/encrypt`, `common/decrypt`.
- **Passphrase delivery uses `passFd = 3`** (`common/general/general.go`) via `cmd.ExtraFiles[0]`. Adding extra files/fds ahead of it breaks passphrase passing.
- **Compile-time assets**: certs and schemas are embedded; there is no runtime loading. Cert versions are derived from filenames in `init()`; schema files are version-pinned in their names.
- **Templates** are located relative to the source file (`runtime.Caller`), so the library only works from a source checkout/module cache layout that keeps `contract/template/` beside `contract.go`.
- **`encryptWrapper`** is the single sign+encrypt integration point; expiry variant only adds time-limited signing-cert generation.
