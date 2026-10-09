# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Architectural Constraints

- **`contract/` depends on `common/`; `common/general/` depends on `encryption/` and `schema/`**: the dependency graph is acyclic — `encryption/` and `schema/` are leaf packages with no internal imports.
- **No interfaces**: the library has no interfaces or mocks; all code is concrete. OpenSSL is invoked as a subprocess, not via a Go crypto abstraction — replacing it requires changing `common/general` and `common/encrypt/decrypt`.
- **All encryption requires external OpenSSL binary**: the library shells out to `openssl` for key operations. Pure-Go TLS/crypto is used only for certificate parsing (`crypto/x509`). Tests will silently fail if OpenSSL is absent.
- **Embedded assets are versioned by file name**: adding a new encryption cert requires adding `ccrt/vX.Y.Z.crt` (etc.) and the `init()` in `encryption/cert.go` auto-populates `CertificateMap` by scanning filenames. Cert version strings come from file names.
- **Schema is frozen at compile time**: contract JSON schemas are embedded — there's no runtime schema loading path. Schema updates require adding new files and embed directives.
- **`encryptWrapper` is the single integration point** for sign+encrypt: both `HpcrContractSignedEncrypted` and `HpcrContractSignedEncryptedContractExpiry` delegate to it, differing only in whether a time-limited signing cert is generated.
- **Template indentation is a hard requirement**: `indentTemplateContent` adds two-space indent to all template lines so the embedded contract appears as a valid YAML block scalar. Remove or change indentation and YAML parsing will break.
- **`passFd = 3`** is hardcoded: the anonymous pipe for passphrase delivery to OpenSSL always uses fd 3. Any refactor that adds new file descriptors before fd 3 will break passphrase passing.
