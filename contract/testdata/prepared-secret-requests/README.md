<!-- Copyright (c) 2026 IBM Corp. SPDX-License-Identifier: Apache-2.0. -->

# Prepared request interoperability fixtures

These fifteen encrypted ASRCB files were generated with unmodified IBM
[s390-tools](https://github.com/ibm-s390-linux/s390-tools/tree/b1d612b4a6a84440e16aae6d66e5f8f4be4e977f),
using its public test SE header/HKDs and disposable secrets and signing keys.
`metadata.json` records IDs and types from the generated reference YAML, plus
the request version and whole-file SHA-256. The production parser does not create
these expected IDs. No plaintext secrets, private keys or transport keys are
included. They are test fixtures, never production deployment inputs.

The fixtures cover V1 and hybrid V2, plain/empty/8190-byte payloads, AES, EC,
HMAC, Association, all user-data/signature kinds, and the `--use-name` option.
For `literal-id`, the embedded ID is the UTF-8 name padded to 32 bytes rather
than SHA-256(name). This prevents a consumer from deriving the wrong ID from an
alias or from assuming all IDs are name hashes.

The ordinary test suite needs only Go and these committed files; Rust, `pvsecret`
and a UV device are not needed to inspect their public headers. The fixtures
check format interoperability. They do not demonstrate a trusted production HKD,
supported hardware, request authentication by this parser or successful UV import.
