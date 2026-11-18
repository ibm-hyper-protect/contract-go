<!--
Copyright (c) 2026 IBM Corp.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Prepared retrievable-secret requests in CCRV contracts

This feature implements the contract format described in IBM's
[Retrievable secret documentation](https://www.ibm.com/docs/en/ccrv/1.1.x?topic=solutions-retrievable-secret).
It imports requests already created by trusted `pvsecret` tooling. It does not
create requests or access the Ultravisor.

The original vendor platform schemas remain unchanged. `HpcrVerifyContract`
applies the separate embedded `RetrievableSecretsSchemaCcrv` after the CCRV
platform schema, then checks binary/certificate/reference semantics. Consumers
using the embedded JSON schemas directly must validate against both schemas.

## Files and certificates

Keep these artifacts distinct:

| Artifact | Purpose | Input |
| --- | --- | --- |
| Binary add-secret request | Carries a secret protected for the intended SE guest and target hosts | `RetrievableSecretRequest.Data` |
| Optional request verification certificate | Lets the runtime verify the request's user signature | `RetrievableSecretRequest.Certificate` |
| Host key document (HKD) | Identifies an allowed deployment host | `HostKeyDocument.Data`, keyed by `HKD-MODEL-PLANTSERIAL` |
| Runtime encryption certificate | Encrypts the outer environment and workload sections | Existing contract encryption functions |
| Request ID reference YAML | Contains the secret ID used by the workload's retrieval tooling | Workload support file; never pass it as request data |

The request-verification certificate accepts one PEM or DER X.509 certificate.
An HKD accepts one PEM or DER certificate for the classical format or two PEM
certificates for the hybrid format defined by s390-tools. The helper preserves
the complete document and Base64-encodes its file bytes exactly once. Parsing a
hybrid document does not establish support for its key algorithms in the target
runtime. Logging TLS certificates remain part of the existing logging configuration.

Create requests on a trusted preparation machine using the target image's SE
header and verified HKDs. Follow the IBM instructions for certificate-chain
verification and optional request signing; do not disable those checks to make
an import succeed. Preserve the request's generated ID reference for the workload.

## Add requests to an environment

Read each file with `os.ReadFile` and handle the error. Given those bytes:

```go
updated, err := contract.WithRetrievableSecrets(environment, "ccrv",
    contract.RetrievableSecretsOptions{
        Requests: []contract.RetrievableSecretRequest{
            {Data: databaseRequest, Certificate: requestVerificationCert},
            {Data: apiTokenRequest},
        },
        Hosts: map[string]contract.HostKeyDocument{
            "HKD-9175-0271A28": {
                Description: "Primary deployment host",
                Data: primaryHKD,
            },
            "HKD-9175-0271A29": {
                Description: "Second deployment host",
                Data: secondHKD,
            },
        },
    })
if err != nil {
    return err
}
```

The input must be one raw `type: env` document with its normal required fields,
including logging. Logging, registry authentication, environment variables and
volume declarations are preserved. The helper rejects an existing `uv-secrets`
block rather than reassigning its indices. If an environment already contains
the intended `host-attestation` block, leave `options.Hosts` empty to preserve
and validate those documents. Supplying both existing hosts and new host options
returns an error; existing documents are never silently replaced. Edit existing
request configurations explicitly in YAML and validate with `HpcrVerifyContract`.

The first request becomes `index-1`, the second `index-2`, and so on, up to eight
requests. Omitting `Lock` in Go writes `lock: true`. An explicit `*bool` pointing
to `false` writes `lock: false`. Locking prevents further additions to the store;
it does not prevent retrieval by the SE guest.

In hand-written YAML, `lock` may be omitted; the runtime's documented default is
true. Validation does not insert defaults or otherwise modify the input.

## Make IDs available before authoring sections

The actual secret ID can be read as soon as the trusted preparation step has
created a binary request:

```go
info, err := contract.InspectPreparedSecretRequest(requestBytes)
if err != nil {
    return err
}
// After trusted tooling has verified the request, persist info.SecretID and
// info.RequestSHA256 with its immutable prepared version. Give section authors
// the required ID/reference, never the plaintext secret or private keys.
```

The result contains the request version, numeric UV secret type, the complete
32-byte `0x`-prefixed ID and the request's SHA-256. These are unverified header
claims. Inspection does not verify the request signature, GCM authentication,
host trust or guest binding. A modified encrypted payload may retain the same
claimed ID; trust must come from the preparation/signature-verification process.

On final import, bind the request to the ID already selected for the build:

```go
request := contract.RetrievableSecretRequest{
    Data:             requestBytes,
    Certificate:      requestVerificationCert,
    ExpectedSecretID: idPinnedDuringPreparation,
}
```

`ExpectedSecretID` accepts 64 hex digits, optionally prefixed by `0x`, without
surrounding whitespace. A mismatch or malformed ID returns an error and no
environment YAML. Leaving it empty retains the original opaque-request API.

Keep four identifiers separate:

| Identifier | Meaning |
| --- | --- |
| Catalog UUID / alias | Application reference to an encrypted stored value/version; never a UV ID. |
| UV secret ID | Embedded 32-byte identity used by guest retrieval tooling. |
| `index-N` | Position of a prepared request within this contract; used by volume references. |
| Request SHA-256 | Checksum of the particular encrypted request, not of its secret value. |

Read the embedded ID rather than hashing a catalog alias. The default `pvsecret`
name hash and the `--use-name` mode produce different IDs. Use unique versioned
request names/IDs for rotation; a new ciphertext or IV does not create a new ID.
Validation rejects repeated request bytes and repeated IDs in inspectable
listable-secret layouts, including requests with distinct ciphertext bytes.
It does not authenticate those IDs or otherwise replace runtime verification.
Null and Update-CCK requests have no listable ID and cannot be inspected or
imported with an expected ID.

## Contract layout and volume references

The resulting environment has this structure. Replace all angle-bracket values
with actual Base64 data; this illustration is not a deployable contract:

```yaml
type: env
logging:
  # Keep your existing logging provider configuration here.
uv-secrets:
  lock: true
  index-1:
    type: pvsecret
    pvsecret: <Base64 of binary request 1>
    pvsecret-crt: <Base64 of optional request verification certificate>
  index-2:
    type: pvsecret
    pvsecret: <Base64 of binary request 2>
host-attestation:
  HKD-9175-0271A28:
    description: Primary deployment host
    host-key-doc: <Base64 of HKD file>
volumes:
  data:
    uv-secret-id: index-1
    uv-previous-secret-id: index-2
```

The volume schema already supports `uv-secret-id` and `uv-previous-secret-id`.
Both must reference requests declared in this environment. The previous-secret
field requires a current-secret field. A volume's current `seed` and
`uv-secret-id` are alternatives. When validating a complete contract, a
UV-backed environment volume must also have a matching workload volume
declaration. Keep that workload volume's own seed and mount settings according
to the target runtime's volume configuration. A standalone environment cannot
prove what its future workload section will declare.

Do not replace seeds or reassign indices on an existing data disk without a
separate migration plan. A valid reference proves only that the request exists;
the runtime still needs the appropriate secret for the requested volume use.

For non-volume secrets, the application retrieves the secret inside the SE guest
using the generated secret-ID reference and the runtime's retrieval tooling.
The contract does not automatically create an application environment variable.
Plaintext retrieval can be consumed directly from standard output, for example
`pvsecret retrieve --inform hex <ID> --outform bin`; no intermediate secret file
is required. Do not log that output. Protected-key types return protected/wrapped
objects rather than the original key bytes, as defined by the target runtime.

Catalog/build roles are enforced by the platform, not this library. UV isolation
is per guest, not per catalog entry or container role. Knowing an ID is not an
authorization mechanism. Per-workload restrictions require control of `/dev/uv`
access or a suitable guest-side broker; do not expose unrestricted device access
to a workload and assume the UI's catalog grants will constrain its retrieval.

## Platform integration boundary

| Stage | Responsible component | contract-go support |
| --- | --- | --- |
| Store neutral secret versions and groups; share within allowed personas | Manager/UI and isolated value worker | No catalog database, persona checks or plaintext reveal API in this library. |
| Assigned Auditor commits a selected version using the intended SE header and verified HKDs | Trusted `pvsecret` preparation worker | Accepts the resulting binary request; does not generate one from plaintext. |
| Publish/pin public IDs before workload/environment authoring | Manager | `InspectPreparedSecretRequest`; retain trusted metadata with the prepared version. |
| Add requests, hosts, locking and volume references | Manager contract adapter | `WithRetrievableSecrets`, optional expected IDs and existing host reuse; standalone/complete validation. |
| Encrypt and sign; export the contract | Existing contract workflow | Existing signing/encryption APIs preserve requests and unrelated configuration. |
| Import, lock and retrieve/use inside the guest | Supported runtime, Ultravisor and workload tooling | No host discovery, UV device operations or software fallback disguised as hardware support. |

## Validation and encryption

Use the existing API for either workflow:

```go
err := contract.HpcrVerifyContract(updated, "ccrv", contract.SectionEnv)
// Or validate the complete wrapped workload+env contract:
err = contract.HpcrVerifyContract(plaintextContract, "ccrv", contract.SectionBoth)
```

Validation checks:

- The original platform schema in both individual and complete validation.
- One YAML document, string mapping keys, duplicate keys (including aliases),
  required fields and field types. Keys are checked before decoding can coerce
  them or overwrite another value. Valid scalar aliases and YAML merges remain
  supported; explicit values may override merged defaults.
- One to eight sequential request indices starting at `index-1`.
- Boolean `lock`, `type: pvsecret`, required request bytes and unknown fields.
- Duplicate binary requests and repeated IDs in inspectable listable layouts.
- Strict Base64 decoding, ASRCB magic, supported request-header versions
  `0x0100`/`0x0200`, declared lengths, user-data kinds and room for key slots.
- Required host documents, HKD identifiers and parseable certificates.
- Current and previous volume references and, when available, workload declarations.

The 8190-byte limit in IBM's documentation applies to the original plaintext
secret file, **not** the binary request or its Base64 encoding. The library
does not interpret secret-specific header fields or decrypt the payload. Secret
type and key-length checks remain with trusted preparation tools and the runtime;
the exact plaintext length is inside the encrypted, padded plaintext payload.

After validation, use `HpcrContractSignedEncrypted` or the existing individual
section encryption functions. The full environment, including requests and
HKDs, travels in the existing encrypted contract. No separate secret database
or additional encryption format is introduced.

If sections were encrypted separately, `HpcrContractSign` checks a single YAML
document with nonempty string `env` and `workload` values before signing. Missing,
null or incorrectly typed sections return an error. A provided
`attestationPublicKey` must be a string; it is never silently dropped for a type
mismatch. The same original-key and duplicate-alias checks apply to this path.

The encryption regression checks also cover existing binary handling: generated
passwords retain 32 random bytes in a line-safe Base64 representation, and RSA/AES
ciphertext is written without trimming bytes. Plaintext section bytes are also
preserved, including meaningful spaces and line breaks in YAML block scalars.
Decryption recognizes OpenSSL salted AES-CBC payloads with either an 8-byte or
16-byte salt; the latter requires OpenSSL's `-saltlen` option (3.2 or later).
Existing encrypted inputs continue to use their stored password; they are not
re-encoded during decryption.

Contract validation checks structure. It does **not** authenticate an HKD chain,
verify the request's user signature, decrypt the request, or prove the request
matches the target image/host. Trusted preparation tooling and the target
runtime/Ultravisor perform those checks. In particular, a parseable request
certificate is not evidence of a valid request signature. Expired request
certificates are not rejected here: IBM documents a runtime warning for that
case rather than shutting down the running guest.

## Platform and hardware boundary

The prepared-request contract feature is enabled for `ccrv`. New `uv-secrets`
blocks are rejected for `ccrt`, `hpvs`, `ccco` and the default CCRT platform.
Existing CCCO host-attestation support and other contract formats are preserved.

IBM currently documents this flow for an IBM z17 with current firmware,
RHEL 9.6 and s390utils 2.36 or later. The `platform` argument selects a contract
profile; it does not detect firmware, guest OS or runtime release. Selecting a
runtime encryption certificate does not establish those capabilities either.
Contract creation and structural tests can run on a development workstation.

### What is gated, and where

| Operation | Required support | Behavior when unsupported |
| --- | --- | --- |
| Offline prepared-request import into a contract | CCRV profile and a supported ASRCB envelope version/user-data layout | Returns the explicit errors below; no output contract or fallback profile. |
| Offline request inspection | Supported binary header layout | Returns an error and zero metadata for unsupported versions/layouts; no OpenSSL or UV device is needed. |
| Outer AES encryption/decryption | Configured executable advertises `enc -pbkdf2`; 16-byte salt decryption also needs `-saltlen` | Returns an actionable OpenSSL capability error before attempting the cipher command; never removes required options. |
| Native Add/List/Lock/Retrieve | Actual target guest, kernel, firmware/UV and secret-type support | Not executed by contract-go. The component invoking `pvsecret` must perform the target preflight described below. |

Library errors include:

| Error prefix | Action |
| --- | --- |
| `UNSUPPORTED_CONTRACT_PLATFORM` | Use a recognized contract profile; the message lists them. |
| `RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM` | This prepared-secret format requires `ccrv`; an empty argument still means the default CCRT profile. |
| `RETRIEVABLE_SECRETS_UNSUPPORTED_REQUEST_VERSION` | Supply a prepared ASRCB V1/V2 request; a later format needs explicit library support. |
| `RETRIEVABLE_SECRETS_UNSUPPORTED_USER_DATA_TYPE` | Use a supported `pvsecret` user-data format; unknown types are rejected. |
| `OPENSSL_UNSUPPORTED_FEATURE` | Install a build with the named option or select it through `OPENSSL_BIN`; 16-byte salts need OpenSSL 3.2+. |
| `OPENSSL_CAPABILITY_CHECK_FAILED` | Fix the executable/configuration so its options can be inspected. |

Unsupported profiles are rejected by the builder and the raw/complete contract
validators. Full signed/encrypted contract APIs validate before accessing keys
or invoking OpenSSL. Generic text-encryption/sign-only APIs do not establish
contract semantics or target compatibility and must not be used as a deployment
support check.

These PRs contain **no native UV execution API**. Do not gate offline preparation
on the workstation's CPU model: it is valid to prepare a remote z17 contract on
a Mac. Conversely, successful preparation or metadata inspection must never
enable native secret operations automatically.

Before invoking a native command, the guest-side worker must obtain current
capabilities from the actual target. Reject an unavailable/failed probe rather
than assuming support. Check SE-guest status and device access, both the kernel
and UV support for the requested operation, and the requested secret type/request
version. For Add also check capacity and whether the store is locked. An SE host
is not an SE guest; Add/List/Lock support does not imply retrievable-type or
Retrieve support. A new `pvsecret` executable, a valid certificate or a machine
model alone proves none of those capabilities. These are requirements for the
component executing native commands, not checks performed by this offline
library. Any development emulation must remain explicit and must not convert
an unsupported native operation into reported hardware success.

On supported hardware, separately verify: boot the intended protected image,
confirm successful request import, retrieve each secret using its ID reference,
and check the result inside the guest. Compare plaintext secrets with a known
disposable test value; for protected keys, verify the intended cryptographic
operation without expecting the original key bytes to be exposed. Check that
locking blocks further additions while retrieval still works. Repeat with a
request created for a different guest/header or untrusted host and confirm it
is rejected. These checks are required before claiming hardware verification.

## References

- [IBM CCRV retrievable secrets](https://www.ibm.com/docs/en/ccrv/1.1.x?topic=solutions-retrievable-secret)
- [s390-tools ASRCB layouts](https://github.com/ibm-s390-linux/s390-tools/blob/master/rust/pv/src/uvsecret/asrcb.rs)
- [s390-tools generic request header](https://github.com/ibm-s390-linux/s390-tools/blob/master/rust/pv/src/req/header.rs)
- [s390-tools request verification](https://github.com/ibm-s390-linux/s390-tools/blob/master/rust/pv/src/uvsecret/user_data.rs)
- [s390-tools classical and hybrid HKD formats](https://github.com/ibm-s390-linux/s390-tools/blob/master/rust/utils/src/hkd.rs)
- [Pinned listable-secret header layout](https://github.com/ibm-s390-linux/s390-tools/blob/b1d612b4a6a84440e16aae6d66e5f8f4be4e977f/rust/pv/src/uvsecret/guest_secret.rs)
- [OpenSSL salted encryption and salt-length options](https://docs.openssl.org/3.2/man1/openssl-enc/)
