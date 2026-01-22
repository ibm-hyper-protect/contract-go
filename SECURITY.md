# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

We recommend always using the latest release to ensure you have the latest security updates.

## Reporting a Vulnerability

The `contract-go` team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### Please DO NOT:

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed

### Instead, Please:

**Report security vulnerabilities via GitHub Security Advisories:**

1. Go to the [Security tab](https://github.com/ibm-hyper-protect/contract-go/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the form with details about the vulnerability

**Or, report via email:**

Contact the project maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) directly with details about the vulnerability.

### What to Include in Your Report

To help us understand and address the issue quickly, please include:

- **Description** - A clear description of the vulnerability
- **Impact** - What an attacker could achieve by exploiting this vulnerability
- **Reproduction Steps** - Detailed steps to reproduce the issue
- **Affected Versions** - Which versions of the library are affected
- **Proposed Fix** - If you have suggestions for how to fix the issue (optional)
- **Your Contact Information** - So we can follow up with questions

### What to Expect

When you report a security vulnerability, here's what will happen:

1. **Acknowledgment** - We will acknowledge receipt of your vulnerability report within 3 business days

2. **Initial Assessment** - We will investigate and confirm the vulnerability within 5 business days

3. **Updates** - We will keep you informed about our progress addressing the issue

4. **Fix Development** - We will develop and test a fix for the vulnerability

5. **Release** - We will:
   - Release a patched version
   - Publish a security advisory
   - Credit you for the discovery (unless you prefer to remain anonymous)

### Timeline

We aim to:

- Acknowledge reports within **3 business days**
- Provide an initial assessment within **5 business days**
- Release a fix within **30 days** for high-severity issues
- Release a fix within **90 days** for medium/low-severity issues

These timelines may vary depending on the complexity of the issue.

## Security Best Practices

When using `contract-go`, we recommend:

### For Library Users

1. **Keep Dependencies Updated**
   - Regularly update to the latest version of `contract-go`
   - Monitor security advisories for this project

2. **Protect Sensitive Data**
   - Never commit private keys, certificates, or credentials to version control
   - Use environment variables or secure vaults for sensitive configuration
   - Ensure encryption certificates are obtained from trusted sources

3. **Validate Input**
   - Always validate contract schemas before processing
   - Use the provided validation functions (`HpcrVerifyContract`, `HpcrVerifyNetworkConfig`)

4. **Secure OpenSSL**
   - Use a recent, patched version of OpenSSL
   - Keep OpenSSL updated with the latest security patches

5. **Network Security**
   - Use HTTPS when downloading encryption certificates
   - Verify certificate downloads from trusted IBM Cloud endpoints

### For Contributors

1. **Code Review**
   - All code changes require review before merging
   - Pay special attention to cryptographic operations

2. **Dependency Management**
   - Regularly audit dependencies for known vulnerabilities
   - Keep dependencies up to date

3. **Testing**
   - Write tests that cover security-relevant code paths
   - Test error handling and edge cases

4. **Secrets in Tests**
   - Never use real credentials in test code
   - Use mock data and test fixtures

## Security-Related Configuration

### OpenSSL Path Configuration

If you need to use a specific OpenSSL binary:

```bash
export OPENSSL_BIN=/path/to/openssl
```

Ensure this path points to a trusted, updated OpenSSL installation.

### Certificate Sources

The library downloads encryption certificates from IBM Cloud by default:

```
https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/
```

Only modify the certificate download URL if you're using a trusted mirror or testing environment.

## Known Security Considerations

### Cryptographic Operations

This library performs cryptographic operations including:

- **RSA encryption/decryption** - Using OpenSSL pkeyutl (PKCS#1 v1.5)
- **AES-256-CBC encryption** - For contract data
- **SHA-256 hashing** - For integrity checking
- **Digital signatures** - For contract signing

These operations rely on:
- Proper OpenSSL installation and configuration
- Secure key generation and storage (user responsibility)
- Trusted encryption certificates from IBM Cloud

### Contract Expiry

When using contract expiry features:
- Certificates are generated with configurable expiration periods
- Ensure CA certificates and keys are stored securely
- Rotate CA keys according to your security policy

## Vulnerability Disclosure Policy

We believe in coordinated vulnerability disclosure:

1. **Report** - Security researchers report vulnerabilities privately
2. **Fix** - We develop and test a fix
3. **Release** - We release the patched version
4. **Disclose** - We publish a security advisory with credit to the researcher
5. **Public** - Full details are disclosed after users have time to update

We will not take legal action against security researchers who:
- Make a good faith effort to avoid privacy violations and data destruction
- Report vulnerabilities privately and give us reasonable time to respond
- Do not exploit vulnerabilities beyond what's necessary to demonstrate the issue

## Security Updates

Stay informed about security updates:

- **GitHub Security Advisories** - Watch this repository for security advisories
- **Releases** - Check the [Releases page](https://github.com/ibm-hyper-protect/contract-go/releases) for security patches
- **Changelog** - Review [CHANGELOG.md](CHANGELOG.md) for security-related changes

## Questions?

If you have questions about this security policy or the security of this project:

1. Review this document thoroughly
2. Check existing [security advisories](https://github.com/ibm-hyper-protect/contract-go/security/advisories)
3. Contact the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md)

---

Thank you for helping keep `contract-go` and our users safe!
