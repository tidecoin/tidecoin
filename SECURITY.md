# Security Policy

## Supported Versions

The latest release on the `master` branch is supported with security updates.

| Version | Supported |
|---------|-----------|
| v1.0.0  | Yes       |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

### Preferred: GitHub Private Vulnerability Reporting

Use GitHub's built-in private vulnerability reporting:

1. Go to the [Security tab](https://github.com/tidecoin/tidecoin/security)
2. Click "Report a vulnerability"
3. Fill in the details

This is the fastest way to reach us and keeps the report confidential.

### Alternative: Encrypted Email

Send an email to **falcon1024@protonmail.com** (not for general support).

Proton Mail provides post-quantum encrypted email (ML-KEM + X25519).
If you are also using Proton Mail, end-to-end PQ encryption is automatic.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and disclosure**: coordinated with the reporter

## Scope

This policy covers the Tidecoin node software (`tidecoind`, `tidecoin-qt`,
`tidecoin-cli`, `tidecoin-wallet`, `tidecoin-tx`, `tidecoin-util`), including:

- Post-quantum signature schemes (Falcon-512/1024, ML-DSA-44/65/87)
- PQHD wallet key derivation
- ML-KEM-512 P2P transport encryption
- Consensus and validation logic
- RPC interface
