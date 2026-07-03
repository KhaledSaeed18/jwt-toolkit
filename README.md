# JWT Toolkit

<p align="center">
  <a href="https://pypi.org/project/jwt-toolkit/"><img src="https://raw.githubusercontent.com/KhaledSaeed18/jwt-toolkit/main/assets/images/demo.jpg" alt="jwt-toolkit demo" width="820"></a>
</p>

<p align="center">
  <a href="https://pypi.org/project/jwt-toolkit/"><img alt="PyPI version" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fpypi.org%2Fpypi%2Fjwt-toolkit%2Fjson&amp;query=%24.info.version&amp;label=PyPI&amp;prefix=v&amp;variant=secondary&amp;logo=pypi"></a>
  <a href="https://pypi.org/project/jwt-toolkit/"><img alt="Python 3.13+" src="https://shieldcn.dev/badge/Python-3.13%2B.svg?variant=secondary&amp;logo=python"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/actions/workflows/ci.yml"><img alt="CI status" src="https://shieldcn.dev/github/ci/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/LICENSE"><img alt="License: MIT" src="https://shieldcn.dev/github/license/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/stargazers"><img alt="GitHub stars" src="https://shieldcn.dev/github/stars/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
</p>

A command-line toolkit for inspecting, verifying, cracking, and securing JSON Web Tokens. Built to expose how JWT signing works and where it breaks.

Use it to audit tokens for misconfigurations, verify signatures and standard claims (including JWKS), brute-force weak HMAC secrets against a wordlist, forge defensive attack-shaped variants for self-audit, and generate cryptographically strong secrets.

- **Decode** any JWT and pretty-print its header, payload, and signature.
- **Audit** tokens with no key required, flagging `alg=none`, weak HMAC, `jwk`-in-header, and other CVE-referenced misconfigurations.
- **Verify** signatures and standard claims (`exp`, `nbf`, `iat`, `iss`, `aud`), including remote JWKS.
- **Sign** new tokens with an HMAC secret or an asymmetric key.
- **Forge** attack-shaped variants (`alg=none`, algorithm confusion) so you can test your own verifier.
- **Crack** weak HMAC secrets against a wordlist, streamed line-by-line.
- **Generate** cryptographically strong random secrets.

Built on `cryptography` with constant-time signature comparison, no runtime dependency on `pyjwt` or `python-jose` — the JWS logic is implemented in the open so you can read exactly how verification works.

## Installation

`jwt-toolkit` is a command-line tool, so the recommended way to install it is with [pipx](https://pipx.pypa.io), which installs CLI tools into isolated environments:

```bash
pipx install jwt-toolkit
```

Or with pip / uv:

```bash
pip install jwt-toolkit
# or
uv tool install jwt-toolkit
```

Requires Python 3.13+.

## Quick start

```bash
# Decode and pretty-print a token
jwt-toolkit decode <token>

# Static security audit (no key needed) flags alg=none, weak HMAC, jwk-in-header, etc.
jwt-toolkit audit <token>
jwt-toolkit audit <token> --strict --json

# Verify signature + standard claims (exp, nbf, iat, iss, aud)
jwt-toolkit verify <token> --secret <secret> --issuer auth.example.com
jwt-toolkit verify <token> --jwks-url https://auth.example.com/.well-known/jwks.json

# Mint a JWT (HMAC or asymmetric)
jwt-toolkit sign --payload '{"sub":"1"}' --secret mysecret

# Generate defensive attack-shaped variants of a token (alg=none, alg confusion, etc.)
jwt-toolkit forge <token> --public-key key.pub.pem

# Brute-force a weak HMAC secret against a wordlist
jwt-toolkit crack <token> wordlists/common-secrets.txt --threads 8

# Generate a strong random secret
jwt-toolkit generate-secret --bits 256 --encoding base64

# Fetch the bundled common-secrets wordlist
jwt-toolkit download-wordlists --output-dir wordlists
```

Run `jwt-toolkit COMMAND --help` for command-specific options.

## Commands

| Command              | Purpose                                                                        |
| -------------------- | ------------------------------------------------------------------------------ |
| `decode`             | Decode a JWT and pretty-print its header and payload.                          |
| `sign`               | Mint a new JWT signed with an HMAC secret or an asymmetric key.                |
| `audit`              | Static security analysis of a JWT, no key required. CVE-referenced findings.   |
| `verify`             | Verify the signature and standard claims of a JWT (supports JWKS).             |
| `forge`              | Emit defensive attack-shaped variants of a JWT for self-audit.                 |
| `crack`              | Brute-force a weak HMAC secret using a wordlist.                               |
| `generate-secret`    | Emit a cryptographically strong random secret.                                 |
| `download-wordlists` | Fetch the latest common-secrets wordlist.                                      |

## Examples

A few showcases of what the output looks like. Tokens here are throwaway test tokens, never use these secrets in production.

### Sign a token

Input:

```bash
jwt-toolkit sign \
  --payload '{"sub":"alice","role":"admin","iat":1700000000}' \
  --secret mysecret123
```

Output:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.cPIGduvFlZtf6Xa3HFDkf8sV7v_8O5fn7_vW7-D1_0c
```

### Decode a token

Input:

```bash
jwt-toolkit decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.cPIGduvFlZtf6Xa3HFDkf8sV7v_8O5fn7_vW7-D1_0c
```

Output:

```
╭─────────────────── Header ────────────────────╮
│ {                                             │
│   "alg": "HS256",                             │
│   "typ": "JWT"                                │
│ }                                             │
╰───────────────────────────────────────────────╯
╭─────────────────── Payload ───────────────────╮
│ {                                             │
│   "sub": "alice",                             │
│   "role": "admin",                            │
│   "iat": 1700000000                           │
│ }                                             │
╰───────────────────────────────────────────────╯
╭────────────────── Signature ──────────────────╮
│ cPIGduvFlZtf6Xa3HFDkf8sV7v_8O5fn7_vW7-D1_0c   │
╰───────────────────────────────────────────────╯
```

### Audit a token

Input:

```bash
jwt-toolkit audit <token>
```

Output:

```
╭────────────── Security Verdict ──────────────╮
│ Verdict : WEAK                               │
│ Grade   : B                                  │
│                                              │
│ CRITICAL : 0   WARN : 2   INFO : 3   PASS : 2│
╰──────────────────────────────────────────────╯
                       Findings
┏━━━━━━━━━━┳───────┳────────────────────┳──────────────────────┓
┃ Severity ┃ Field ┃ Detail             ┃ Recommendation       ┃
┡━━━━━━━━━━╇───────╇────────────────────╇──────────────────────┩
│ WARN     │ alg   │ HS256 is symmetric │ Use a strong secret  │
│ WARN     │ exp   │ No exp claim       │ Always set exp       │
│ INFO     │ aud   │ Missing aud claim  │                      │
│ INFO     │ iss   │ Missing iss claim  │                      │
│ INFO     │ jti   │ No jti claim       │ Issue a unique jti   │
│ PASS     │ iat   │ iat looks sane     │                      │
│ PASS     │ typ   │ typ=JWT            │                      │
└──────────┴───────┴────────────────────┴──────────────────────┘
```

Add `--json` for machine-readable output and `--strict` to fail on warnings.

### Verify a token

Input:

```bash
jwt-toolkit verify <token> --secret mysecret123
```

Output:

```
              Verification Checks
┏━━━━━━━━┳───────────┳────────────────────┓
┃ Result ┃ Check     ┃ Detail             ┃
┡━━━━━━━━╇───────────╇────────────────────┩
│ PASS   │ signature │ Signature is valid │
│ WARN   │ exp       │ No expiry claim    │
└────────┴───────────┴────────────────────┘
╭──────────────────────────────────────────╮
│ VALID                                    │
╰──────────────────────────────────────────╯
```

### Generate a strong secret

Input:

```bash
jwt-toolkit generate-secret --bits 256 --encoding base64
```

Output:

```
╭──────────────── Generated Secret ────────────────╮
│ HTZhdhvS6GPEKeziu3Ey5d6NVf8da9mjjfQTFQD99o8=     │
│                                                  │
│ Encoding : base64                                │
│ Length   : 256 bits (32 bytes)                   │
│ Entropy  : 256 bits, strong                      │
╰──────────────────────────────────────────────────╯
```

### Crack a weak secret

Input:

```bash
jwt-toolkit crack <token> wordlists/common-secrets.txt --threads 8
```

Output:

```
╭──────────── Weak Secret Detected ────────────╮
│ Secret: mysecret123                          │
│                                              │
│ Algorithm        : HS256                     │
│ Position         : #1 of ~3 candidates       │
│ Candidates tried : 1                         │
│ Time elapsed     : 0.001s                    │
│                                              │
│ This secret is in a common wordlist.         │
│ Generate a strong one with:                  │
│   jwt-toolkit generate-secret                │
╰──────────────────────────────────────────────╯
```

## Scripting

Suppress the banner and color output for clean machine-readable runs:

```bash
jwt-toolkit --quiet audit <token> --json
JWT_TOOLKIT_QUIET=1 NO_COLOR=1 jwt-toolkit audit <token> --json
```

## Use responsibly

`jwt-toolkit` is built for defensive work: auditing your own tokens, hardening your own systems, and learning how JWTs break. Only use it against tokens and systems you are authorized to test.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/CONTRIBUTING.md) for the codebase layout, development setup, branch and commit conventions, and the pull-request workflow.

## License

[MIT](https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/LICENSE) © Khaled Saeed
