# JWT Toolkit

A command-line toolkit for inspecting, verifying, cracking, and securing JSON Web Tokens — built to expose how JWT signing works and where it breaks.

Use it to audit tokens for misconfigurations, verify signatures and standard claims (including JWKS), brute-force weak HMAC secrets against a wordlist, forge defensive attack-shaped variants for self-audit, and generate cryptographically strong secrets.

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

# Static security audit (no key needed) — flags alg=none, weak HMAC, jwk-in-header, etc.
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

| Command              | Purpose                                                                         |
| -------------------- | ------------------------------------------------------------------------------- |
| `decode`             | Decode a JWT and pretty-print its header and payload.                           |
| `sign`               | Mint a new JWT signed with an HMAC secret or an asymmetric key.                 |
| `audit`              | Static security analysis of a JWT — no key required. CVE-referenced findings.  |
| `verify`             | Verify the signature and standard claims of a JWT (supports JWKS).              |
| `forge`              | Emit defensive attack-shaped variants of a JWT for self-audit.                  |
| `crack`              | Brute-force a weak HMAC secret using a wordlist.                                |
| `generate-secret`    | Emit a cryptographically strong random secret.                                  |
| `download-wordlists` | Fetch the latest common-secrets wordlist.                                       |

## Scripting

Suppress the banner and color output for clean machine-readable runs:

```bash
jwt-toolkit --quiet audit <token> --json
JWT_TOOLKIT_QUIET=1 NO_COLOR=1 jwt-toolkit audit <token> --json
```

## Use responsibly

`jwt-toolkit` is built for defensive work — auditing your own tokens, hardening your own systems, and learning how JWTs break. Only use it against tokens and systems you are authorized to test.

## License

[MIT](./LICENSE) © Khaled Saeed
