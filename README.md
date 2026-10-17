# JWT Toolkit

<p align="center">
  <a href="https://pypi.org/project/jwt-toolkit/"><img src="https://raw.githubusercontent.com/KhaledSaeed18/jwt-toolkit/main/assets/images/hero.png" alt="jwt-toolkit: audit flags a weak HS256 token, crack finds its secret in the bundled wordlist, and verify checks a strong token's signature and claims" width="900"></a>
</p>

<p align="center">
  <a href="https://pypi.org/project/jwt-toolkit/"><img alt="PyPI version" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fpypi.org%2Fpypi%2Fjwt-toolkit%2Fjson&amp;query=%24.info.version&amp;label=PyPI&amp;prefix=v&amp;variant=secondary&amp;logo=pypi"></a>
  <a href="https://pypi.org/project/jwt-toolkit/"><img alt="Python 3.13+" src="https://shieldcn.dev/badge/Python-3.13%2B.svg?variant=secondary&amp;logo=python"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/actions/workflows/ci.yml"><img alt="CI status" src="https://shieldcn.dev/github/ci/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/LICENSE"><img alt="License: MIT" src="https://shieldcn.dev/github/license/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
  <a href="https://github.com/KhaledSaeed18/jwt-toolkit/stargazers"><img alt="GitHub stars" src="https://shieldcn.dev/github/stars/KhaledSaeed18/jwt-toolkit.svg?variant=secondary"></a>
</p>

**Find the weak spots in your JSON Web Tokens before an attacker does.**

`jwt-toolkit` is a command-line tool for inspecting, auditing, verifying, and stress-testing JWTs. Point it at a token from your own system and it tells you what is wrong with it: a missing expiry, a guessable HMAC secret, a header that invites key confusion, a verifier that accepts `alg: none`. Every command has readable terminal output, and the ones you would script have a stable `--json` mode for CI.

The JWS logic is implemented in the open on top of [`cryptography`](https://cryptography.io), with no dependency on `pyjwt` or `python-jose`, so you can read exactly how a signature is checked.

## Contents

- [Features](#features)
- [Installation](#installation)
- [A two-minute tour](#a-two-minute-tour)
- [Commands](#commands)
  - [decode](#decode) · [audit](#audit) · [verify](#verify) · [diff](#diff) · [sign](#sign) · [forge](#forge) · [crack](#crack) · [generate-secret](#generate-secret) · [download-wordlists](#download-wordlists)
- [Passing tokens, keys, and secrets](#passing-tokens-keys-and-secrets)
- [Supported algorithms](#supported-algorithms)
- [Scripting and CI](#scripting-and-ci)
- [Security model](#security-model)
- [Use responsibly](#use-responsibly)
- [Contributing](#contributing) · [Security policy](#security-policy) · [License](#license)

## Features

| | |
| --- | --- |
| **Decode** | Pretty-print the header, payload, and signature, with `iat`/`nbf`/`exp` shown in UTC and relative to now. |
| **Audit** | Static analysis with no key required. Flags `alg: none`, weak HMAC use, embedded `jwk`, `jku`/`x5u` over HTTP, `kid` injection shapes, `crit` misuse, missing or excessive lifetimes, and PII in the payload, with CVE references and an A to F grade. |
| **Verify** | Signature plus `exp`, `nbf`, `iat`, `iss`, and `aud` checks against an HMAC secret, a PEM key, an X.509 certificate, or a JWKS endpoint. |
| **Diff** | Compare two tokens field by field, with JSON Pointer paths and identity, permission, and lifetime fields highlighted. |
| **Sign** | Mint test tokens with HMAC, RSA, RSA-PSS, ECDSA, or EdDSA keys, including encrypted private keys, payload files, and lifetimes such as `--expires-in 15m`. |
| **Forge** | Generate attack-shaped variants of a token (`alg: none`, algorithm confusion, tampered payloads) to check that your verifier rejects them. |
| **Crack** | Test an HMAC secret against a wordlist across worker processes. A curated list ships with the package. |
| **Generate** | Produce cryptographically strong secrets, raw for scripts or formatted for humans. |

## Installation

`jwt-toolkit` is a command-line tool, so install it into its own environment with [pipx](https://pipx.pypa.io) or [uv](https://docs.astral.sh/uv/):

```bash
pipx install jwt-toolkit
# or
uv tool install jwt-toolkit
```

To try it without installing:

```bash
uvx jwt-toolkit --help
```

`pip install jwt-toolkit` also works inside a virtual environment. Requires Python 3.13 or newer.

## A two-minute tour

```bash
# 1. Create a strong secret and keep it out of your shell history
jwt-toolkit generate-secret --raw > hs256.secret

# 2. Mint a token that expires in 15 minutes
TOKEN=$(jwt-toolkit sign --payload '{"sub":"alice","iss":"auth.example.com","aud":"api"}' \
  --secret-file hs256.secret --expires-in 15m)

# 3. Look inside it
jwt-toolkit decode "$TOKEN"

# 4. Check it for misconfigurations, no key needed
jwt-toolkit audit "$TOKEN"

# 5. Verify the signature and claims the way your API should
jwt-toolkit verify "$TOKEN" --secret-file hs256.secret --issuer auth.example.com --audience api

# 6. Make sure the secret is not in a common wordlist
jwt-toolkit crack "$TOKEN"
```

Run `jwt-toolkit` on its own for an overview, or `jwt-toolkit COMMAND --help` for every option of a command.

## Commands

| Command | What it answers |
| --- | --- |
| [`decode`](#decode) | What is inside this token? |
| [`audit`](#audit) | Is this token configured safely? |
| [`verify`](#verify) | Is this token authentic and currently acceptable? |
| [`diff`](#diff) | What changed between these two tokens? |
| [`sign`](#sign) | Can I mint a token for testing? |
| [`forge`](#forge) | Does my verifier reject known attack shapes? |
| [`crack`](#crack) | Is this HMAC secret guessable? |
| [`generate-secret`](#generate-secret) | What should the secret be instead? |
| [`download-wordlists`](#download-wordlists) | Where do I get the wordlist as a file? |

Each command reads the token from an argument, a file, or stdin. See [Passing tokens, keys, and secrets](#passing-tokens-keys-and-secrets).

### decode

Decodes a token without verifying it and prints the header, payload, and signature. When the payload has `iat`, `nbf`, or `exp`, a **Time Claims** table shows each value in UTC and relative to now, and flags values that are not valid NumericDates.

```bash
jwt-toolkit decode <token>
jwt-toolkit decode @token.jwt --json
```

| Option | Description |
| --- | --- |
| `--json` | Print `{schema_version, header, payload, signature}` with raw values. |

Decoding is not verification: anyone can write any claims into a token. Use [`verify`](#verify) before trusting the contents.

### audit

Runs static checks against the header and payload and grades the token. No key is needed. Add `--secret`, `--secret-file`, or `--public-key` to include a signature check in the same report.

```bash
jwt-toolkit audit <token>
jwt-toolkit audit <token> --strict --require iss,aud --json
```

```
╭────────────────────────────── Security Verdict ──────────────────────────────╮
│ Verdict : WEAK                                                               │
│ Grade   : B                                                                  │
│                                                                              │
│ CRITICAL : 0   WARN : 2   INFO : 3   PASS : 2                                │
╰──────────────────────────────────────────────────────────────────────────────╯
                                    Findings
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity   ┃ Field          ┃ Detail                ┃ Recommendation         ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ WARN       │ alg            │ HS256 is symmetric —  │ Use a                  │
│            │                │ the shared secret     │ cryptographically      │
│            │                │ must be strong or it  │ strong secret          │
│            │                │ can be brute-forced   │ (jwt-toolkit           │
│            │                │                       │ generate-secret) or    │
│            │                │                       │ migrate to an          │
│            │                │                       │ asymmetric algorithm.  │
├────────────┼────────────────┼───────────────────────┼────────────────────────┤
│ WARN       │ exp            │ No exp claim — token  │ Always set exp;        │
│            │                │ never expires         │ short-lived tokens     │
│            │                │                       │ limit blast radius if  │
│            │                │                       │ leaked.                │
└────────────┴────────────────┴───────────────────────┴────────────────────────┘
```

| Option | Description |
| --- | --- |
| `--strict` | Treat WARN findings as failures (exit 1). |
| `--require CLAIMS` | Comma-separated claims that must be present, such as `iss,aud,sub`. Each missing one is a WARN finding. |
| `--secret`, `--secret-file` | Also verify an HMAC signature. |
| `--public-key FILE` | Also verify an asymmetric signature with a PEM key or X.509 certificate. |
| `--json` | Print the full report, including every finding and its recommendation. |

**What it checks**

| Area | Findings |
| --- | --- |
| Algorithm | `alg: none` in any casing (CRITICAL, CVE-2015-2951); non-registered spellings such as `hs256`; symmetric algorithms that depend on secret strength; unknown or missing `alg`; the deprecated `EdDSA` name. |
| Key smuggling | `jwk` embedded in the header (CRITICAL, CVE-2018-0114); `jku` or `x5u` over plain HTTP (CRITICAL) or pointing at external keys (WARN); HMAC combined with key-bearing headers, the HS/RS confusion shape (CRITICAL, CVE-2016-10555). |
| Header parameters | `kid` containing path traversal, SQL, or command injection sequences; non-string `kid`; `crit` that is malformed or lists missing parameters; non-boolean `b64`; unexpected `typ`. |
| Lifetime | Missing `exp`; expired tokens; `nbf` in the future; `iat` in the future or implausible; very long lifetimes; non-numeric time claims. |
| Claims | Missing `iss`, `aud`, `iat`, or `jti` (INFO), and any claim named in `--require` (WARN). |
| Payload contents | Sensitive field names such as `password` or `secret`; email addresses; Luhn-valid card numbers anywhere in nested data. |

**Grades**: any CRITICAL finding gives **F**, three or more WARN give **C**, one or two WARN give **B**, otherwise **A**.

**Exit codes**: `0` grade A to C, `1` grade F, a failed signature check, or WARN findings under `--strict`, `2` invalid input.

### verify

Checks the signature, then the registered claims. The algorithm must match the key you supply, so an RS256 public key never verifies an HS256 token, and `alg: none` is always rejected.

```bash
jwt-toolkit verify <token> --secret-file hs256.secret --issuer auth.example.com --audience api
jwt-toolkit verify <token> --public-key public.pem
jwt-toolkit verify <token> --public-key cert.pem --leeway 30
jwt-toolkit verify <token> --jwks-url https://auth.example.com/.well-known/jwks.json --json
```

| Option | Description |
| --- | --- |
| `--secret`, `--secret-file` | HMAC secret for `HS*` tokens. |
| `--public-key FILE` | PEM public key or X.509 certificate for `RS*`, `PS*`, `ES*`, and `Ed*` tokens. |
| `--jwks-url URL` | JWKS endpoint (`https://`, `http://`, or `file://`). The token's `kid` selects the key, and its `kty`, `crv`, and `alg` must match the token. |
| `--issuer`, `--audience` | Expected `iss` and `aud`. `aud` may be a string or a list. |
| `--leeway SECONDS` | Clock-skew tolerance for `exp` and `nbf`. |
| `--json` | Print `{schema_version, valid, checks[]}`. |

Checks performed: signature; `crit` (rejected, since no extensions are supported); `exp` (a token is expired at its `exp` second); `nbf`; `iat` not in the future; and `iss`/`aud` when requested. Time claims must be finite numbers.

**Exit codes**: `0` valid, `1` invalid, `2` unusable input, key, or options.

### diff

Compares two tokens and reports added, removed, and changed fields in the header and payload. Paths are JSON Pointers such as `/roles/0`, arrays are compared in order, and JSON types stay distinct, so `1`, `1.0`, and `true` are different values. Neither token is verified.

```bash
jwt-toolkit diff @before.jwt @after.jwt
jwt-toolkit diff "$OLD" "$NEW" --json --exit-code
```

```
                            Changed Fields
┏━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃   ┃ Section ┃ Path     ┃ Change  ┃ Before     ┃ After               ┃
┡━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ ! │ payload │ /roles/0 │ changed │ "user"     │ "admin"             │
├───┼─────────┼──────────┼─────────┼────────────┼─────────────────────┤
│ ! │ payload │ /exp     │ changed │ 2000000000 │ 2000086400          │
├───┼─────────┼──────────┼─────────┼────────────┼─────────────────────┤
│   │ payload │ /email   │ added   │ (absent)   │ "alice@example.com" │
└───┴─────────┴──────────┴─────────┴────────────┴─────────────────────┘
╭───────────────────────────────── Token Diff ─────────────────────────────────╮
│ Tokens differ                                                                │
│                                                                              │
│ Field changes : 3 (2 notable)                                                │
│ Signature     : changed                                                      │
│ Neither token was verified. This compares contents only.                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Rows marked `!` are identity, audience, lifetime, permission, or key-selection fields. The summary also says when only the serialization changed, for example reordered keys with the same values.

| Option | Description |
| --- | --- |
| `--json` | Print `{schema_version, verified, identical, signature_changed, header_encoding_changed, payload_encoding_changed, changes[]}`. |
| `--exit-code` | Exit 1 when the tokens differ, like `git diff --exit-code`. |

Only one of the two arguments may be `-` (stdin).

### sign

Mints a token for tests and fixtures. The header always declares the algorithm that was used.

```bash
jwt-toolkit sign --payload '{"sub":"1"}' --secret-file hs256.secret
jwt-toolkit sign --payload-file fixture.json --private-key private.pem --alg RS256 --expires-in 15m
echo '{"sub":"1"}' | jwt-toolkit sign --payload-file - --private-key ed25519.pem --alg Ed25519
```

| Option | Description |
| --- | --- |
| `--payload JSON` / `--payload-file FILE` | The payload as a JSON object. Pass exactly one; `--payload-file -` reads stdin. |
| `--expires-in DURATION` | Set `iat` to now and `exp` to now plus the duration: `30s`, `15m`, `1h`, `7d`, or `2w`. Refuses to overwrite an `iat` or `exp` already in the payload. |
| `--secret`, `--secret-file` | HMAC secret for `HS*`. |
| `--private-key FILE` | PEM private key (PKCS#8 or traditional) for `RS*`, `PS*`, `ES*`, and `Ed*`. |
| `--passphrase-file FILE` | Passphrase for an encrypted private key. Without it, you are prompted on a terminal; non-interactive runs fail instead of hanging. |
| `--alg ALG` | Signing algorithm, `HS256` by default. |
| `--header JSON` | Replace the default `{"alg": ..., "typ": "JWT"}` header. |

The token is printed on its own line, so `$(jwt-toolkit sign ...)` captures it cleanly.

### forge

Builds attack-shaped variants of a token you own. Send each one to your API: **every variant should be rejected**. A variant that is accepted points to a real verification flaw.

```bash
jwt-toolkit forge <token>
jwt-toolkit forge <token> --public-key public.pem --json
jwt-toolkit forge <token> --mode alg_none_lower
```

| Variant | What a correct verifier must do | Reference |
| --- | --- | --- |
| `alg_none_lower`, `alg_none_upper`, `alg_none_mixed` | Reject unsigned tokens in any casing of `none`. | CVE-2015-2951 |
| `empty_signature` | Reject a token whose signature was removed. | |
| `tampered_payload` | Recompute the signature instead of trusting the claims. | |
| `hs_rs_confusion` | Never verify HMAC with a public key. Needs `--public-key`. | CVE-2016-10555 |
| `kid_path_traversal`, `kid_sql_injection` | Never build file paths or SQL from `kid`. | |
| `jku_attacker` | Never fetch keys from an unpinned `jku`. | |
| `jwk_embedded` | Never trust a key supplied in the token header. | CVE-2018-0114 |

The last four are **header-only**: they keep the original signature, so a rejection shows the header was handled but does not prove the flaw is absent. The output marks them.

### crack

Tries every line of a wordlist as the HMAC secret. Use it on your own tokens to prove a secret is guessable, and replace any secret it finds.

```bash
jwt-toolkit crack <token>                              # bundled common-secrets list
jwt-toolkit crack <token> rockyou.txt --workers 8
jwt-toolkit crack <token> keys.txt --encoding all --output found.txt
```

```
╭──────────────────────────── Weak Secret Detected ────────────────────────────╮
│ Secret: supersecret                                                          │
│                                                                              │
│ Algorithm        : HS256                                                     │
│ Position         : #107 of ~313 candidates                                   │
│ Candidates tried : 107                                                       │
│ Time elapsed     : 0.001s                                                    │
│ Average rate     : 107.7k c/s                                                │
│                                                                              │
│ This secret is in a common wordlist — it is not safe.                        │
│ Generate a strong secret with: jwt-toolkit generate-secret                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

| Option | Description |
| --- | --- |
| `WORDLIST` | Path to a wordlist. Without it, the curated list bundled with the package is used. |
| `--workers N` | Worker processes, 1 to 64, default 4. Lists under 50,000 candidates run in one process. `--threads` is accepted as an alias. |
| `--encoding` | Treat each line as `utf-8` text, `hex`, `base64`, or try `all` three. |
| `--output FILE` | Write a found secret to a file. |

Wordlists are streamed, so multi-gigabyte lists are fine. Each line is tried exactly as written: only the line ending and a leading byte-order mark are removed, so secrets with spaces or a leading `#` are found.

**Exit codes**: `1` the secret was found (the token is weak), `0` the list was exhausted, `2` invalid input. Not finding a secret does not prove it is strong; [`generate-secret`](#generate-secret) does.

### generate-secret

Generates a random secret with Python's `secrets` module.

```bash
jwt-toolkit generate-secret                       # 256 bits, hex, in a panel
jwt-toolkit generate-secret --bits 512 --encoding base64
jwt-toolkit generate-secret --raw > hs256.secret  # just the secret and a newline
```

| Option | Description |
| --- | --- |
| `--bits N` | 64 to 4096, a multiple of 8. Default 256. |
| `--encoding` | `hex` (default) or `base64` (URL-safe, padded). |
| `--raw` | Print only the secret, unaffected by `--quiet` and `--no-color`. |

### download-wordlists

Saves the curated wordlist as a file, for use with other tools or as a starting point for your own list. `crack` does not need it, since the same list ships with the package.

```bash
jwt-toolkit download-wordlists --output-dir wordlists
```

The file is fetched over verified TLS from this release's git tag and checked against a pinned SHA-256 before it is kept. `--source URL` downloads from somewhere else without the hash check, and `--force` overwrites an existing file.

## Passing tokens, keys, and secrets

**Tokens.** Every command that takes a token accepts:

| Form | Meaning |
| --- | --- |
| `eyJhbGci...` | The token itself. |
| `@path/to/token.jwt` | Read the token from a file. |
| `-` | Read the token from stdin. |

Surrounding whitespace and line breaks are ignored.

**HMAC secrets.** `--secret VALUE` is convenient but ends up in shell history and is visible to other users in process listings. Prefer `--secret-file FILE`: the file is read as UTF-8 text, and only a byte-order mark and one trailing newline are removed, so the output of `generate-secret --raw` works unchanged.

**Asymmetric keys.** Private keys are PEM files in PKCS#8 or traditional format. Encrypted keys are supported through `--passphrase-file` or an interactive prompt. Public keys may be PEM `SubjectPublicKeyInfo` keys or X.509 certificates.

**JWKS.** `verify --jwks-url` fetches a key set over HTTPS (or reads a `file://` path), selects the key by the token's `kid`, and requires the key type, curve, and any `alg` on the key to match the token.

## Supported algorithms

| Family | `alg` values | Key input |
| --- | --- | --- |
| HMAC | `HS256`, `HS384`, `HS512` | `--secret` or `--secret-file` |
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` | PEM, X.509, or JWKS (`kty: RSA`) |
| RSA-PSS | `PS256`, `PS384`, `PS512` | PEM, X.509, or JWKS (`kty: RSA`) |
| ECDSA | `ES256`, `ES384`, `ES512` | PEM, X.509, or JWKS (`kty: EC`) |
| EdDSA | `Ed25519`, `Ed448`, `EdDSA` | PEM, X.509, or JWKS (`kty: OKP`) |

`alg` is matched case-sensitively, as RFC 7515 requires. `EdDSA` is the RFC 8037 name and takes its curve from the key. RFC 9864 deprecates it in favour of `Ed25519` and `Ed448`, so `audit` reports it as INFO. `alg: none` is never accepted by `verify`.

## Scripting and CI

**Quiet, uncolored output.** Global options go before the command:

```bash
jwt-toolkit --quiet --no-color audit "$TOKEN" --json
```

| Option | Environment variable | Effect |
| --- | --- | --- |
| `--quiet` | `JWT_TOOLKIT_QUIET=1` | Suppress the banner and non-essential output. |
| `--no-color` | `NO_COLOR=1` | Disable colors. |
| `--no-banner` | `JWT_TOOLKIT_NO_BANNER=1` | Suppress the banner shown by a bare `jwt-toolkit`. |

**JSON output.** `decode`, `audit`, `verify`, `diff`, and `forge` accept `--json`. Every document carries `"schema_version": "0.1"`; a field will not be renamed or removed without a new schema version. Errors use the same envelope with a stable code:

```json
{
  "schema_version": "0.1",
  "error": "invalid_structure",
  "message": "Invalid JWT structure: expected 3 parts, got 1",
  "detail": ["A JWT must have exactly 3 base64url parts separated by dots"]
}
```

Error codes include `invalid_structure`, `invalid_base64url`, `invalid_json`, `invalid_json_object`, `invalid_number`, `token_unreadable`, `unsupported_algorithm`, `invalid_key_options`, `key_error`, and `stdin_conflict`.

**Exit codes.** `0` means the check passed, `1` means it found a problem, and `2` means the input could not be used. The exceptions are [`crack`](#crack), which exits `1` when it finds the secret, and [`diff`](#diff), which only exits `1` with `--exit-code`.

**Example: gate a deployment on a token's configuration**

```yaml
- name: Audit the service token
  run: |
    pipx install jwt-toolkit
    jwt-toolkit --quiet audit "$SERVICE_TOKEN" --strict --require iss,aud,exp --json > audit.json
```

## Security model

What `jwt-toolkit` guarantees about its own behavior:

- Signatures and MACs are compared in constant time, through `hmac.compare_digest` or `cryptography`'s verifiers.
- `verify` rejects `alg: none`, derives the algorithm family from the key you supply rather than from the token, matches `alg` case-sensitively, and rejects tokens that require unsupported `crit` extensions.
- Header and payload must be JSON objects; `NaN`, `Infinity`, and overflowing numbers are rejected rather than compared.
- Secrets, passphrases, and private keys are never echoed in output or error messages.
- Token contents are printed as literal text, so a crafted claim cannot inject terminal styling or crash the renderer.
- The only network access is the JWKS fetch you request with `--jwks-url` and the explicit `download-wordlists` command, both over verified TLS when using HTTPS.

## Use responsibly

`jwt-toolkit` is built for defensive work: auditing your own tokens, hardening your own services, and learning how JWTs break. `forge` and `crack` exist so you can find these weaknesses before someone else does. Only use them against tokens and systems you are authorized to test.

## Contributing

Contributions are welcome, from new audit rules to documentation fixes. See [CONTRIBUTING.md](https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/CONTRIBUTING.md) for the project layout, development setup, branch and commit conventions, and the pull request checklist.

## Security policy

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/KhaledSaeed18/jwt-toolkit/security/advisories/new), not public issues. See [SECURITY.md](https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/SECURITY.md) for supported versions and the supply-chain controls behind each release.

## License

[MIT](https://github.com/KhaledSaeed18/jwt-toolkit/blob/main/LICENSE) © Khaled Saeed
