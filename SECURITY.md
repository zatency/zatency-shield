@'
# Security Policy

## Supported Versions

Zatency Shield follows semantic versioning. Security patches and vulnerability fixes are actively maintained for the latest minor release:

| Version | Supported |
| :--- | :--- |
| `0.2.x` | :white_check_mark: Supported |
| `< 0.2.0` | :x: Unsupported |

## Security Architecture Guarantees

- **Zero External Telemetry:** Both the Rust proxy data plane and policy inspection engine run 100% locally inside your deployment boundary.
- **Constant-Time Authentication:** Virtual gateway bearer tokens (`zsk-...`) are verified using constant-time cryptographic comparisons (`subtle::ConstantTimeEq`) to mitigate timing side-channel attacks.
- **Unicode Normalization:** Incoming prompts undergo NFKC Unicode normalization prior to signature evaluation to prevent homoglyph and full-width character bypasses.
- **Hard Resource Limits:** Request payloads are capped at `2 MiB` (`DefaultBodyLimit`), and upstream connections enforce strict connect (`5s`) and read (`30s`) timeouts.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, guardrail bypass, or memory/denial-of-service issue in Zatency Shield:

1. Email **security@zatency.com** with a detailed description, reproduction steps, and affected version.
2. You will receive an acknowledgment within **24 hours** and an initial triage assessment within **72 hours**.
3. Once a patch is verified, we will coordinate a responsible disclosure timeline and credit you in the release notes (unless you prefer to remain anonymous).
'@ | Set-Content -Path SECURITY.md -Encoding UTF8
