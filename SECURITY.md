# Security Policy

## Supported Versions

FeraTerra maintains active security coverage across the latest releases of `feraterra-mcp` and public FeraTerra gateways:

| Component | Supported Version | Status |
| :--- | :--- | :--- |
| [`FeraTerra/feraterra-mcp`](https://github.com/FeraTerra/feraterra-mcp) | `4.9.x` (`main`) | Supported |
| [`FeraTerra/feraterra-sdk`](https://github.com/FeraTerra/feraterra-sdk) | `4.9.x` (`main`) | Supported |
| [`FeraTerra/elizaos-plugin-feraterra`](https://github.com/FeraTerra/elizaos-plugin-feraterra) | `1.0.x` (`main`) | Supported |
| Public Gateways (`feraterra.app`, `testnet.feraterra.app`, `mcp.feraterra.app`) | Live deployments | Supported |

## Reporting a Vulnerability

**Please do NOT report undisclosed security vulnerabilities through public GitHub issues, pull requests, or public discussions.**

Instead, use either of our private disclosure channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Navigate to the **Security** tab of [`FeraTerra/feraterra-mcp`](https://github.com/FeraTerra/feraterra-mcp/security/advisories/new) (`Security -> Advisories -> Report a vulnerability`) to submit an encrypted private advisory directly to the maintainers.
2. **Email:**
   Send a detailed report to **`security@feraterra.app`**.

### What to Include

To help us reproduce and remediate findings rapidly, please include:

- Affected version, commit SHA, or endpoint URL (`https://feraterra.app`, `https://testnet.feraterra.app`, or `https://mcp.feraterra.app/mcp`).
- Step-by-step minimal reproduction (never execute destructive testing against shared public order books; use stateless `POST /order/preview` or `node ./bin/feraterra-mcp.mjs --self-test` wherever possible).
- Impact assessment (e.g., HMAC signing, `ARENA_LEDGER_TIP_V2_1` `Keccak-256` / `secp256k1` verification, MCP stdio framing, or credential redaction).

## Response Targets & Coordinated Disclosure

- **Initial Acknowledgment:** Within **48 hours** of receipt.
- **Triage & Severity Assessment:** Within **5 business days**.
- **Remediation & Coordinated Disclosure:** Critical fixes are prioritized immediately; once a patch is released and verified, we coordinate public advisory publication and researcher credit (if desired).
