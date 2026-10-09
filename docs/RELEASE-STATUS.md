# Native Community source preview — October 9, 2026

This repository contains the new accountless native Community UI and local storage layer, together with an unchanged, allowlisted Apache-2.0 export from Vaultage V2. It is separate from the commercial open-beta installer and the older Electron Community app.

## Observed source checks

- Debug and release application builds passed on the development Mac with Swift 6.3.3.
- Twenty-four isolated synthetic storage checks passed, including namespace isolation, label-only persistence, deletion/reference integrity, failed-write rollback, concurrent first launch, FIFO/symlink refusal, environment export, and competing-file publication/cleanup races.
- Supported environment values round-tripped unchanged through Node 22.23.3 `util.parseEnv` and `/bin/sh`. Unsupported characters are refused explicitly.
- All 110 licensed vendor files match the allowlisted export manifest. No private provider, account/billing, proprietary app shell or signing material was copied into this repository.
- An independent source review found and rechecked fixes for export-value escaping, export failure cleanup and the credential scanner's PEM coverage. No remaining concrete high or medium severity finding was identified within that review's scope. This is not a security certification.
- Native accessibility checks covered empty Vault/Projects, a secure entry field, disabled empty save, synthetic project creation, all three environment choices, persistence and deletion cancellation. No actual credential operation was claimed by these UI checks.

## Installer checks still required

- A synthetic unsigned Keychain write failed with `errSecMissingEntitlement` (-34018). No owner credentials were used. An authorized Community App ID and Developer ID profile are required; the commercial app's identity is not reused.
- Distribution signing, native user-presence reads, clean-machine installation, Gatekeeper and notarization are not yet verified for Community.
- Window capture protection prevented usable screenshots. The native checks above used the accessibility tree; screenshot-based visual QA and broader assistive-technology testing remain separate release work.
- Automatic migration from the older Electron Community app is not included.

Source publication, successful compilation and synthetic tests do not make this a finished installer. See [SECURITY.md](../SECURITY.md) for custody, plaintext disclosure, filesystem and same-user threat limitations.
