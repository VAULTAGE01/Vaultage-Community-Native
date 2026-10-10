# Native Community source preview — October 9, 2026

This repository contains the new accountless native Community UI and local storage layer, together with an unchanged, allowlisted Apache-2.0 export from Vaultage V2. It is separate from the commercial open-beta installer and the older Electron Community app.

## Observed source checks

- Debug and release application builds passed on the development Mac with Swift 6.3.3.
- Thirty isolated synthetic checks passed, including the original storage/export checks and six disclosure-gate cases: authentication focus changes, ready-state focus loss, manual cancellation, stale completion, selection/purpose binding, 20-second expiry, single use and concurrent aliases.
- Supported environment values round-tripped unchanged through Node 25.6.0 `util.parseEnv` and `/bin/sh` in the latest run. Unsupported characters are refused explicitly.
- All 110 licensed vendor files match the allowlisted export manifest. No private provider, account/billing, proprietary app shell or signing material was copied into this repository.
- An independent source review found and rechecked fixes for export-value escaping, export failure cleanup and the credential scanner's PEM coverage. No remaining concrete high or medium severity finding was identified within that review's scope. This is not a security certification.
- Native accessibility checks covered empty Vault/Projects, a secure entry field, disabled empty save, synthetic project creation, all three environment choices, persistence and deletion cancellation. No actual credential operation was claimed by these UI checks.

## Installer checks still required

- A synthetic unsigned Keychain write failed with `errSecMissingEntitlement` (-34018). A separate authorized Community Developer ID profile was subsequently obtained. A verification bundle was signed with hardened runtime, timestamp and only its own explicit App ID/team/Keychain group; strict signature verification passed. Saving one disposable synthetic secret in this signed bundle succeeded. The commercial app's identity is not reused.
- The original signed UI reproduced Reveal/Copy cancellation when macOS authentication changed focus. The new two-action flow passes synthetic tests and independent source review, with no concrete remaining P0/P1/P2 identified in that scope. Real signed UI verification of the corrected disclosure flow is pending.
- Clean-machine installation, Gatekeeper and notarization are not yet verified for Community. No public Community installer readiness is claimed.
- Window capture protection prevented usable screenshots. The native checks above used the accessibility tree; screenshot-based visual QA and broader assistive-technology testing remain separate release work.
- Automatic migration from the older Electron Community app is not included.

Source publication, successful compilation and synthetic tests do not make this a finished installer. See [SECURITY.md](../SECURITY.md) for custody, plaintext disclosure, filesystem and same-user threat limitations.
