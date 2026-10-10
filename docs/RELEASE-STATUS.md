# Native Community open beta — October 9, 2026

This repository contains the new accountless native Community UI and local storage layer, together with an unchanged, allowlisted Apache-2.0 export from Vaultage V2. It is separate from the commercial open-beta installer and the older Electron Community app.

## Observed source checks

- Debug and release application builds passed on the development Mac with Swift 6.3.3.
- Thirty isolated synthetic checks passed, including the original storage/export checks and six disclosure-gate cases: authentication focus changes, ready-state focus loss, manual cancellation, stale completion, selection/purpose binding, 20-second expiry, single use and concurrent aliases.
- Supported environment values round-tripped unchanged through Node 25.6.0 `util.parseEnv` and `/bin/sh` in the latest run. Unsupported characters are refused explicitly.
- All 110 licensed vendor files match the allowlisted export manifest. No private provider, account/billing, proprietary app shell or signing material was copied into this repository.
- An independent source review found and rechecked fixes for export-value escaping, export failure cleanup and the credential scanner's PEM coverage. No remaining concrete high or medium severity finding was identified within that review's scope. This is not a security certification.
- Native accessibility checks covered empty Vault/Projects, a secure entry field, disabled empty save, synthetic project creation, all three environment choices, persistence and deletion cancellation. No actual credential operation was claimed by these UI checks.

## Observed installer checks and remaining limits

- A synthetic unsigned Keychain write failed with `errSecMissingEntitlement` (-34018). A separate authorized Community Developer ID profile was subsequently obtained. A verification bundle was signed with hardened runtime, timestamp and only its own explicit App ID/team/Keychain group; strict signature verification passed. Saving one disposable synthetic secret in this signed bundle succeeded. The commercial app's identity is not reused.
- The original signed UI reproduced Reveal/Copy cancellation when macOS authentication changed focus. The new two-action flow passes synthetic tests and independent source review, with no concrete remaining P0/P1/P2 identified in that scope. In the corrected signed development bundle, authenticating the disposable synthetic record produced a hidden ready state; Show value displayed the expected synthetic text, and the original 20-second deadline hid it again. Copy authentication also produced a hidden ready state, and Copy value completed with the 30-second clipboard status. Owner records and real credential values were not used for these checks. Clipboard contents were not captured; actual app-switch focus behavior remains covered by synthetic/source checks rather than a confirmed OS switch in this UI pass.
- Public release [v0.1.0-beta.3](https://github.com/VAULTAGE01/Vaultage-Community-Native/releases/tag/v0.1.0-beta.3) contains the arm64 macOS 14+ DMG, checksum and source manifest. The artifact was built from clean source revision `da5d4dbe88e95c9d2155e4c70ff03dbed5fb4e0e`; later documentation changes do not change that artifact provenance.
- App notarization `4da53aa8-3641-4fae-bc41-b86de028ad68` and DMG notarization `9e26608a-b7aa-48a6-a6e4-1a61cc8bcb9e` were accepted. Both were stapled and ticket validation passed. Strict hardened-runtime signatures and Gatekeeper accepted the app, DMG and app inside a verified read-only DMG mount.
- The public DMG download was retrieved and verified: 4,556,476 bytes; SHA-256 `51327369247bc0bfd2e11599c0b01044f2fae5bb77ead405d755db9b8bae478e`. The final extracted app launched. Its executable matches the tested signed development build after removing signatures from disposable verification copies.
- Clean-machine installation remains unverified.
- Window capture protection prevented usable screenshots. The native checks above used the accessibility tree; screenshot-based visual QA and broader assistive-technology testing remain separate release work.
- Automatic migration from the older Electron Community app is not included.

This is an open beta, with the observed release checks and limitations above. See [SECURITY.md](../SECURITY.md) for custody, plaintext disclosure, filesystem and same-user threat limitations.
