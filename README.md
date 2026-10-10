# Vaultage Community Native

A free-forever, accountless macOS secrets manager and local project workspace, built from Vaultage V2's open core.

**Open beta for Apple silicon Macs running macOS 14 or later.** [Download the signed, Apple-notarized Community installer](https://github.com/VAULTAGE01/Vaultage-Community-Native/releases/tag/v0.1.0-beta.3). Version 0.1.0, build 3 is free forever and accountless. The separate Vaultage product beta and its account requirement do not apply to this local Community app.

The release includes the DMG, SHA-256 checksum and exact source manifest. See [release evidence and remaining beta limits](docs/RELEASE-STATUS.md).

## Scope

- Local secret metadata, folders and label-only search.
- Credential values held in macOS Keychain with the open core's user-presence controls.
- Explicit human reveal/copy and deletion.
- Local projects, development/staging/production environments and credential references.
- Confirmed plaintext `.env` export to a new file, using a documented literal subset.
- No Vaultage account, subscription, billing, provider catalog, hosted sync or agent integration. No paid usage quotas.

## Build and run

macOS 14 or later and a Swift 6 toolchain are required.

```sh
swift build
swift run CommunityKitTests
node scripts/verify-source-boundary.mjs
swift run VaultageCommunity
```

The UI and synthetic storage tests build locally. An unsigned synthetic Keychain write was refused with `errSecMissingEntitlement` (-34018). Running from source alone does not establish a usable credential store. The published Community bundle uses its separate App ID and authorized Developer ID profile. Disposable synthetic save, Reveal and Copy were exercised in a signed development bundle; the final installer passes strict signature, notarization-ticket and Gatekeeper checks. The commercial app's identity is not reused. No signing credentials or provisioning profiles are included here. OS user-presence prompts must be answered by the person using the app.

Reveal and Copy use two explicit actions: macOS authentication prepares a protected, short-lived value; then **Show value** or **Copy value** consumes that approval in the active window. Values stay hidden during authentication. The approval expires after 20 seconds and clears on selection changes, cancellation or focus loss after authentication. Returning focus never reveals or copies automatically.

## Data and limitations

Community metadata is separate from the commercial app, in `~/Library/Application Support/VaultageCommunityV2`. The metadata file holds labels and references, not credential values. Values use the fixed Community Keychain namespace. This initial native app does not import or migrate the older Electron Community vault automatically.

Revealing or copying intentionally exposes a value to the user or system clipboard. Plaintext environment export intentionally exposes selected values to the destination file and tools with access to it. Exports use single-quoted UTF-8 values compatible with Node's `util.parseEnv` and shell assignments: apostrophes, backslashes, newlines and control characters are refused instead of being escaped into a different credential. Values containing dollar signs, backticks, double quotes, hashes or spaces remain literal. This is not a promise of compatibility with every framework's environment parser or interpolation plugin. See [SECURITY.md](SECURITY.md).

The older Electron Community edition is maintained at [VAULTAGE01/Vaultage](https://github.com/VAULTAGE01/Vaultage). Its exact release notes describe its binary readiness; it is a separate generation.

## License

New application source is Apache-2.0. The vendored V2 open-core package retains its exact scope and third-party notices. The maintained proprietary provider adapters, commercial app shell, hosted account/billing implementation, private signing and branding assets are outside this repository.

Vaultage is a product by Arcalab, founded in 2026. Public founder name: WJ Ra.
