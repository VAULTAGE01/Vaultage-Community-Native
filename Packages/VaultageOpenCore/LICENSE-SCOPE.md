# First-party license scope — Vaultage Open Core package

This file records that the original first-party source files included in this independently buildable package are licensed under Apache-2.0. It applies only to the source paths in this package; it is not a blanket license for the product repository or the mixed desktop app.

## Apache-2.0 scope

The original first-party source files included under these paths are licensed under Apache-2.0:

- `Sources/VaultageCore/**`
- `Sources/VaultageMCP/**`
- `Sources/VaultageBrokerContract/**`

The Apache-2.0 text is [LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt). This scope covers original Vaultage code in those paths only. It does not relicense Apple system frameworks, the external Swift MCP SDK, or any other third-party source; those components retain their own licenses and notices in [third-party/](third-party/) and [NOTICE.md](NOTICE.md).

## Outside this package scope

Provider adapters, provider catalog and registrations, the native app shell and packaging, hosted account/billing service, identity and billing integrations, website assets, signing, and other first-party sources are outside this package and remain proprietary planned areas. A mixed app bundle may contain Apache-2.0 components while remaining a proprietary distribution; inclusion in one bundle does not extend this source scope.

The package manifest declares only the `VaultageCore`, generic `VaultageMCP` and `VaultageBrokerContract` targets plus the external `MCP` product. Provider-aware composition is not included.

`VaultageBrokerContract` here carries the value-free XPC wire shapes only — what is allowed to cross a custody boundary, and the encoders that fail closed rather than omit a field. The product's peer-identity constants (Developer ID team, bundle identifiers, the packaging script's Info.plist key), the XPC broker client and the XPC broker service are outside this package: the first is distribution identity, and the last composes maintained provider adapters.

Provider identifiers and typed provider operation contracts that live in `VaultageCore` are public interfaces by design; the maintained adapters that implement them, and the service catalog, are not in this package.

The source allowlist and hashes are recorded in [EXPORT-MANIFEST.json](EXPORT-MANIFEST.json) and [FILES.sha256](FILES.sha256).
