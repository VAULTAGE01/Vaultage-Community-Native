# Native Community V2 implementation contract

Owner: WJ Ra (Arcalab). Authorized October 9, 2026: free forever, accountless local vault and projects; publish only the reviewed Community source on GitHub, then link the marketing website. Current V2 commercial app/account flow remains separate. This repository is a source preview until independent release checks and a signed/notarized package are complete.

Reuse the licensed V2 Core SecretVault/KeychainVault and VaultSecret, with a new local UI and metadata store. Do not copy proprietary app shell, provider adapters/catalog, account/billing service, XPC client/service or signing credentials. No source or binary can claim universally preventing an unrestricted same-user attacker from accessing memory/files. Never log secrets or use real owner/provider credentials in tests. Keychain-backed developer operation must be tested using synthetic records; any missing OS/signing precondition fails closed and must be disclosed.

## Shared CommunityKit API (storage agent owns implementation)

Public Sendable/Codable/Identifiable types:
- SecretKind: apiKey, password, secureNote (String raw values).
- SecretSummary: id: UUID, title: String, kind: SecretKind, folder: String, createdAt: Date.
- EnvironmentBinding: id: UUID, key: String, secretID: UUID.
- ProjectEnvironment: id: UUID, name: String, bindings: [EnvironmentBinding].
- CommunityProject: id: UUID, name: String, environments: [ProjectEnvironment].
- CommunitySnapshot: secrets: [SecretSummary], projects: [CommunityProject].

CommunityStore actor init(directory: URL = CommunityStore.defaultDirectory, vault: any SecretVault = KeychainVault()). Separate Application Support/VaultageCommunityV2 metadata, no Pro store. Methods:
- snapshot() throws -> CommunitySnapshot
- createSecret(title: String, kind: SecretKind, folder: String, value: Data) throws -> SecretSummary
- deleteSecret(id: UUID) throws (remove references, never a different Keychain namespace)
- readSecret(id: UUID, prompt: String) throws -> VaultSecret (only a human UI calls it; OS presence remains in KeychainVault)
- createProject(name: String) throws -> CommunityProject (includes Development, Staging, Production environments)
- deleteProject(id: UUID) throws (keeps secrets)
- setBinding(projectID: UUID, environmentID: UUID, key: String, secretID: UUID) throws
- removeBinding(projectID: UUID, environmentID: UUID, bindingID: UUID) throws
- exportEnvironment(projectID: UUID, environmentID: UUID, to: URL, confirmation: String) throws; requires exact EXPORT, one supported env key per line, refuses symlink targets/unsafe writes and emits no secret to a log/error. UI labels the plaintext exposure. Export into a new file only (no overwrite).

Metadata contains labels and references only; credential Data goes to the injected SecretVault. Resolve accounts from fixed community-v2 prefix + UUID, never metadata-supplied arbitrary Keychain accounts. Failed mutations must preserve previously stored secrets and metadata. No quotas/paywall, accounts, billing, HTTP or agent surface. Practical parser/file limits are security bounds, not a paid usage limit.

## Native UI (UI agent owns Sources/VaultageCommunity)

Dark green/grey background, restrained violet accent, Vault and Projects in sidebar. Accountless first launch to local workspace; add-secret SecureField, titles/folders/search; secret rows show only labels; Reveal/Copy only human actions via readSecret. Secret value views expire and clear on window deactivation; clipboard expiry clears only this app's unchanged write. Explicit deletion dialogs. Project + environment selector, add/remove binding from existing secrets, plaintext export confirmation EXPORT then NSSavePanel. No provider/service/agent/account placeholders. Use system symbols, no private brand assets. Honest source-preview badge.

Do not add edit-secret yet: safe copy-on-new-record rotation can follow. Do not create or import billing/auth sessions. Build source with swift build and meaningful isolated tests. This initial native source release is not a signed/notarized customer-ready installer.
