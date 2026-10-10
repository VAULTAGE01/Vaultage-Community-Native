# Security and open-beta limits

The published native Community open beta is Developer ID signed and Apple notarized. Strict signatures, stapled tickets and Gatekeeper were verified for the app and DMG. Clean-machine installation and broader assistive-technology behavior remain unverified. See [release evidence](docs/RELEASE-STATUS.md).

Credential values are stored through the V2 open core's KeychainVault; its user-presence and fail-closed access-group checks remain unchanged. An unsigned synthetic Keychain write was refused with `errSecMissingEntitlement` (-34018) on the development machine. Source builds and fake-vault tests do not prove native Keychain custody. Distribution signing requires an authorized, separately configured Community App ID and Keychain access group; no private profile, credential or signing identity is shipped in source.

Metadata contains names, types, folders and project/environment references in owner-only local files. These labels are not encrypted. Metadata is not an authority proof against another process running as the same user. Credential accounts are always computed from the fixed Community namespace and UUID, not taken as arbitrary account names from metadata.

Human reveal/copy returns a value to the native UI or clipboard intentionally. Authentication first stages a protected VaultSecret handle bound to an exact request, secret and purpose. A second active-window Show/Copy action consumes it once. The macOS authentication sheet may temporarily take focus without disclosing anything; ready and visible values clear on later focus loss. Pending and visible disclosure share one 20-second deadline from authentication completion. The UI clears its clipboard write after 30 seconds only while unchanged. Swift/String, system clipboard and OS-owned buffers may retain copies; no universal memory-erasure or screenshot-proof guarantee is made. An unrestricted same-user agent can operate outside this app's controls.

Environment-file export requires a human confirmation and exports plaintext deliberately. Values use a conservative single-quoted literal subset verified with Node's `util.parseEnv` and shell assignments. Apostrophes, backslashes, newlines and control characters are refused; the app does not silently alter credential values to fit a parser. Other parsers or interpolation plugins need separate validation. File permissions and safe creation reduce accidental exposure; programs with access to the file can read its values. Never use real credentials in issues, logs or test fixtures.

Filesystem metadata and Keychain are separate systems: rollback handles observed failures, but no claim of a single crash-atomic distributed transaction is made. Signing, native UI user-presence, accessibility and clean-machine installation require their own release evidence.

Report issues privately to outworldlychronicles@gmail.com. Do not send passwords, API keys, tokens, vault files or plaintext environment files.
