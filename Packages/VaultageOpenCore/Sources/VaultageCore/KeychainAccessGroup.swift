import Foundation
import Security

/// The one place that answers "which Keychain access group does this build
/// write to?" — BL-101, `12-REMOTE-APPROVALS-PROTOCOL.md` §11.4.2 and
/// `13-MULTI-DEVICE-CUSTODY.md` §9.1.
///
/// ## Why this exists
///
/// `KeychainVault` set no `kSecAttrAccessGroup` at all. An item saved without
/// the attribute lands in the **first** group of the signing entitlement. That
/// is harmless while there is exactly one group and catastrophic the moment a
/// second one appears: `Scripts/build-app.sh` writes the app's array at `:154`
/// and the broker's at `:160` from one `KEYCHAIN_GROUP` variable, and if a new
/// group were ever written first, every credential the broker saved would
/// become invisible to the app — which still performs the human-driven Vault
/// save, verify and delete paths. Pinning the group explicitly removes the
/// ordering dependency before any second group can exist.
///
/// ## Why it is `nil` by default
///
/// The concrete group embeds the team's App ID prefix, which is only known at
/// packaging time, from the validated provisioning profile. And an explicit
/// `kSecAttrAccessGroup` on a binary that carries no `keychain-access-groups`
/// entitlement fails `errSecMissingEntitlement` — which is every `swift build`,
/// every `Scripts/test.sh` run and every ad-hoc development bundle. So the
/// checked-in default is `nil` and `KeychainVault` **omits the key entirely**
/// when it is, which is exactly today's behaviour.
///
/// ## Why the fallback is not a silent widening (DB-M40)
///
/// A *signed* build that somehow reached the `nil` fallback — a packaging path
/// that skipped `build-app.sh`, a notarization re-run over a stale tree — would
/// write into the implicit first group with no error, which is precisely the
/// widening the pin exists to remove. So a build that is entitled or
/// distribution-signed and does **not** know its group refuses to run.
/// `Scripts/build-app.sh` refuses to sign a tree with the developer escape
/// hatch baked into it.
public enum KeychainAccessGroup {
    /// The `Info.plist` key `Scripts/build-app.sh` writes into **both** the app
    /// bundle and the nested broker service bundle, from the same
    /// `KEYCHAIN_GROUP` variable that writes the two `keychain-access-groups`
    /// entitlement arrays.
    ///
    /// This is the same mechanism `MetadataStore.buildChannelInfoKey` and
    /// `BrokerContract.transportInfoKey` already use: an observable fact about
    /// the running bundle, not an argument or an environment variable an agent
    /// could influence.
    public static let infoDictionaryKey = "VaultageKeychainAccessGroup"

    /// The single developer escape hatch of §11.4.2 step 1.
    ///
    /// **It is a compilation condition, not an environment variable.** An
    /// environment variable is readable — and settable — by anyone who can
    /// launch the custody process, which would make "no silent widening" a
    /// property of the launcher rather than of the build. As a Swift
    /// compilation condition it is fixed when the binary is produced, so a
    /// signed artifact either has it or does not, and `codesign` seals the
    /// answer. A developer turns it on by passing the condition below to
    /// `swift build` as an `-Xswiftc` define; the literal spelling is not
    /// written out here, because `Scripts/build-app.sh` greps the packaged tree
    /// for exactly that spelling and a doc comment is not a request.
    ///
    /// `Scripts/build-app.sh` refuses to sign a configuration that requests it
    /// and refuses to sign a built binary that contains it — the second check
    /// being the one that cannot be fooled by where the define came from.
    public static let developerOverrideCompilationCondition = "VAULTAGE_ALLOW_IMPLICIT_KEYCHAIN_GROUP"

    #if VAULTAGE_ALLOW_IMPLICIT_KEYCHAIN_GROUP
    public static let developerOverrideIsCompiledIn = true
    /// Emitted into the binary **only** when the escape hatch is compiled in, so
    /// `Scripts/build-app.sh` can refuse to sign such a binary by inspecting the
    /// built product rather than trusting the build configuration it was handed.
    /// Same idiom as `SecretExposureContracts`' byte scan.
    public static let developerOverrideMarker = "VAULTAGE-IMPLICIT-KEYCHAIN-GROUP-ESCAPE-HATCH-COMPILED-IN"
    #else
    public static let developerOverrideIsCompiledIn = false
    #endif

    public static let refusalMessage = """
        Vaultage was built without its Keychain access group. This build is \
        signed or entitled, so it must name the group it writes to explicitly; \
        falling back to the implicit first group would silently widen where \
        credentials are stored. Rebuild with Scripts/build-app.sh.
        """

    public static let malformedRefusalMessage = """
        Vaultage's Keychain access group is malformed. The bundle declares \
        \(infoDictionaryKey) but the value is not a concrete access group. \
        Rebuild with Scripts/build-app.sh.
        """

    // MARK: - What the bundle declares

    /// The three states the `Info.plist` key can be in. `malformed` is kept
    /// distinct from `absent` deliberately: a present-but-unusable value is a
    /// packaging fault, and collapsing it into `absent` would take the
    /// unentitled fallback on a build that was meant to be pinned.
    public enum Declaration: Equatable, Sendable {
        case absent
        case pinned(String)
        case malformed(String)
    }

    /// Decoded from a bundle's `Info.plist`, with no I/O of its own beyond the
    /// bundle read, so the self-tests can drive it from a fixture bundle.
    public static func declaration(in bundle: Bundle = .main) -> Declaration {
        guard let raw = bundle.object(forInfoDictionaryKey: infoDictionaryKey) else { return .absent }
        guard let value = raw as? String else { return .malformed(String(describing: type(of: raw))) }
        return declaration(forDeclaredValue: value)
    }

    /// Value-level decoding, split out so a fixture can exercise the accepted
    /// and rejected shapes without building a bundle for each one.
    public static func declaration(forDeclaredValue value: String) -> Declaration {
        // An absent key and an empty string mean the same thing to a packaging
        // script that ran but had nothing to write, so empty is `absent`.
        if value.isEmpty { return .absent }
        return isWellFormed(value) ? .pinned(value) : .malformed(value)
    }

    /// A concrete access group is `<10-character App ID prefix>.<identifier>`.
    /// The prefix is what `validate_profile_authorization` derives from the
    /// provisioning profile (`Scripts/build-app.sh:49-51`); a template value
    /// that still contains `$(AppIdentifierPrefix)`, a bare bundle identifier,
    /// or anything carrying whitespace is a packaging fault, not a group.
    public static func isWellFormed(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 256 else { return false }
        guard let separator = value.firstIndex(of: ".") else { return false }
        let prefix = value[value.startIndex..<separator]
        guard prefix.count == 10,
              prefix.allSatisfy({ $0.isASCII && ($0.isUppercase || $0.isNumber) })
        else { return false }
        let remainder = value[value.index(after: separator)...]
        guard !remainder.isEmpty else { return false }
        return remainder.allSatisfy { character in
            character.isASCII && (character.isLetter || character.isNumber || character == "." || character == "-")
        }
    }

    // MARK: - What the running binary is

    /// The two independent signals §11.4.2 and DB-M40 name. Either one on its
    /// own means "this build is expected to know its access group": an entitled
    /// build that does not know it is a build error, and a distribution-signed
    /// build without the entitlement cannot reach the Data Protection Keychain
    /// at all (spike fact 4), so running it would only fail later and less
    /// clearly.
    public struct SigningPosture: Equatable, Sendable {
        public let carriesKeychainAccessGroupsEntitlement: Bool
        public let isDistributionSigned: Bool

        public init(carriesKeychainAccessGroupsEntitlement: Bool, isDistributionSigned: Bool) {
            self.carriesKeychainAccessGroupsEntitlement = carriesKeychainAccessGroupsEntitlement
            self.isDistributionSigned = isDistributionSigned
        }

        /// Unsigned, ad-hoc and linker-signed builds are `false` on both counts
        /// and take the fallback.
        public var mustNameItsGroup: Bool { carriesKeychainAccessGroupsEntitlement || isDistributionSigned }

        public static let unsigned = SigningPosture(carriesKeychainAccessGroupsEntitlement: false, isDistributionSigned: false)
    }

    /// Reads the running binary's own signature. No `codesign` subprocess, no
    /// file path Vaultage supplies: `SecCodeCopySelf` is the kernel's answer to
    /// "what am I", so nothing on disk or in the environment can substitute a
    /// different answer.
    ///
    /// A failure to read the signature at all is reported as
    /// `SigningPosture.unsigned`, which is the honest reading — a binary whose
    /// signature cannot be examined has no entitlements to carry.
    #if canImport(AppKit)
    public static func currentSigningPosture() -> SigningPosture {
        var selfCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &selfCode) == errSecSuccess, let selfCode else { return .unsigned }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(selfCode, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let staticCode
        else { return .unsigned }
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
              let info = information as? [String: Any]
        else { return .unsigned }
        return posture(fromSigningInformation: info)
    }
    #else
    /// **BL-096 slice 1 — the iOS reading, and it is the honest one.**
    ///
    /// The whole probe above is macOS-only Security: `SecCode`,
    /// `SecCodeCopySelf`, `SecCodeCopySigningInformation` and the
    /// `kSecCodeInfo*` keys do not exist on iOS, and iOS publishes **no** API
    /// for a process to read its own entitlements. So this platform cannot
    /// examine its own signature, and the doc comment above already states
    /// what that means: *"a binary whose signature cannot be examined has no
    /// entitlements to carry"*. `.unsigned` it is.
    ///
    /// Nothing on the phone authorizes on this: the phone's six Enclave key
    /// roles (§2.2) are `DeviceKeyStore`'s, in the iOS app, which decides
    /// Enclave-versus-software from `SecureEnclave.isAvailable` and a
    /// compile-time flag rather than from a signature it cannot read. This
    /// exists so the module compiles and so a caller that asks gets a true
    /// answer instead of an invented one.
    public static func currentSigningPosture() -> SigningPosture { .unsigned }
    #endif

    #if canImport(AppKit)
    /// Split from `currentSigningPosture()` so the mapping is testable against
    /// a literal signing-information dictionary.
    public static func posture(fromSigningInformation info: [String: Any]) -> SigningPosture {
        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        let entitled = entitlements?["keychain-access-groups"] != nil
        // `kSecCodeSignatureAdhoc`. An ad-hoc or linker-signed binary — every
        // `swift build` product on Apple Silicon, and today's
        // `dist/Vaultage.app` — has no certificate chain at all.
        let adhoc = ((info[kSecCodeInfoFlags as String] as? UInt32) ?? 0) & SecCodeSignatureFlags.adhoc.rawValue != 0
        let certificates = (info[kSecCodeInfoCertificates as String] as? [Any]) ?? []
        return SigningPosture(
            carriesKeychainAccessGroupsEntitlement: entitled,
            isDistributionSigned: !adhoc && !certificates.isEmpty
        )
    }
    #endif

    // MARK: - The decision

    public enum LaunchDecision: Equatable, Sendable {
        /// Set `kSecAttrAccessGroup` to this value on every `SecItem*` call.
        case pinned(String)
        /// Omit `kSecAttrAccessGroup`, which is the behaviour every build had
        /// before BL-101. One line is logged the first time custody is used.
        case implicitFallback
        /// The developer escape hatch of §11.4.2 step 1, on a build that would
        /// otherwise refuse. Also omits the key, and says so loudly.
        case developerOverride
        /// Fail closed, with this message.
        case refuse(String)

        public var accessGroup: String? {
            if case .pinned(let group) = self { return group }
            return nil
        }
    }

    /// The whole rule, as a pure function of three inputs, so the table in the
    /// evidence note is the table the self-test asserts:
    ///
    /// | declaration | posture | decision |
    /// |---|---|---|
    /// | pinned | any | `pinned` |
    /// | absent | unsigned/ad-hoc | `implicitFallback` |
    /// | absent | entitled or distribution-signed | `refuse` |
    /// | absent | entitled, escape hatch compiled in | `developerOverride` |
    /// | malformed | any | `refuse` |
    ///
    /// A malformed value is refused even with the escape hatch compiled in and
    /// even on an unsigned build: the hatch excuses an *implicit* group, which
    /// is a state the shipped default is already in. It does not excuse a bundle
    /// that names a group nobody can use.
    ///
    /// `overrideIsCompiledIn` is a parameter only so the self-tests can assert
    /// both columns of the table from one binary. Nothing in the product passes
    /// it, and no runtime input can change it.
    public static func decide(
        declaration: Declaration,
        posture: SigningPosture,
        overrideIsCompiledIn: Bool = developerOverrideIsCompiledIn
    ) -> LaunchDecision {
        switch declaration {
        case .pinned(let group):
            return .pinned(group)
        case .malformed:
            return .refuse(malformedRefusalMessage)
        case .absent:
            guard posture.mustNameItsGroup else { return .implicitFallback }
            return overrideIsCompiledIn ? .developerOverride : .refuse(refusalMessage)
        }
    }

    // MARK: - The resolved answer for this process

    /// Resolved once. Every `SecItem*` call in `KeychainVault` consults it, so
    /// a refusal is not merely a launch banner: no custody operation can take
    /// the implicit path on a build that must not.
    public static let current: LaunchDecision = decide(
        declaration: declaration(in: .main),
        posture: currentSigningPosture()
    )

    /// The access group every `SecItem*` call must use, or `nil` for "omit the
    /// key". Throws rather than returning `nil` when the decision is a refusal.
    public static func resolvedForCustody(_ decision: LaunchDecision = current) throws -> String? {
        switch decision {
        case .pinned(let group):
            return group
        case .implicitFallback:
            noteFallbackOnce("Vaultage is running unsigned: Keychain items use the implicit access group (BL-101 fallback).")
            return nil
        case .developerOverride:
            noteFallbackOnce("Vaultage was compiled with -D\(developerOverrideCompilationCondition): Keychain items use the implicit access group on a build that should name one. This binary must never be signed or shipped.")
            return nil
        case .refuse(let message):
            throw VaultageError.storage(message)
        }
    }

    /// Called from a custody-owning process's entry point so a build that can
    /// never serve a request says so at launch rather than at the first read.
    /// Returns the message to print when the process must not continue.
    /// Audit H-07. The access group for the keys that must never be readable
    /// from the GUI process: the grant signing key and the remote-connect
    /// `kex` handle, both promptless by design. It is the custody group with
    /// `.broker` appended, which only the nested broker service's entitlement
    /// carries — the app declares the custody group alone, so code executing
    /// in the app gets `errSecMissingEntitlement` here. On an unsigned build
    /// the answer is the same implicit fallback as custody's: there is no
    /// process boundary to hold, and the note says so.
    public static func resolvedForBrokerOnly(_ decision: LaunchDecision = current) throws -> String? {
        guard let group = try resolvedForCustody(decision) else { return nil }
        return brokerOnlyGroup(custody: group)
    }

    /// `<custody group>.broker`, exactly what `VaultageBroker.entitlements`
    /// and `Scripts/build-app.sh` name as the service's second group.
    public static func brokerOnlyGroup(custody group: String) -> String { group + ".broker" }

    public static func launchRefusal(_ decision: LaunchDecision = current) -> String? {
        if case .refuse(let message) = decision { return message }
        return nil
    }

    // MARK: - Query construction

    /// The attributes shared by every `SecItem*` call: the class, the service
    /// namespace, the account, the Data Protection Keychain selector, and —
    /// when this build is pinned — the access group. Nothing else. The save,
    /// read and delete builders below are this dictionary plus the keys that
    /// operation needs, which is what lets a self-test assert the exact
    /// dictionary rather than a sampling of it.
    public static func baseAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let accessGroup { attributes[kSecAttrAccessGroup as String] = accessGroup }
        return attributes
    }

    /// `SecItemAdd`'s dictionary without the two values only the caller holds:
    /// `kSecValueData` (the secret) and `kSecAttrAccessControl` (a live
    /// `SecAccessControl`). Neither is comparable in a fixture, and neither
    /// varies with the access group, which is what this ticket changes.
    public static func saveAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        baseAttributes(service: service, account: account, accessGroup: accessGroup)
    }

    /// `SecItemCopyMatching`'s dictionary without `kSecUseAuthenticationContext`,
    /// which is a live `LAContext`.
    public static func readAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        var attributes = baseAttributes(service: service, account: account, accessGroup: accessGroup)
        attributes[kSecReturnData as String] = true
        return attributes
    }

    /// `SecItemDelete`'s dictionary, complete.
    public static func deleteAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        baseAttributes(service: service, account: account, accessGroup: accessGroup)
    }

    // MARK: - The account session store's four call sites

    /// `AccountKeychainStore` (`AccountClient.swift`) keeps the device session
    /// record — installation identity, session token, entitlement lease cache —
    /// in its own Keychain service, through four `SecItem*` calls that carried
    /// the same implicit-group hazard `KeychainVault`'s three did. BL-101 left
    /// them as a named exemption because a concurrent lane owned the file; the
    /// exemption is now closed and these builders are why. They are separate
    /// from `saveAttributes`/`readAttributes`/`deleteAttributes` rather than
    /// shared with them because the two stores' dictionaries genuinely differ —
    /// the session read pins `kSecMatchLimit` and the session add carries
    /// `kSecAttrAccessible` instead of a `SecAccessControl` — and folding them
    /// together would have changed one store's bytes to describe the other's.
    ///
    /// The `kSecAttrAccessGroup` decision is the same one, from the same place.

    /// `SecItemCopyMatching`'s dictionary for the session record, complete.
    public static func sessionReadAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        var attributes = baseAttributes(service: service, account: account, accessGroup: accessGroup)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        return attributes
    }

    /// `SecItemUpdate`'s *query* half for the session record, complete. The
    /// changed-attributes half carries only `kSecValueData`, which the caller
    /// holds and which never varies with the access group.
    public static func sessionUpdateQueryAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        baseAttributes(service: service, account: account, accessGroup: accessGroup)
    }

    /// `SecItemAdd`'s dictionary for the session record, without `kSecValueData`.
    ///
    /// The session record is `WhenUnlockedThisDeviceOnly` with **no**
    /// `.userPresence`: it is the device's own identity, read on every account
    /// call, and prompting for it would prompt for everything. That is unchanged
    /// by this ticket and is asserted here so it cannot drift silently.
    public static func sessionAddAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        var attributes = baseAttributes(service: service, account: account, accessGroup: accessGroup)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return attributes
    }

    /// `SecItemDelete`'s dictionary for the session record, complete.
    public static func sessionDeleteAttributes(service: String, account: String, accessGroup: String?) -> [String: Any] {
        baseAttributes(service: service, account: account, accessGroup: accessGroup)
    }

    // MARK: - One line, once

    private static let fallbackNote = FallbackNote()

    private static func noteFallbackOnce(_ message: String) {
        fallbackNote.emit(message)
    }

    private final class FallbackNote: @unchecked Sendable {
        private let lock = NSLock()
        private var emitted = false
        func emit(_ message: String) {
            lock.lock()
            let first = !emitted
            emitted = true
            lock.unlock()
            guard first else { return }
            FileHandle.standardError.write(Data("\(message)\n".utf8))
        }
    }
}
