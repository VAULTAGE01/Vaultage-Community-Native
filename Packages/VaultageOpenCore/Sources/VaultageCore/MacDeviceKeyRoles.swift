import CryptoKit
import Foundation
import Security

/// BL-099 — **the Mac's two key roles of the protocol's six** (§2.2).
///
/// | Role | Mac | Purpose |
/// |---|---|---|
/// | `sig` | Ed25519, software, account Keychain — **existing, unchanged** | DPoP on every route; the Mac's single `sig` key serves the read-only and state-changing classes alike, because the reason the *phone* splits them (DB-H10) is a Secure Enclave ACL the Mac does not have |
/// | `kex` | **P-256, Secure Enclave**, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly + .privateKeyUsage`, broker-only access group (§12 item 19) — **owed, see below** | HPKE recipient for the credential envelope (§5.3) |
///
/// **The broker-only access group shipped with the audit's H-07 fix**
/// (2026-09-22, closing what BL-109 / BL-100 slice B had left owed).
/// `VaultageBroker.entitlements` carries a second `keychain-access-groups`
/// entry, `<custody group>.broker`, which `Vaultage.entitlements` does not, and
/// `loadKexBlob` resolves the `kex` reference blob through
/// `KeychainAccessGroup.resolvedForBrokerOnly` — so on a signed build, code
/// running as the **app** process gets `errSecMissingEntitlement` for it and
/// cannot reconstruct the Enclave handle that HPKE-opens the phone's
/// envelopes, even though the ACL carries no presence flag (§5.6 must complete
/// without one). `build-app.sh` asserts the app's sealed entitlements carry
/// the custody group alone and the service's carry exactly these two. On an
/// unsigned build both groups resolve to the implicit fallback and there is no
/// process boundary to hold, as before.
///
/// The other four roles — `sigw`, `apv`, `sum`, `sum2` — are the phone's and are
/// BL-096's.
///
/// **There is no key binding statement, and there must not be one.** The brief
/// for this slice asked for "the binding signature over the appendix's
/// preimage"; the appendix's P11 `bindingPreimage` is **deleted** (DB-H1), and
/// §2.4 says why: its preimage named an enrolment `request_id` and a
/// server-assigned `enrolledAt`, neither of which a verifying Mac can recover
/// from the roster, so the check could not run — and even repaired it proves
/// nothing against an invented device. **What binds the Mac's two keys together
/// is out of band, not a signature**: both thumbprints travel inside the QR
/// payload (P1), both are folded into the six-word SAS (P2) along with the
/// phone's five, and the owner compares six words once. The pins are the whole
/// control.
///
/// **What is a signed-build gate, and why** (spike fact 1 and platform fact 6).
/// HPKE conformance for `SecureEnclave.P256.KeyAgreement.PrivateKey` is
/// *established* — the spike compiled and ran an authenticated roundtrip against
/// one, unsigned. What the spike never did is **persist** the key: its key lived
/// for one process. Persisting means the Data Protection Keychain, and an
/// unsigned binary cannot open that at all, for any accessibility class (spike
/// fact 4). So creating and reloading `kex` is a **release gate on a signed
/// artifact**, and the unsigned path here does not fake it: it reports why it
/// skipped, in words, and no caller can mistake the skip for a key.
public enum MacDeviceKeyRoles {
    /// The Keychain service the `kex` key's reference blob lives under. Its own
    /// namespace, separate from the vault's and from the account session's, so
    /// the three are independently deletable and independently auditable.
    public static let kexService = "com.vaultage.foundation20260910.devicekey.kex.v1"
    public static let kexAccount = "mac-kex-p256"

    // MARK: - Status, reported rather than inferred

    /// What the `kex` key is on this run. Every case says what it is and, for
    /// the two that are not a key, exactly why — because the honest report is
    /// the deliverable on an unsigned build, not a placeholder key.
    public enum KexKeyStatus: Equatable, Sendable {
        /// Loaded from the Keychain, or created and persisted on this run.
        case present(thumbprint: String, createdOnThisRun: Bool)
        /// This Mac has no Secure Enclave. There is **no software fallback**:
        /// five of the protocol's six roles are Enclave keys and §12 platform
        /// fact 6 records that there is no fallback if persistence is
        /// unavailable.
        case noSecureEnclave
        /// The build cannot open the Data Protection Keychain, so the key
        /// cannot be persisted and reloaded. Skipped honestly.
        case unsignedBuild(reason: String)
        /// The Enclave and the Keychain were both reachable and the operation
        /// still failed. Never silently downgraded to one of the above.
        case failed(reason: String)

        public var thumbprint: String? {
            if case .present(let thumbprint, _) = self { return thumbprint }
            return nil
        }

        /// The one line the evidence note quotes.
        public var description: String {
            switch self {
            case .present(let thumbprint, let created):
                "kex: \(created ? "created and persisted" : "loaded") in the Secure Enclave, thumbprint \(thumbprint)"
            case .noSecureEnclave:
                "kex: no Secure Enclave on this Mac — there is no software fallback, and remote connect cannot run here"
            case .unsignedBuild(let reason):
                "kex: not created — \(reason)"
            case .failed(let reason):
                "kex: failed — \(reason)"
            }
        }
    }

    /// Why an unsigned build does not attempt the Enclave key, in the words the
    /// evidence note and the Devices screen both use.
    public static let unsignedSkipReason = "this build carries no provisioning-profile-backed keychain-access-groups entitlement, so it cannot open the Data Protection Keychain at all (platform fact 5). Persisting and reloading an Enclave key is a signed-build gate (platform fact 6); nothing here fakes one."

    // MARK: - The kex key

    /// Loads the `kex` key, creating it once if it does not exist.
    ///
    /// The order of the three guards is the order in which a failure is most
    /// honest: no Enclave at all, then no Keychain to persist into, then the
    /// operation itself.
    public static func kexKey(
        posture: KeychainAccessGroup.SigningPosture = KeychainAccessGroup.currentSigningPosture(),
        decision: KeychainAccessGroup.LaunchDecision = KeychainAccessGroup.current,
        enclaveIsAvailable: Bool = SecureEnclave.isAvailable
    ) -> KexKeyStatus {
        guard enclaveIsAvailable else { return .noSecureEnclave }
        // An unsigned or ad-hoc build cannot reach the Data Protection Keychain,
        // so it cannot persist the blob that makes the key reloadable. Creating
        // an in-memory Enclave key here would "work" and prove nothing, which is
        // precisely the confusion spike fact 1 and fact 6 exist to separate.
        guard posture.mustNameItsGroup else { return .unsignedBuild(reason: unsignedSkipReason) }
        do {
            let group = try KeychainAccessGroup.resolvedForBrokerOnly(decision)
            if let existing = try loadKexBlob(accessGroup: group) {
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing)
                return .present(thumbprint: RemoteDeviceKeyThumbprint.thumbprint(of: key.publicKey), createdOnThisRun: false)
            }
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try kexAccessControl())
            try saveKexBlob(key.dataRepresentation, accessGroup: group)
            return .present(thumbprint: RemoteDeviceKeyThumbprint.thumbprint(of: key.publicKey), createdOnThisRun: true)
        } catch let error as VaultageError {
            return .failed(reason: error.localizedDescription)
        } catch {
            return .failed(reason: "\(error)")
        }
    }

    /// §2.2's ACL for `kex`, exactly: `WhenUnlockedThisDeviceOnly` — the key is
    /// unusable while the Mac is locked, which is §5.6's `presence_unavailable`
    /// branch rather than a bug — and `.privateKeyUsage`, with **no presence
    /// flag of any kind**. Consuming a sealed envelope must not raise a prompt:
    /// §11.6's answer for release one is (b), and §5.6 verifies from plaintext
    /// already in memory, so remote connect works end to end with no Keychain
    /// read and no presence prompt.
    public static func kexAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            throw VaultageError.storage("Could not create the Secure Enclave access control for the device key-agreement key.")
        }
        return control
    }

    /// The Enclave key's reference blob. It is **not** the private key — the
    /// private key never leaves the Enclave and is not in any backup, which is
    /// why a restored Mac re-pairs (§2.2, DB-L7) — but it is the only handle
    /// that reopens the key, so it is stored under the same pinned access group
    /// as every other `SecItem` call in this module (BL-101).
    /// The three dictionaries are `KeychainAccessGroup`'s `session*` builders,
    /// not a fourth copy: the reference blob wants exactly the shapes the
    /// account session record wants — `WhenUnlockedThisDeviceOnly`, no
    /// `.userPresence`, one match — and BL-101's rule is that no file builds a
    /// Keychain query by hand.
    static func loadKexBlob(accessGroup: String?) throws -> Data? {
        let query = KeychainAccessGroup.sessionReadAttributes(service: kexService, account: kexAccount, accessGroup: accessGroup)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw VaultageError.storage("Could not read the device key-agreement key reference (\(status)).")
        }
        return data
    }

    static func saveKexBlob(_ blob: Data, accessGroup: String?) throws {
        var attributes = KeychainAccessGroup.sessionAddAttributes(service: kexService, account: kexAccount, accessGroup: accessGroup)
        attributes[kSecValueData as String] = blob
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultageError.storage("Could not store the device key-agreement key reference (\(status)).")
        }
    }

    /// The loaded `kex` private key, ready to hand to
    /// `HPKE.Recipient(privateKey:ciphersuite:info:encapsulatedKey:)` (§5.3,
    /// spike fact 1).
    ///
    /// Returns `nil` rather than creating anything: the creation path is
    /// `kexKey()`, which reports why it skipped. A caller that gets `nil` here
    /// has no recipient key and must refuse the envelope, not invent one.
    ///
    /// The key itself never leaves the Secure Enclave; what is loaded is the
    /// reference blob that reopens it.
    public static func loadedKexPrivateKey(
        decision: KeychainAccessGroup.LaunchDecision = KeychainAccessGroup.current
    ) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        guard let blob = try loadKexBlob(accessGroup: try KeychainAccessGroup.resolvedForBrokerOnly(decision)) else { return nil }
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    }

    /// Removing the `kex` key is what a re-pair after a restore amounts to. It
    /// is never called by a network path.
    public static func deleteKexKey(decision: KeychainAccessGroup.LaunchDecision = KeychainAccessGroup.current) throws {
        let query = KeychainAccessGroup.sessionDeleteAttributes(service: kexService, account: kexAccount, accessGroup: try KeychainAccessGroup.resolvedForBrokerOnly(decision))
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultageError.storage("Could not delete the device key-agreement key reference (\(status)).")
        }
    }

    // MARK: - The pairing payload, which is what actually binds the two keys

    /// P1, built from this Mac's live thumbprints.
    ///
    /// This is the whole of the "binding": the phone pins `(macDeviceId,
    /// macSigThumbprint, macKexThumbprint)` from the QR, the SAS proves both
    /// sides agree on them, and the owner confirms with Touch ID. There is no
    /// signature over a binding preimage because DB-H1 deleted the one version 2
    /// had, and because a signature by either of these keys over a statement
    /// about both proves only that the signer holds one of them — which is
    /// exactly what the ceremony already establishes, out of band, in a way the
    /// relay cannot forge.
    public static func pairingPayload(
        pairingId: String,
        macDeviceId: String,
        accountSubject: String,
        sigThumbprint: String,
        kexThumbprint: String,
        nonce: Data,
        createdAt: Int
    ) throws -> RemotePairingPayload {
        guard nonce.count == RemotePairingPayload.nonceBytes else {
            throw VaultageError.invalidInput("A pairing nonce is \(RemotePairingPayload.nonceBytes) random bytes.")
        }
        guard RemoteDeviceKeyThumbprint.isWellFormed(sigThumbprint), RemoteDeviceKeyThumbprint.isWellFormed(kexThumbprint) else {
            throw VaultageError.invalidInput("A pairing payload carries two RFC 7638 thumbprints.")
        }
        return RemotePairingPayload(
            pairingId: pairingId,
            macDeviceId: macDeviceId,
            accountSubject: accountSubject,
            macSigThumbprint: sigThumbprint,
            macKexThumbprint: kexThumbprint,
            nonce: RemoteBase64URL.encode(nonce),
            createdAt: createdAt
        )
    }

    /// 32 fresh random bytes, from the system CSPRNG, never reused across
    /// pairings (§2.4).
    public static func freshPairingNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: RemotePairingPayload.nonceBytes)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultageError.storage("Could not draw a pairing nonce from the system random source.")
        }
        return Data(bytes)
    }
}

/// The `sig` half of §2.2's Mac row, projected out of `DeviceAccountClient`
/// without exposing the private key or the rest of the device identity.
///
/// `deviceID` is `nil` until the Mac has completed device authorization; the
/// pairing ceremony cannot run before then, because P1 carries `macDeviceId` and
/// a pin keyed on nothing is not a pin.
public struct MacSigIdentity: Equatable, Sendable {
    public let deviceID: String?
    public let deviceName: String
    public let accountSubject: String?
    public let sigThumbprint: String

    public init(deviceID: String?, deviceName: String, accountSubject: String?, sigThumbprint: String) {
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.accountSubject = accountSubject
        self.sigThumbprint = sigThumbprint
    }

    /// Whether this Mac can begin a pairing ceremony at all: it needs its own
    /// device id and the account subject that every preimage in this protocol
    /// carries as field one of its body.
    public var canPair: Bool {
        deviceID != nil && accountSubject != nil && RemoteDeviceKeyThumbprint.isWellFormed(sigThumbprint)
    }
}
