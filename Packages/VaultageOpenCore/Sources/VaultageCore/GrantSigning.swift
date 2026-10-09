import CryptoKit
import Foundation
import Security

// BL-136 step 1 (D70 amendment 2) — grant records carry a MAC under a key only
// this Mac's signed Vaultage binaries can read.
//
// A grant's `digest` is an unkeyed SHA-256 over the records it covers, so any
// process running as the same user could write a grant into `metadata.json`
// with a digest it computed itself, and `authorizingGrant` had no way to tell
// it from one the owner approved on a sheet with Touch ID. The MAC is what
// tells them apart: it is computed at every write the broker makes to a grant
// — commit, arming, revocation, the device kill switch — under a key that
// lives in the custody Keychain access group and nowhere else, and a grant
// whose MAC is missing or wrong authorizes nothing. It is a key, not a
// credential: it opens no vault item, and it is never shown, exported or
// mirrored.
//
// **What it holds, and what it does not.** On a signed build the key is filed
// under the custody access group, which only this team's signed binaries can
// read; on an unsigned or developer-override build `KeychainAccessGroup` takes
// its implicit-group fallback and the key is no better protected than any
// other item of that process, so the guarantee is a property of
// `LaunchDecision.pinned` alone. And the stamp covers the record, not the
// file: rolling `metadata.json` back to a copy taken before a revocation
// restores a grant the owner revoked, with its stamp. Closing that needs
// revocation state kept outside the file, which step 4's per-session arming
// is the first part of.

/// What can sign a grant. The broker holds one; every place a grant is created
/// or armed stamps it, and `authorizingGrant` checks it.
public protocol GrantSigning: Sendable {
    /// The MAC over the grant's identity and its approved shape. Throws when
    /// the key cannot be read, which the caller treats as "no grant".
    func mac(for grant: Grant) throws -> String
    /// Audit H-08. The highest `revocationGeneration` this Mac's broker has
    /// written, kept where a same-user writer cannot roll it back. A file
    /// below it has been restored from before a revocation.
    func revocationWatermark() -> Int
    /// Raises the anchor; never lowers it.
    func raiseRevocationWatermark(to generation: Int) throws
}

public extension GrantSigning {
    /// Whether `state` is at or past every revocation this Mac has written.
    func isCurrent(_ state: VaultageMetadata) -> Bool { state.revocationGeneration >= revocationWatermark() }
}

/// HMAC-SHA256 over the fields a human approved and every stamp that decides
/// whether the grant is live — including `revokedAt` and `deviceKillSwitch`.
/// Those only ever narrow when present, but a writer who can add a field can
/// delete one, and a revocation that could be undone by removing its key from
/// the file would be no revocation at all.
public struct GrantSigner: GrantSigning {
    private let key: SymmetricKey
    /// The in-memory anchor, shared by every copy of this signer (a class), so
    /// a broker and a test that hold the same signer see the same watermark.
    private let anchor = Watermark()

    public init(keyData: Data) { key = SymmetricKey(data: keyData) }

    public func revocationWatermark() -> Int { anchor.value }
    public func raiseRevocationWatermark(to generation: Int) throws { anchor.raise(to: generation) }

    private final class Watermark: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = 0
        var value: Int { lock.lock(); defer { lock.unlock() }; return stored }
        func raise(to generation: Int) { lock.lock(); stored = max(stored, generation); lock.unlock() }
    }

    /// One random key for this process. The default for a broker that is
    /// composed without a Keychain — the self-tests, and nothing that ships:
    /// `BrokerServiceComposition` always supplies the Keychain key.
    public static let processEphemeral: GrantSigner = {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("Vaultage could not obtain secure random bytes for a grant signing key.")
        }
        return GrantSigner(keyData: Data(bytes))
    }()

    /// The dates are taken to the whole second, because that is what
    /// `metadata.json` keeps of them (`MetadataStore` encodes ISO 8601 without
    /// fractional seconds, truncating): a grant signed in memory and read back
    /// from disk must be the same preimage.
    public static func fields(of grant: Grant) -> [String] {
        [
            "vaultage.grant.mac.v1",
            grant.id.uuidString,
            grant.digest,
            grant.policyRevision,
            wholeSeconds(grant.createdAt),
            wholeSeconds(grant.expiresAt),
            "\(grant.duration.seconds)",
            grant.decidingDeviceID ?? "none",
            grant.armedAt.map(wholeSeconds) ?? "pending",
            grant.revokedAt.map(wholeSeconds) ?? "live",
            grant.deviceKillSwitch.map(wholeSeconds) ?? "none"
        ]
    }

    private static func wholeSeconds(_ date: Date) -> String {
        String(Int64(date.timeIntervalSince1970.rounded(.down)))
    }

    public func mac(for grant: Grant) throws -> String {
        let code = HMAC<SHA256>.authenticationCode(for: CanonicalDigest.encode(Self.fields(of: grant)), using: key)
        return code.map { String(format: "%02x", $0) }.joined()
    }

}

public extension GrantSigning {
    /// Whether `grant.mac` is this signer's, compared in constant time. A key
    /// that cannot be read verifies nothing.
    func verifies(_ grant: Grant) -> Bool {
        guard let recorded = grant.mac, let expected = try? mac(for: grant) else { return false }
        let left = Array(recorded.utf8), right = Array(expected.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

/// The shipping key: 32 random bytes in the **broker-only** Keychain access group (audit H-07),
/// created on first use, readable without a presence prompt (it is checked at
/// every auto-allow decision) and only by this team's signed binaries — the
/// access group is what a same-user process outside them lacks. Device-only,
/// never synchronised.
public final class KeychainGrantSigningKey: GrantSigning, @unchecked Sendable {
    public static let account = "grant-signing-key.v1"
    private let service: String
    private let accessGroupDecision: KeychainAccessGroup.LaunchDecision
    private let lock = NSLock()
    private var loaded: GrantSigner?

    public init(service: String = KeychainVault.service, accessGroupDecision: KeychainAccessGroup.LaunchDecision = KeychainAccessGroup.current) {
        self.service = service
        self.accessGroupDecision = accessGroupDecision
    }

    public func mac(for grant: Grant) throws -> String {
        try signer().mac(for: grant)
    }

    // MARK: Audit H-08 — the rollback anchor

    public static let watermarkAccount = "revocation-watermark.v1"

    public func revocationWatermark() -> Int {
        lock.lock(); defer { lock.unlock() }
        // Unreadable is treated as "no anchor": a key store that cannot be
        // read verifies no grant anyway (`mac(for:)` throws), so this cannot
        // widen; it only avoids refusing a file for a reason it did not have.
        return (try? Self.readWatermark(service: service, accessGroup: KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision))) ?? 0
    }

    public func raiseRevocationWatermark(to generation: Int) throws {
        lock.lock(); defer { lock.unlock() }
        let accessGroup = try KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision)
        let current = (try? Self.readWatermark(service: service, accessGroup: accessGroup)) ?? 0
        guard generation > current else { return }
        var value = UInt64(generation).bigEndian
        let data = Data(bytes: &value, count: 8)
        let query = KeychainAccessGroup.readAttributes(service: service, account: Self.watermarkAccount, accessGroup: accessGroup)
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecItemNotFound {
            var add = KeychainAccessGroup.saveAttributes(service: service, account: Self.watermarkAccount, accessGroup: accessGroup)
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else { throw VaultageError.storage("Could not record the revocation anchor (\(status)).") }
        } else if update != errSecSuccess {
            throw VaultageError.storage("Could not raise the revocation anchor (\(update)).")
        }
    }

    private static func readWatermark(service: String, accessGroup: String?) throws -> Int {
        let query = KeychainAccessGroup.readAttributes(service: service, account: watermarkAccount, accessGroup: accessGroup)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 8 else { throw VaultageError.storage("The revocation anchor record is not an 8-byte count.") }
            return Int(UInt64(bigEndian: data.withUnsafeBytes { $0.load(as: UInt64.self) }))
        case errSecItemNotFound:
            return 0
        default:
            throw VaultageError.storage("The revocation anchor is unavailable (\(status)).")
        }
    }

    private func signer() throws -> GrantSigner {
        lock.lock(); defer { lock.unlock() }
        if let loaded { return loaded }
        // Audit H-07: the broker-only group, which the app's entitlement does
        // not carry, so a compromised GUI process cannot forge a grant.
        let accessGroup = try KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision)
        if let existing = try Self.stored(service: service, accessGroup: accessGroup) {
            loaded = existing
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultageError.storage("Could not create a grant signing key.")
        }
        var query = KeychainAccessGroup.saveAttributes(service: service, account: Self.account, accessGroup: accessGroup)
        query[kSecValueData as String] = Data(bytes)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let add = SecItemAdd(query as CFDictionary, nil)
        let signer: GrantSigner
        switch add {
        case errSecSuccess:
            signer = GrantSigner(keyData: Data(bytes))
        case errSecDuplicateItem:
            // Another of our processes created it between the read and the
            // add: theirs is the key, ours is discarded. A plain second read —
            // the lock is not re-entrant, so this is not a call to `signer()`.
            guard let theirs = try Self.stored(service: service, accessGroup: accessGroup) else {
                throw VaultageError.storage("The grant signing key was created by another process and could not be read back.")
            }
            signer = theirs
        default:
            throw VaultageError.storage("Could not save the grant signing key (\(add)).")
        }
        loaded = signer
        return signer
    }

    /// The stored key, nil when there is none yet. Any other outcome — a
    /// refused read, a record of the wrong length — is an error, never a fresh
    /// key: two keys would make every grant from before the second one worthless.
    private static func stored(service: String, accessGroup: String?) throws -> GrantSigner? {
        let query = KeychainAccessGroup.readAttributes(service: service, account: Self.account, accessGroup: accessGroup)
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 32 else {
                throw VaultageError.storage("The grant signing key record is not a 32-byte key.")
            }
            return GrantSigner(keyData: data)
        case errSecItemNotFound:
            return nil
        default:
            throw VaultageError.storage("The grant signing key is unavailable (\(status)).")
        }
    }
}
