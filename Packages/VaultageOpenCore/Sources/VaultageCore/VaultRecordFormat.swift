import CryptoKit
import Foundation

// BL-100 slice A — the sealed record format of `13-MULTI-DEVICE-CUSTODY.md` §3.2.
//
// **Slice A syncs adds and edits only.** Nothing here writes a `tomb`, and
// nothing here creates `vkx` or writes a wrap row addressed to one — that is
// slice B, and it is the one irreversible act (§15, BL-100's slice table).
// What this file owns is the shape of a record on disk and on the wire: the
// AEAD envelope and its AAD, the opaque `wireID`, and the padding buckets.

/// §3.1's record kinds. `head` is the seventh kind and is *retained rather than
/// synced*, so it is not a `VaultRecordKind`: it has no envelope, no `wireID`
/// and no bucket, and it lives in `VaultHeadChainStore` (§3.1, §10).
public enum VaultRecordKind: String, Codable, Sendable, CaseIterable {
    case vault
    case folder
    case item
    case value
    case blob
    /// **Slice C (BL-110).** Declared here so BL-102's schema can hold it;
    /// nothing in slice A writes, reads or syncs one (§3.1's row).
    case tomb

    /// The slice that may write this kind. `VaultCipherStore` refuses a
    /// slice-C kind, so "nothing in slice A writes one" is enforced rather
    /// than described.
    public var isSliceA: Bool { self != .tomb }

    /// §3.2's record classes, which are what the bucket table is indexed by and
    /// therefore the whole of what a bucket discloses.
    ///
    /// **`vault` has its own class from the second pass** (seventeenth pass,
    /// DB17-C1). It was in `metadata` with `folder`, `item` and `tomb`, whose
    /// ladder tops out at 16 KiB — which was true of a `vault` record carrying
    /// *"name, kind, archivedAt, key generation, `RK_v.public`, sequencer
    /// `deviceId`"* and is **false** of the one this build seals, because slice
    /// A resolved §3.2's openability question by putting the vault's
    /// **membership** in that record (`VaultMembership`). A membership for a
    /// vault at bound 2's cap is ~1.8 MiB, so under the old table the `vault`
    /// record lost its bucket — and a missing bucket is a refusal — at a few
    /// hundred records.
    public var sizeClass: VaultRecordSizeClass {
        switch self {
        case .vault: .vault
        case .folder, .item, .tomb: .metadata
        case .value: .value
        case .blob: .blob
        }
    }
}

/// §3.2's bucket table, re-derived from `CompositeCredential`'s own bounds:
/// `CompositeCredential.swift:"public static let maximumFieldBytes = 64 * 1024"`
/// times `CompositeCredential.swift:"public static let maximumFields = 8"` is
/// ≈512 KiB plus header, which is where the 1 MiB top bucket comes from.
public enum VaultRecordSizeClass: String, Sendable {
    case metadata
    /// **The `vault` record's own class** (version 20 item 1; seventeenth pass,
    /// DB17-C1). 256 B, 1 KiB, 4 KiB, 16 KiB, then **64 KiB steps to an 8 MiB
    /// cap**, derived from bound 2's 50,000 live records at **under 160 bytes
    /// an entry** — §3.1 puts the vault's membership inside this record, so the
    /// record grows with the vault. A `vault` record over 8 MiB is a missing
    /// bucket and therefore a **refusal** like any other, which is bound 2's own
    /// refusal arriving one record early rather than a new failure mode.
    case vault
    case value
    case blob

    public var buckets: [Int] {
        switch self {
        case .metadata: [256, 1024, 4 * 1024, 16 * 1024]
        case .vault:
            [256, 1024, 4 * 1024, 16 * 1024]
                + stride(from: 64 * 1024, through: 8 * 1024 * 1024, by: 64 * 1024).map { $0 }
        case .value: [256, 1024, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        case .blob: stride(from: 64 * 1024, through: 10 * 1024 * 1024, by: 64 * 1024).map { $0 }
        }
    }

    /// The smallest bucket that holds `count` bytes, or `nil` when the record
    /// is larger than anything this class admits. A missing bucket is a
    /// **refusal**: the three ways a builder resolves one — refuse, truncate,
    /// invent — are a silent migration failure, a false success and an
    /// unanalysed leak (§3.2).
    public func bucket(for count: Int) -> Int? { buckets.first { $0 >= count } }
}

/// The subject a record is keyed on: its kind and its id.
///
/// For a `value` record the id is **`(keychainAccount, credentialVersion)`**,
/// joined by one `|` with the version spelled `none` when absent — §2.3's
/// `subjectID` rule, stated once and used by both the wrap preimage (slice B)
/// and the `wireID` here. A field whose `keychainAccount` equals the item's
/// produces **no separate record**: it *is* the primary (§3.1).
public struct VaultRecordSubject: Hashable, Sendable, Codable {
    public let kind: VaultRecordKind
    public let recordID: String

    public init(kind: VaultRecordKind, recordID: String) {
        self.kind = kind
        self.recordID = recordID
    }

    public static func vault(_ vaultID: UUID) -> VaultRecordSubject {
        VaultRecordSubject(kind: .vault, recordID: vaultID.uuidString.lowercased())
    }

    public static func folder(_ folderID: UUID) -> VaultRecordSubject {
        VaultRecordSubject(kind: .folder, recordID: folderID.uuidString.lowercased())
    }

    public static func item(_ itemID: UUID) -> VaultRecordSubject {
        VaultRecordSubject(kind: .item, recordID: itemID.uuidString.lowercased())
    }

    /// §2.3, seventh pass DB7-L4: one canonical string, encoded as exactly one
    /// field. A builder who encoded the pair as two fields would make all three
    /// wrap counts wrong.
    public static func value(keychainAccount: String, credentialVersion: UUID?) -> VaultRecordSubject {
        let version = credentialVersion?.uuidString.lowercased() ?? "none"
        return VaultRecordSubject(kind: .value, recordID: "\(keychainAccount.lowercased())|\(version)")
    }

    public static func blob(_ attachmentID: String) -> VaultRecordSubject {
        VaultRecordSubject(kind: .blob, recordID: attachmentID)
    }
}

/// §3.2's opaque wire identifier.
///
/// `wireID = HMAC-SHA256(VIK_v, "vaultage.vault.wireid.v1" ‖ recordKind ‖ recordID)`,
/// truncated to 128 bits. The control plane cannot tell an `item` record from a
/// `folder` record, follow an item across a rename, or correlate two accounts.
public enum VaultWireID {
    public static let domain = "vaultage.vault.wireid.v1"

    public static func compute(identityKey: SymmetricKey, subject: VaultRecordSubject) -> String {
        var preimage = Data(domain.utf8)
        preimage.append(Data(subject.kind.rawValue.utf8))
        preimage.append(Data(subject.recordID.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: preimage, using: identityKey)
        return Data(mac).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    /// A `wireID` is 128 bits of lowercase hex and nothing else. The store
    /// keys files on it, so a caller-supplied identifier that is not one is a
    /// path-traversal question rather than a naming question.
    public static func isWellFormed(_ value: String) -> Bool {
        value.count == 32 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}

/// §3.2's envelope AAD, at its stated count.
///
/// > `aad: CanonicalDigest.encode(["vaultage.vault.record.v2", "6",
/// >  accountSubject, vaultID, recordKind, recordID, keyGeneration, revision])`
///
/// Binding `accountSubject` means a record moved between accounts fails
/// authentication; binding `revision` means a record cannot be rolled back to
/// an earlier ciphertext under a later number; binding `recordKind` means a
/// `value` cannot be re-filed as an `item`; binding `keyGeneration` is what
/// makes C-3's fence enforceable at the record rather than only at the head.
public enum VaultRecordAAD {
    public static let domain = "vaultage.vault.record.v2"
    /// Rule 1's leading arity count, **computed from the body** rather than
    /// asserted, because that is the convention four consecutive passes were
    /// spent getting wrong (§3.2).
    public static func fields(
        accountSubject: String,
        vaultID: UUID,
        subject: VaultRecordSubject,
        keyGeneration: Int,
        revision: Int
    ) -> [String] {
        let body = [
            accountSubject,
            vaultID.uuidString.lowercased(),
            subject.kind.rawValue,
            subject.recordID,
            "\(keyGeneration)",
            "\(revision)"
        ]
        return [domain, "\(body.count)"] + body
    }

    public static func encode(
        accountSubject: String,
        vaultID: UUID,
        subject: VaultRecordSubject,
        keyGeneration: Int,
        revision: Int
    ) -> Data {
        CanonicalDigest.encode(fields(
            accountSubject: accountSubject,
            vaultID: vaultID,
            subject: subject,
            keyGeneration: keyGeneration,
            revision: revision
        ))
    }
}

/// What a record looks like on the wire and in `VaultCipherStore`.
///
/// The header is **value-free and kind-free**: `wireID`, `revision`,
/// `keyGeneration` and the padded ciphertext. The record's kind and id live in
/// the AAD, which the opener supplies from its own resolution of the `wireID`
/// (see `VaultWireIndex`), so the relay learns neither.
public struct VaultSealedRecord: Codable, Sendable, Equatable {
    public let wireID: String
    public let revision: Int
    public let keyGeneration: Int
    /// AES-256-GCM combined representation (nonce ‖ ciphertext ‖ tag).
    public let sealed: Data

    public init(wireID: String, revision: Int, keyGeneration: Int, sealed: Data) {
        self.wireID = wireID
        self.revision = revision
        self.keyGeneration = keyGeneration
        self.sealed = sealed
    }

    public var byteCount: Int { sealed.count }
}

/// The errors the record format raises. Each is a refusal a caller can say
/// something true about; none of them can be reached by a partially-written
/// file (`VaultCipherStore` writes atomically).
public enum VaultRecordError: Error, Equatable, Sendable, LocalizedError {
    case sliceCKind(VaultRecordKind)
    case overBucket(kind: VaultRecordKind, bytes: Int)
    case malformedWireID(String)
    case authenticationFailed(wireID: String, revision: Int)
    case storage(String)

    public var errorDescription: String? {
        switch self {
        case .sliceCKind(let kind):
            "Nothing in this release writes a \(kind.rawValue) record — deletion sync is a later release (BL-110)."
        case .overBucket(let kind, let bytes):
            "A \(kind.rawValue) record of \(bytes) bytes is larger than any size bucket this format defines."
        case .malformedWireID(let value):
            "That is not a record identifier: \(value.prefix(16))."
        case .authenticationFailed(let wireID, let revision):
            "A sealed record did not open (\(wireID.prefix(8))…, revision \(revision))."
        case .storage(let detail):
            detail
        }
    }
}

/// The seal and the open, with §3.2's padding applied before the AEAD so a
/// bucket is a property of the ciphertext rather than of a claim about it.
///
/// The padding is length-prefixed inside the plaintext — four big-endian bytes
/// of true length, then the bytes, then zeroes to the bucket — so the open
/// recovers the exact plaintext and a bucket boundary leaks only the bucket.
public enum VaultRecordEnvelope {
    public static func seal(
        plaintext: Data,
        key: SymmetricKey,
        accountSubject: String,
        vaultID: UUID,
        subject: VaultRecordSubject,
        keyGeneration: Int,
        revision: Int,
        wireID: String
    ) throws -> VaultSealedRecord {
        guard subject.kind.isSliceA else { throw VaultRecordError.sliceCKind(subject.kind) }
        guard VaultWireID.isWellFormed(wireID) else { throw VaultRecordError.malformedWireID(wireID) }
        let padded = try pad(plaintext, class: subject.kind.sizeClass, kind: subject.kind)
        let aad = VaultRecordAAD.encode(
            accountSubject: accountSubject,
            vaultID: vaultID,
            subject: subject,
            keyGeneration: keyGeneration,
            revision: revision
        )
        do {
            let box = try AES.GCM.seal(padded, using: key, authenticating: aad)
            guard let combined = box.combined else {
                throw VaultRecordError.storage("Could not serialize a sealed record.")
            }
            return VaultSealedRecord(wireID: wireID, revision: revision, keyGeneration: keyGeneration, sealed: combined)
        } catch let error as VaultRecordError {
            throw error
        } catch {
            throw VaultRecordError.storage("Could not seal a record.")
        }
    }

    public static func open(
        _ record: VaultSealedRecord,
        key: SymmetricKey,
        accountSubject: String,
        vaultID: UUID,
        subject: VaultRecordSubject
    ) throws -> Data {
        let aad = VaultRecordAAD.encode(
            accountSubject: accountSubject,
            vaultID: vaultID,
            subject: subject,
            keyGeneration: record.keyGeneration,
            revision: record.revision
        )
        do {
            let box = try AES.GCM.SealedBox(combined: record.sealed)
            let padded = try AES.GCM.open(box, using: key, authenticating: aad)
            return try unpad(padded)
        } catch {
            throw VaultRecordError.authenticationFailed(wireID: record.wireID, revision: record.revision)
        }
    }

    static func pad(_ plaintext: Data, class sizeClass: VaultRecordSizeClass, kind: VaultRecordKind) throws -> Data {
        var framed = Data()
        var length = UInt32(plaintext.count).bigEndian
        withUnsafeBytes(of: &length) { framed.append(contentsOf: $0) }
        framed.append(plaintext)
        guard let bucket = sizeClass.bucket(for: framed.count) else {
            throw VaultRecordError.overBucket(kind: kind, bytes: plaintext.count)
        }
        framed.append(Data(repeating: 0, count: bucket - framed.count))
        return framed
    }

    static func unpad(_ padded: Data) throws -> Data {
        guard padded.count >= 4 else { throw VaultRecordError.storage("A sealed record's padding frame is truncated.") }
        let header = padded.prefix(4)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let start = padded.index(padded.startIndex, offsetBy: 4)
        guard Int(length) <= padded.count - 4 else {
            throw VaultRecordError.storage("A sealed record declares more plaintext than it carries.")
        }
        let end = padded.index(start, offsetBy: Int(length))
        return Data(padded[start ..< end])
    }
}

/// **The `vault` record's own membership** — §3.1's `vault` row and §3.2's
/// openability answer, ratified and sized by version 20 (item 1; seventeenth
/// pass, DB17-C1).
///
/// `wireID` is HMAC'd under `VIK_v` and runs **forward only**, and §3.2's AAD
/// binds `recordKind` and `recordID`, so an opener has to know the pair
/// **before** it decrypts. A fresh device — §6.2a's kit restore, §5.1's new
/// pairing — holds the vault id and nothing else, so it can address exactly one
/// record: the `vault` record, whose `recordID` **is** that vault id. §3.1
/// therefore puts *"the `(recordKind, recordID)` pair of every live record in
/// it, keyed by `wireID`"* inside that record's plaintext, which is inside the
/// AEAD: §3.4 does not grow, and §2.3's `subjectID` is **not** a resolution
/// channel.
///
/// **What that makes decidable**, which is the finding's real question. An
/// unresolvable `wireID` was a `folder` (a fold failure for the vault) or an
/// `item`, `value` or `blob` (retained, marked, counted) with no way for the
/// device to tell which. Under this map the branch is never guessed: either the
/// `vault` record has opened, and then every live record's pair is here and each
/// takes its own branch — or the `vault` record has **not** opened, and then it
/// is itself the fold failure and **nothing below it is reachable at all**.
public struct VaultMembership: Codable, Sendable, Equatable {
    /// **A fixed-size entry, over a quantity something bounds** (eighteenth
    /// pass, DB18-H1). Version 20 derived the 8 MiB cap from *"under 160 bytes
    /// an entry"*, which is right for a `value` id — *"two lowercase UUID
    /// strings joined by one `|`"* — and right **only** while that is what a
    /// `value` id is. It is built from `Models.swift:"public var keychainAccount: String"`,
    /// which nothing bounds: `VaultItemTypes` bounds the field *key* at 128 and
    /// the field *text* at 4,096 and the account at nothing, so A-2 writes items
    /// with 10 KB accounts and the `vault` record loses its bucket at around 800
    /// records instead of 50,000 — a wedge sixty times cheaper than bound 2.
    ///
    /// So the entry is **`(wireID, kind, recordID)` and nothing else, and each
    /// of the three has a compiled bound** (custody plan version 21): the
    /// `wireID` is 32 lowercase hex; the kind is one of six enum names; and the
    /// `recordID` is a 36-character lowercased UUID for a `vault`, `folder` or
    /// `item`, a 64-character content address for a `blob`, and for a `value`
    /// the pair `"\(keychainAccount)|\(credentialVersion)"` — **with
    /// `keychainAccount` bounded at the 36-character lowercase UUID string the
    /// provisioning path already mints**. The account is an opaque minted
    /// identifier and never owner text — what an owner types is the field's key
    /// and label, which live in the `item` record under `maximumKeyLength` and
    /// `maximumTextLength` — so bounding it costs the product nothing, and an
    /// `item` whose account is not one is refused at the write.
    public static let listedKinds: [VaultRecordKind] = VaultRecordKind.allCases.filter(\.isSliceA)
    /// The bound on one `recordID`: a `value`'s pair is two 36-character UUID
    /// strings and one `|`, which is the longest any kind presents.
    public static let recordIDFieldBytes = 36 + 1 + 36
    /// The largest entry, encoded the way the shipped `[String:
    /// VaultRecordSubject]` is — **about 140 bytes, and under 160 in every
    /// case**, the `value` being the largest because every other kind's id is
    /// shorter.
    public static let maximumEntryBytes = 160
    /// The map's own framing, which the JSON object's braces are.
    public static let headerBytes = 2

    /// **How many entries one `index` page holds** (custody plan version 22
    /// item 4). The map leaves the `vault` record for append-only `index`
    /// pages in §3.2's **16 KiB** metadata class, and 96 × `maximumEntryBytes`
    /// is 15,360 — inside 16,384 with the page's own framing to spare.
    ///
    /// It is the number `maximumIndexPagesPerVault` divides the addressable cap
    /// by, so bound 2's record half derives from it rather than from a figure
    /// somebody picked.
    public static let maximumIndexEntriesPerPage = 96

    /// The membership's own ceiling, **derived from bound 2 rather than
    /// chosen**: a vault may hold `maximumLiveRecordsPerVault` live records, so
    /// 50,000 entries at under 160 bytes each is under 8 MiB.
    public static var maximumEncodedBytes: Int {
        headerBytes + VaultRecordBudget.maximumLiveRecordsPerVault * maximumEntryBytes
    }

    /// **The cap is the round power of two above the derivation's product**, and
    /// this says so rather than implying it (custody plan version 21): 50,000
    /// entries at the measured ~140 bytes is under 8,000,000, the bucket table
    /// gives 8,388,608, and the 388,608 bytes between them are what the `vault`
    /// record's other plaintext — name, kind, `archivedAt`, key generation,
    /// `RK_v.public`, sequencer `deviceId` — and the padding frame come out of.
    public static let sizeClassCap = 8 * 1024 * 1024

    /// **The account bound, in one place, at the shape the product actually
    /// mints** (nineteenth pass). `keychainAccount` is decoded from the record
    /// with no length rule, so this is what an `item` write and a membership
    /// entry are both checked against — and the product writes
    /// `Broker.swift`'s `let keychainAccount = UUID().uuidString`, which is
    /// **uppercase**. A lowercase-only rule would have refused every credential
    /// the product creates, which is a bound that fails closed on the honest
    /// path: the point is to exclude the 10 KB account A-2 chooses, not the
    /// 36-character identifier this codebase mints.
    ///
    /// The subject builder lowercases it into the `recordID`
    /// (`VaultRecordSubject.value`), so both cases reach this and both are
    /// admitted; what is refused is anything that is not a UUID string.
    public static func isMintedAccount(_ account: String) -> Bool {
        guard account.utf8.count == 36 else { return false }
        return UUID(uuidString: account) != nil
    }

    /// The `vault` record's non-membership half — name, kind, `archivedAt`, key
    /// generation, `RK_v.public`, sequencer `deviceId` (§3.1) — which is what
    /// the 16 KiB `metadata` bucket was derived for and still bounds.
    public static let maximumFixedFieldBytes = 16 * 1024

    /// What the `vault` class's top bucket has to admit, and therefore the one
    /// number that gates the table above.
    public static var maximumVaultRecordBytes: Int { maximumFixedFieldBytes + maximumEncodedBytes }

    public enum MembershipError: Error, Equatable, Sendable, LocalizedError {
        case unlistableKind(VaultRecordKind)
        case malformedWireID(String)
        case entryTooLarge(bytes: Int)
        /// **A `value` id whose account half is not the minted UUID** — the one
        /// quantity nothing bounded, and the one the 8 MiB derivation rests on.
        case unmintedAccount(String)
        case malformedEncoding(String)

        public var errorDescription: String? {
            switch self {
            case .unlistableKind(let kind):
                "Nothing in this release lists a \(kind.rawValue) record in a vault's membership."
            case .malformedWireID(let value):
                "A vault membership entry is not keyed on a record identifier: \(value.prefix(16))."
            case .entryTooLarge(let bytes):
                "A vault membership entry of \(bytes) bytes is larger than this format's entry ceiling."
            case .unmintedAccount:
                "A credential's account is not one Vaultage minted, so it cannot be listed in a vault's membership."
            case .malformedEncoding(let detail):
                detail
            }
        }
    }

    /// `wireID → (recordKind, recordID)`, which is §3.1's own wording.
    public private(set) var entries: [String: VaultRecordSubject]

    public init(entries: [String: VaultRecordSubject] = [:]) { self.entries = entries }

    /// Adds a live record, computing its `wireID` the way both devices do.
    public mutating func add(_ subject: VaultRecordSubject, identityKey: SymmetricKey) throws {
        try add(subject, wireID: VaultWireID.compute(identityKey: identityKey, subject: subject))
    }

    public mutating func add(_ subject: VaultRecordSubject, wireID: String) throws {
        guard Self.listedKinds.contains(subject.kind) else { throw MembershipError.unlistableKind(subject.kind) }
        guard VaultWireID.isWellFormed(wireID) else { throw MembershipError.malformedWireID(wireID) }
        let bytes = subject.recordID.utf8.count
        guard bytes <= Self.recordIDFieldBytes else { throw MembershipError.entryTooLarge(bytes: bytes) }
        // A `value`'s id is the account pair, and the account half is the one
        // nothing bounded — which is the quantity the 8 MiB derivation rests
        // on, so an unbounded one is refused here as well as at the write.
        if subject.kind == .value {
            let account = String(subject.recordID.prefix { $0 != "|" })
            guard Self.isMintedAccount(account) else { throw MembershipError.unmintedAccount(account) }
        }
        entries[wireID] = subject
    }

    public var count: Int { entries.count }

    /// One entry's encoded size, **measured rather than asserted**: the map is
    /// encoded the way the shipped `[String: VaultRecordSubject]` is, so what a
    /// contract measures is what a record carries.
    public static func entryBytes(wireID: String, subject: VaultRecordSubject) -> Int {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let one = try? encoder.encode([wireID: subject]) else { return maximumEntryBytes }
        // `{}` is the empty map; each further entry adds a separator.
        return one.count - headerBytes + 1
    }

    public func encode() throws -> Data {
        for (wireID, subject) in entries {
            guard Self.listedKinds.contains(subject.kind) else { throw MembershipError.unlistableKind(subject.kind) }
            let bytes = Self.entryBytes(wireID: wireID, subject: subject)
            guard bytes <= Self.maximumEntryBytes else { throw MembershipError.entryTooLarge(bytes: bytes) }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(entries)
    }

    public static func decode(_ data: Data) throws -> VaultMembership {
        guard let entries = try? JSONDecoder().decode([String: VaultRecordSubject].self, from: data) else {
            throw MembershipError.malformedEncoding("A vault membership did not decode.")
        }
        var membership = VaultMembership()
        for (wireID, subject) in entries { try membership.add(subject, wireID: wireID) }
        return membership
    }
}

/// `wireID → (recordKind, recordID)`, per vault, broker-owned and device-local.
///
/// **Derived and memory-only** (eighteenth pass, DB18-M1). It is the resolved
/// form of the `vault` record's membership, rebuilt from that record every time
/// flow 7 opens it; it is **never written to disk**. An earlier draft of this
/// comment said it was *"cached in the broker's container beside the store"*,
/// and `VaultContainerPath` has no path for it — so persisting it would fail
/// §10's own container walk, which is the check that caught the claim. §10
/// carries a row for it with no path and no protection class, the same shape
/// the list projection's row has and for the same reason.
///
/// It holds **no key, no ciphertext and no label**. Every subject yields its
/// `wireID` by the same HMAC both devices compute, so the resolution is one
/// forward pass over the map — and a `value` resolves one layer further down,
/// from the `item` record that names its account and its credential version.
public struct VaultWireIndex: Codable, Sendable, Equatable {
    public private(set) var subjects: [String: VaultRecordSubject]

    public init(subjects: [String: VaultRecordSubject] = [:]) { self.subjects = subjects }

    /// The index a device holds the moment the `vault` record opens, and the
    /// **only** thing that seeds it. The `vault` record's own subject is in it
    /// because that one is resolvable from the vault id alone.
    public static func resolving(
        _ membership: VaultMembership,
        vaultID: UUID,
        identityKey: SymmetricKey
    ) -> VaultWireIndex {
        var index = VaultWireIndex(subjects: membership.entries)
        // The vault record's own pair is resolvable from the vault id alone,
        // which is why it is the one record a fresh device can address and why
        // the cheap answer was available at all (§5.1 pins the vault id into
        // the QR payload and the SAS).
        let own = VaultRecordSubject.vault(vaultID)
        index.record(own, wireID: VaultWireID.compute(identityKey: identityKey, subject: own))
        return index
    }

    public mutating func record(_ subject: VaultRecordSubject, wireID: String) {
        subjects[wireID] = subject
    }

    public func subject(for wireID: String) -> VaultRecordSubject? { subjects[wireID] }

    public var count: Int { subjects.count }
}
