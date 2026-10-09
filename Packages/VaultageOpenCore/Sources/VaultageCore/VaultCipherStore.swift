import CryptoKit
import Darwin
import Foundation

// BL-100 slice A — the broker-owned container, its declared manifest, and the
// local sealed record store (`13-MULTI-DEVICE-CUSTODY.md` §3.2, §7.1, §10).
//
// **Where the sealed store lives is a slice A decision, and it is the broker's
// container** (seventh pass, DB7-M5). It costs nothing today — the broker
// already runs all seven batch flows and already performs *apply* — and it is
// where the bound can be placed if BL-109 answers "broker-only group". A
// container plus an RPC hop is an **indirection, not a bound**: what bounds
// "read the sealed store from disk" is what the XPC interface returns, which is
// §3.2's table and `BrokerProtocol.swift`'s slice-A rows.

/// The one place that answers "which directory does the broker own?".
///
/// It hangs off the metadata directory, so `VAULTAGE_METADATA_DIRECTORY` moves
/// the whole container with it on a development build exactly as it already
/// moves `attachments/` — which is what lets every test below, and the BL-042
/// gate driver's isolated-store route, run without opening the owner's real
/// store or their Keychain.
public struct BrokerContainer: Sendable, Equatable {
    public let root: URL

    public init(root: URL) { self.root = root.standardizedFileURL }

    /// The production composition: `<metadata directory>/broker`.
    public init(metadataDirectory: URL = MetadataStore.defaultDirectory) {
        self.init(root: metadataDirectory.appendingPathComponent("broker", isDirectory: true))
    }

    public func directory(_ path: VaultContainerPath) -> URL {
        root.appendingPathComponent(path.rawValue, isDirectory: true)
    }

    /// Creates the container root 0700. Every write below re-asserts the mode,
    /// because a directory created by an earlier build is not this build's.
    public func ensure() throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    }
}

/// The path classes §10's container manifest declares. A path the broker
/// creates that is not one of these fails the walk.
public enum VaultContainerPath: String, Sendable, CaseIterable, Codable {
    case cipherStore = "VaultCipherStore"
    case heads = "heads"
    case deletionQueue = "deletionQueue"
    case fence = "fence"
    /// §7.1's persisted fold-failure markers, new in version 17 (fifteenth
    /// pass, DB15-H1): the projection is memory-only and flow 7's own trigger
    /// is *"`renderList` finds no projection"*, which fires on exactly the
    /// broker restart that would otherwise erase the state.
    case foldFailures = "foldFailures"
    /// §7.1's persisted **head** refusals, new with the sixteenth pass
    /// (DB16-C1): a served head that breaks a bound is refused **as a whole**,
    /// before apply, and the refusal is keyed on the head digest so the device
    /// does not re-fetch the same bytes in a loop.
    case headRefusals = "headRefusals"
    /// **Slice C (BL-110).** Declared so the manifest is the whole table rather
    /// than slice A's half of it; nothing in slice A creates it.
    case durations = "durations"
}

/// §10's container manifest — **the second of the two enforcement tests**
/// (twelfth pass, DB12-H2).
///
/// Version 13 leaned on the `VaultageMetadata` collection enumeration three
/// times for things that enumeration structurally cannot see: the retained
/// `head` chain, the `deletionQueue`, and — as the stated catch for a builder's
/// shortcut — a projection cached to disk. None of the three is a property on a
/// `Codable` struct; all three are files. So every path the broker creates
/// under its container is declared here with its platform, kind, protection
/// class and retention horizon, and `walk(_:)` fails on an undeclared path.
///
/// **The projection's row is the point of the manifest**: it declares *no
/// path*, so a projection cached to disk has nowhere legal to be.
public struct VaultContainerManifest: Sendable {
    public struct Row: Sendable, Equatable {
        public let platform: Platform
        /// Which root this row is under. The two **shipped** rows are in the
        /// metadata directory rather than the broker's container, which is why
        /// the manifest needed a location column when the fifteenth pass added
        /// them.
        public let location: Location
        /// `nil` is the projection's row — memory only, and declaring a path
        /// for it is the failure the manifest exists to catch — and the two
        /// shipped rows', which name files rather than a path class.
        public let path: VaultContainerPath?
        public let fileNames: [String]
        public let kind: String
        public let protectionClass: ProtectionClass
        public let horizon: String
        public let slice: Slice

        public init(
            platform: Platform,
            location: Location,
            path: VaultContainerPath?,
            fileNames: [String] = [],
            kind: String,
            protectionClass: ProtectionClass,
            horizon: String,
            slice: Slice
        ) {
            self.platform = platform
            self.location = location
            self.path = path
            self.fileNames = fileNames
            self.kind = kind
            self.protectionClass = protectionClass
            self.horizon = horizon
            self.slice = slice
        }
    }

    public enum Platform: String, Sendable, Equatable {
        case macOS
        case both
        case iOSContainingApp
        case iOSExtensionShared
    }
    public enum Location: String, Sendable, Equatable {
        case brokerContainer
        case metadataDirectory
        case memoryOnly
    }
    public enum Slice: String, Sendable, Equatable { case a = "A", c = "C", shipped }
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`'s file equivalent.
    /// `notApplicable` is the projection's, which has no file to protect.
    public enum ProtectionClass: String, Sendable, Equatable {
        case completeUntilFirstUserAuthentication
        /// **The honest macOS statement rather than an omission**: 0600 inside
        /// a 0700 directory, with no data-protection class set. That is what
        /// the two shipped rows have had since before this design existed.
        case posixOnly
        case notApplicable
    }

    /// The manifest, verbatim from §10's table at **version 17**, in full —
    /// the macOS rows, the two **shipped** rows the fifteenth pass added
    /// (`metadata.json` and `receipts.jsonl`, which the broker creates and
    /// which no earlier version declared), the projection's
    /// platform-independent row, slice C's `durations/`, and the four iOS rows.
    ///
    /// **BL-107 carries its own instance of the walk** over the containing
    /// app's container and the extension-shared one, because a macOS-target
    /// test cannot see a separate bundle's process (thirteenth pass, DB13-M4).
    /// The iOS rows are declared here so the manifest is the whole table rather
    /// than slice A's half of it.
    public static let rows: [Row] = [
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .cipherStore,
            kind: "sealed records — vault, item, folder, value, blob",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "the live set, plus at most one arriving revision per record until its first open promotes or discards it (§7.1); a record leaves when the head stops naming it",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .heads,
            kind: "the retained chain (§3.1's seventh kind) — head, signature, acceptedAtMonotonic, accumulators",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "30 days or 64 MiB per vault, oldest-first above the shared retentionFloor",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .deletionQueue,
            kind: "§7.3 part A's entries — kind, id, revision, Lamport, queuedAtMonotonic, vault",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "until restored, or until BL-110 drains it",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .fence,
            kind: "§3.3's persisted accumulator and the unsent-changes queue",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "zeroed at each successful head exchange; the queue until it transcodes and pushes",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .foldFailures,
            kind: "§7.1's fold markers — one per (vault, record), a set; a vault or folder marker blocks the vault, anything else is a record waiting for a readable copy",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "until a later arriving revision for that record opens",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .headRefusals,
            kind: "§7.1's head refusals — one per vault, keyed on the head digest **and the served-bytes digest**, so the same bytes are not re-fetched in a loop and an honest re-serve of the same head is not refused from disk (seventeenth pass, DB17-H1)",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "until this device admits a head for that vault, or the same head carrying different bytes",
            slice: .a
        ),
        Row(
            platform: .both,
            location: .memoryOnly,
            path: nil,
            fileNames: [],
            kind: "`VaultWireIndex`, the resolved form of the `vault` record's membership — **derived and memory-only**, rebuilt from that record at every open and never written down (eighteenth pass, DB18-M1)",
            protectionClass: .notApplicable,
            horizon: "the broker process's lifetime",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .metadataDirectory,
            path: nil,
            fileNames: ["metadata.json", "metadata.lock"],
            kind: "VaultageMetadata itself, which is what enforcement (a) enumerates",
            protectionClass: .posixOnly,
            horizon: "the life of the install",
            slice: .shipped
        ),
        Row(
            platform: .macOS,
            location: .metadataDirectory,
            path: nil,
            fileNames: ["receipts.jsonl", "receipts.quarantine.jsonl", "receipts.lock"],
            kind: "the never-sync receipt log, and from slice A the discard receipt's home",
            protectionClass: .posixOnly,
            horizon: "append-only; nothing sweeps it in release one",
            slice: .shipped
        ),
        Row(
            platform: .both,
            location: .memoryOnly,
            path: nil,
            kind: "the list projection",
            protectionClass: .notApplicable,
            horizon: "memory only; declaring a path for it is the failure the manifest exists to catch",
            slice: .a
        ),
        Row(
            platform: .macOS,
            location: .brokerContainer,
            path: .durations,
            kind: "W, both accumulator horizons, the pending run and its deadline, the aggregation day",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "per §7.3 part C",
            slice: .c
        ),
        Row(
            platform: .iOSContainingApp,
            location: .brokerContainer,
            path: .heads,
            kind: "the retained chain, as macOS",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "as macOS — non-purgeable, never a Caches directory",
            slice: .a
        ),
        Row(
            platform: .iOSContainingApp,
            location: .brokerContainer,
            path: .deletionQueue,
            kind: "§7.3 part A's entries, same shape (O-10)",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "until restored, or until BL-110 drains it",
            slice: .a
        ),
        Row(
            platform: .iOSContainingApp,
            location: .brokerContainer,
            path: .foldFailures,
            kind: "§7.1's fold markers, same shape — the iOS form follows this column (sixteenth pass, DB16-H4)",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "as macOS",
            slice: .a
        ),
        Row(
            platform: .iOSContainingApp,
            location: .brokerContainer,
            path: .headRefusals,
            kind: "§7.1's head refusals, same shape",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "as macOS",
            slice: .a
        ),
        Row(
            platform: .iOSContainingApp,
            location: .brokerContainer,
            path: .cipherStore,
            kind: "sealed records for the vaults not enabled for AutoFill",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "as macOS",
            slice: .a
        ),
        Row(
            platform: .iOSExtensionShared,
            location: .brokerContainer,
            path: .cipherStore,
            kind: "sealed records for the AutoFill-enabled vaults only",
            protectionClass: .completeUntilFirstUserAuthentication,
            horizon: "as macOS",
            slice: .a
        )
    ]

    /// The declared path classes **in the broker's container on this
    /// platform**, which is what the walk compares against.
    public static var declaredPaths: Set<String> {
        Set(rows
            .filter { $0.location == .brokerContainer && ($0.platform == .macOS || $0.platform == .both) }
            .compactMap { $0.path?.rawValue })
    }

    /// **Slice A creates five of the six declared macOS paths**; `durations/`
    /// is BL-110's and nothing here creates it.
    public static var sliceAPaths: Set<String> {
        Set(rows
            .filter { $0.slice == .a && $0.location == .brokerContainer && ($0.platform == .macOS || $0.platform == .both) }
            .compactMap { $0.path?.rawValue })
    }

    public struct Violation: Error, Equatable, Sendable, CustomStringConvertible {
        public let path: String
        public let reason: String
        public var description: String { "\(path): \(reason)" }
    }

    /// Walks the container and returns every undeclared path, newest rule
    /// first: a **top-level** entry that is not a declared path class, and any
    /// file directly in the container root. A builder's on-disk projection
    /// cache is both.
    public static func undeclared(in container: BrokerContainer) throws -> [Violation] {
        let manager = FileManager.default
        guard manager.fileExists(atPath: container.root.path) else { return [] }
        let entries = try manager.contentsOfDirectory(
            at: container.root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        var violations: [Violation] = []
        for entry in entries {
            let name = entry.lastPathComponent
            let isDirectory = (try? entry.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            guard isDirectory else {
                violations.append(Violation(path: name, reason: "a file in the broker's container root is declared by no manifest row"))
                continue
            }
            guard declaredPaths.contains(name) else {
                violations.append(Violation(path: name, reason: "an undeclared path class under the broker's container"))
                continue
            }
        }
        return violations
    }
}

/// §10's **other** enforcement test: every collection on `VaultageMetadata` is
/// classified sync or no-sync, and an unclassified new one fails the suite.
///
/// A table in a document does not stop the next collection from defaulting to
/// whatever the serializer does — so the table is here, beside the code, and
/// the self-test enumerates the type rather than reading the table.
public enum VaultSyncClassification: String, Sendable {
    case never
    case syncsValueFree
    case connectionOnly

    /// Keyed on `VaultageMetadata`'s own property names. Every collection the
    /// type declares must appear; a new one that does not fails the suite.
    public static let table: [String: VaultSyncClassification] = [
        // The vault itself. `vault`, `folder` and `item` records are what
        // slice A syncs — the value-free half of each is the projection, and
        // the credential is its own `value` record under its own key.
        "vaults": .syncsValueFree,
        "folders": .syncsValueFree,
        "vaultItems": .syncsValueFree,
        // Device-scoped by definition, or an authorization about this Mac.
        "projects": .never,
        "environments": .never,
        "connections": .connectionOnly,
        "bindings": .never,
        "runtimeSourceAuthorizations": .never,
        "runtimeInjectionAuthorizations": .never,
        "enrolledClients": .never,
        "grants": .never,
        "vaultItemDeletionReservations": .never,
        "freeActiveConnectionIDs": .never,
        "provisionedResources": .never,
        "pendingProvisionings": .never,
        "resourceMutationKeys": .never,
        "resources": .never,
        "inventoryRefreshes": .never,
        // BL-094 / D36: exactly the fact D36 wants visible, value-free.
        "deployedCredentials": .syncsValueFree,
        "rotations": .never,
        "devicePairings": .never,
        "deviceRevocations": .never,
        "everRevokedDeviceIDs": .never,
        "everRevokedKeyThumbprints": .never,
        "revocationSerialWatermarks": .never,
        "remoteDecisionReplays": .never,
        "audit": .never
    ]

    /// The collection-valued properties `VaultageMetadata` actually declares,
    /// read from the type rather than from a list. `Mirror` is the only
    /// mechanism available here: the suite runs as a plain executable with no
    /// XCTest and no reflection database.
    public static func declaredCollections(of value: VaultageMetadata = VaultageMetadata()) -> [String] {
        Mirror(reflecting: value).children.compactMap { child in
            guard let label = child.label else { return nil }
            let described = String(describing: type(of: child.value))
            let isCollection = described.hasPrefix("Array<")
                || described.hasPrefix("Set<")
                || described.hasPrefix("Dictionary<")
            return isCollection ? label : nil
        }
    }
}

/// What the store refuses.
public enum VaultCipherStoreError: Error, Equatable, Sendable, LocalizedError {
    case malformedWireID(String)
    case unknownRecord(String)
    case storage(String)

    public var errorDescription: String? {
        switch self {
        case .malformedWireID(let value): "That is not a record identifier: \(value.prefix(16))."
        case .unknownRecord(let wireID): "This Mac holds no record \(wireID.prefix(8))…."
        case .storage(let detail): detail
        }
    }
}

/// One record's two slots: the revision that **opened** and, at most, the one
/// revision that **arrived** beside it.
public struct VaultStoredRecord: Sendable, Equatable {
    public let wireID: String
    /// The last revision this device **opened**, which is what `normalize`
    /// reads and what a read returns. `nil` means the record has never opened
    /// here — a creation, and the case DB14-C1 is about.
    public let current: VaultSealedRecord?
    /// At most one. **The next arriving revision for that record evicts the one
    /// held** (fourteenth pass, DB14-M1) — a rule, not a consequence, so a
    /// builder does not accumulate one stored revision per applied head.
    public let arriving: VaultSealedRecord?

    public var hasArriving: Bool { arriving != nil }
    public var byteCount: Int { (current?.byteCount ?? 0) + (arriving?.byteCount ?? 0) }
}

/// The local, atomic, fsynced, 0600-in-0700 sealed store, modelled on
/// `VaultAttachmentStore`'s file discipline and living in the broker's own
/// container.
///
/// It holds **ciphertext and nothing else**: no key, no plaintext, no label.
/// Apply writes into it with **no key and no presence** (§7.1 stage 2), which
/// is why the type has no notion of one.
public actor VaultCipherStore {
    /// The container this store lives in, so a caller composing its siblings —
    /// the head chain, the fold markers, the head refusals — does not have to
    /// be handed the same value twice.
    public nonisolated let container: BrokerContainer

    public init(container: BrokerContainer) {
        self.container = container
    }

    public nonisolated var root: URL { container.directory(.cipherStore) }

    public nonisolated func vaultDirectory(_ vaultID: UUID) -> URL {
        root.appendingPathComponent(vaultID.uuidString.lowercased(), isDirectory: true)
    }

    // MARK: - Stage 2's two slots

    /// Apply's write. **The arriving revision is stored beside the record's
    /// last revision that opened, never over it** (thirteenth pass, DB13-C1),
    /// and **a second arriving revision replaces the first** (fourteenth pass,
    /// DB14-M1).
    ///
    /// It reports whether it **replaced** one, because a replacement of a
    /// *retained unopenable* revision is the substitution A-1 gets one of per
    /// revision — and **the device says so once per substitution** (sixteenth
    /// pass, DB16-M3), which is a receipt the caller writes.
    @discardableResult
    public func storeArriving(_ record: VaultSealedRecord, vaultID: UUID) throws -> Bool {
        try requireWireID(record.wireID)
        let slot = url(vaultID: vaultID, wireID: record.wireID, slot: .arriving)
        let replaced = FileManager.default.fileExists(atPath: slot.path)
        try write(record, to: slot)
        return replaced
    }

    /// The authoring path: this device sealed it, so it is current by
    /// construction and there is nothing to promote.
    public func storeCurrent(_ record: VaultSealedRecord, vaultID: UUID) throws {
        try requireWireID(record.wireID)
        try write(record, to: url(vaultID: vaultID, wireID: record.wireID, slot: .current))
        try? FileManager.default.removeItem(at: url(vaultID: vaultID, wireID: record.wireID, slot: .arriving))
    }

    /// **A record's current revision advances only when the arriving one
    /// opens** (§7.1). Called by flow 7, never by apply.
    ///
    /// **And promotion deletes what it supersedes** (fifteenth pass, DB15-M1):
    /// the revision it replaces is removed, which is what *"entering flow 7
    /// frees them"* rests on and which §3.2's `applyHead` row now states.
    public func promoteArriving(wireID: String, vaultID: UUID) throws {
        try requireWireID(wireID)
        let arriving = url(vaultID: vaultID, wireID: wireID, slot: .arriving)
        guard FileManager.default.fileExists(atPath: arriving.path) else {
            throw VaultCipherStoreError.unknownRecord(wireID)
        }
        let current = url(vaultID: vaultID, wireID: wireID, slot: .current)
        _ = try? FileManager.default.replaceItemAt(current, withItemAt: arriving, backupItemName: nil, options: [])
        if FileManager.default.fileExists(atPath: arriving.path) {
            // `replaceItemAt` is a rename when the destination exists and a
            // move when it does not; the fallback covers the first-revision
            // case on filesystems where it declines.
            try? FileManager.default.removeItem(at: current)
            try FileManager.default.moveItem(at: arriving, to: current)
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: current.path)
    }

    /// **One that does not open is discarded** — with a receipt the caller
    /// writes — **and the last good revision stays current**. This is the
    /// **edit** case: there is a current revision to fall back to.
    public func discardArriving(wireID: String, vaultID: UUID) throws {
        try requireWireID(wireID)
        try? FileManager.default.removeItem(at: url(vaultID: vaultID, wireID: wireID, slot: .arriving))
    }

    /// **And where this device has never opened the record, the unopenable
    /// revision is *retained*** (fifteenth pass, DB15-H2): discarding it leaves
    /// `normalize` running over a **missing** record, which is the loss the
    /// fold-failure rule exists to prevent. The eviction rule above still holds
    /// at most one arriving revision per record, so a **second** arriving
    /// revision for that record replaces the retained one and is tried at the
    /// next open — which is how a relay that later serves the record honestly
    /// clears the failure. Keeping the bytes is the whole of the operation, so
    /// this call does nothing but say so.
    public func retainUnopenable(wireID: String, vaultID: UUID) throws {
        try requireWireID(wireID)
        guard FileManager.default.fileExists(atPath: url(vaultID: vaultID, wireID: wireID, slot: .arriving).path) else {
            throw VaultCipherStoreError.unknownRecord(wireID)
        }
    }

    public func record(wireID: String, vaultID: UUID) throws -> VaultStoredRecord {
        try requireWireID(wireID)
        return VaultStoredRecord(
            wireID: wireID,
            current: try? read(url(vaultID: vaultID, wireID: wireID, slot: .current)),
            arriving: try? read(url(vaultID: vaultID, wireID: wireID, slot: .arriving))
        )
    }

    public func currentRevision(wireID: String, vaultID: UUID) throws -> VaultSealedRecord? {
        try record(wireID: wireID, vaultID: vaultID).current
    }

    /// **"This record has a current (opened) revision on this device."**
    ///
    /// §7.1's fold-failure rule is written against this property and **not
    /// against the record's birthday** (fifteenth pass, DB15-C1): version 16
    /// scoped the rule to *a creation* and the property it protects to *has
    /// opened at least once*, and between them lies every record above revision
    /// 1 that this device has never opened — which §5.1's enrolment and §6.2a's
    /// restore make **every** record on a newly added or restored device. The
    /// predicate is expressed explicitly here so neither branch can be written
    /// against the other.
    public func hasOpenedRevision(wireID: String, vaultID: UUID) throws -> Bool {
        try record(wireID: wireID, vaultID: vaultID).current != nil
    }

    /// A record leaves when the head stops naming it (§10's horizon).
    public func remove(wireID: String, vaultID: UUID) throws {
        try requireWireID(wireID)
        try? FileManager.default.removeItem(at: url(vaultID: vaultID, wireID: wireID, slot: .current))
        try? FileManager.default.removeItem(at: url(vaultID: vaultID, wireID: wireID, slot: .arriving))
    }

    // MARK: - What the budgets count

    /// **Live** records — the current revisions. An arriving revision is
    /// sealed store and is **not** a live record, so it is invisible to bound
    /// 2's 50,000 and visible to its 2 GiB (fourteenth pass, DB14-H1).
    public func liveRecordCount(vaultID: UUID) -> Int {
        slots(vaultID: vaultID).filter { $0.hasSuffix(Slot.current.suffix) }.count
    }

    public func arrivingRecordCount(vaultID: UUID) -> Int {
        slots(vaultID: vaultID).filter { $0.hasSuffix(Slot.arriving.suffix) }.count
    }

    /// Every byte on disk for this vault, both slots. This is what bound 2's
    /// byte half measures, which is why the worst case is twice the live bytes.
    public func byteCount(vaultID: UUID) -> Int {
        let directory = vaultDirectory(vaultID)
        let manager = FileManager.default
        guard let names = try? manager.contentsOfDirectory(atPath: directory.path) else { return 0 }
        return names.reduce(0) { total, name in
            let attributes = try? manager.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            return total + ((attributes?[.size] as? Int) ?? 0)
        }
    }

    /// **The `wireID`s with a live slot**, which is what bound 2's record half
    /// is a union over (twentieth pass, DB20-C1). `wireIDs` below returns both
    /// slots and is the container walk's; this is the live set's.
    public func liveWireIDs(vaultID: UUID) -> Set<String> {
        Set(slots(vaultID: vaultID).compactMap { name in
            name.hasSuffix(Slot.current.suffix) ? String(name.dropLast(Slot.current.suffix.count)) : nil
        })
    }

    public func wireIDs(vaultID: UUID) -> Set<String> {
        Set(slots(vaultID: vaultID).compactMap { name in
            for slot in Slot.allCases where name.hasSuffix(slot.suffix) {
                return String(name.dropLast(slot.suffix.count))
            }
            return nil
        })
    }

    // MARK: - Files

    enum Slot: CaseIterable {
        case current
        case arriving
        var suffix: String {
            switch self {
            case .current: ".current"
            case .arriving: ".arriving"
            }
        }
    }

    private func slots(vaultID: UUID) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: vaultDirectory(vaultID).path)) ?? []
    }

    private nonisolated func url(vaultID: UUID, wireID: String, slot: Slot) -> URL {
        vaultDirectory(vaultID).appendingPathComponent("\(wireID)\(slot.suffix)")
    }

    private func requireWireID(_ value: String) throws {
        guard VaultWireID.isWellFormed(value) else { throw VaultCipherStoreError.malformedWireID(value) }
    }

    private func read(_ url: URL) throws -> VaultSealedRecord {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        return try decoder.decode(VaultSealedRecord.self, from: data)
    }

    /// Atomic, 0600, inside 0700, fsynced — `VaultAttachmentStore`'s
    /// discipline, because the argument that makes it acceptable there is the
    /// argument that makes it acceptable here: the disk holds ciphertext and
    /// nothing else.
    private func write(_ record: VaultSealedRecord, to url: URL) throws {
        let folder = url.deletingLastPathComponent()
        let manager = FileManager.default
        do {
            try container.ensure()
            try manager.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
            try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.deletingLastPathComponent().path)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(record)
            let temporary = folder.appendingPathComponent("record-\(UUID().uuidString).tmp")
            guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw VaultCipherStoreError.storage("Could not create a sealed record file.")
            }
            do {
                let handle = try FileHandle(forWritingTo: temporary)
                defer { try? handle.close() }
                try handle.write(contentsOf: data)
                try handle.synchronize()
            } catch {
                try? manager.removeItem(at: temporary)
                throw VaultCipherStoreError.storage("Could not write a sealed record.")
            }
            _ = try manager.replaceItemAt(url, withItemAt: temporary, backupItemName: nil, options: [])
            try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch let error as VaultCipherStoreError {
            throw error
        } catch {
            throw VaultCipherStoreError.storage("Could not write a sealed record.")
        }
    }
}


/// §9.3's **second** downgrade guard, and its precedence.
///
/// > 1. `MetadataStore` already refuses a file whose `schemaVersion` exceeds the
/// >    build's. **This runs first**, and it covers the metadata file.
/// > 2. The `minimumAppBuild` marker covers the **sealed store**, and is checked
/// >    immediately after the metadata file opens.
///
/// **A build that passes one and fails the other must not half-open**: it
/// refuses the whole store with one message naming which check failed. Opening
/// the metadata and withholding the records is the half-open that rule forbids,
/// because it renders a vault whose contents a build cannot read as an empty
/// one.
public enum VaultSealedStoreGuard {
    /// `nil` when this build may open the sealed store, and the one owner-facing
    /// message otherwise.
    public static func refusal(forAppBuild build: Int, in state: VaultageMetadata) -> String? {
        guard let required = state.minimumAppBuild, build < required else { return nil }
        return """
            This Mac's vault was last written by a newer version of Vaultage (build \(required)), \
            and this build (\(build)) cannot read its sealed records. Nothing has been changed. \
            Please update Vaultage.
            """
    }
}
