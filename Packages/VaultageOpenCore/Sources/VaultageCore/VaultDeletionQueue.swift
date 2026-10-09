import Foundation

// BL-100 slice A — §7.3 **part A**: a delete is applied locally and queued
// (`13-MULTI-DEVICE-CUSTODY.md` version 17 §7.3; twelfth pass DB12-H3;
// typed thirteenth pass DB13-H3; tested and re-scoped fourteenth pass DB14-H3,
// DB14-H4; the excluded **seam** named fifteenth pass DB15-H4, DB15-M3;
// the negative test's shape sixteenth pass DB16-M1, DB16-M2).
//
// **Slice A syncs adds and edits only.** A deletion is applied on the device
// that made it and recorded here. No `tomb` record, no fold, no `provisional`
// field, no accumulator, no pending run, no `K`, no vault-deletion flow, no undo
// window — **nothing about deletion crosses the wire.** Deletion sync is slice
// C, and it is BL-110.

/// One suppressed record. **Value-free**: an id, a revision and a Lamport.
///
/// `revisionAtQueueing` and `lamportAtQueueing` are recorded because **BL-110
/// drains the queue** and part C's *"a `tomb` wins against an edit whose Lamport
/// is older than the tombstone's"* needs both — a queue that dropped them would
/// have to guess at the cutover.
public struct VaultDeletionQueueEntry: Codable, Sendable, Hashable {
    public let vaultID: UUID
    public let recordKind: VaultRecordKind
    public let recordID: String
    public let wireID: String
    public let revisionAtQueueing: Int
    public let lamportAtQueueing: Int
    /// **This device's own monotonic instant.** No wall clock, and no
    /// accumulator: nothing in slice A's queue expires, notifies or pends.
    public let queuedAtMonotonic: TimeInterval

    public init(
        vaultID: UUID,
        recordKind: VaultRecordKind,
        recordID: String,
        wireID: String,
        revisionAtQueueing: Int,
        lamportAtQueueing: Int,
        queuedAtMonotonic: TimeInterval
    ) {
        self.vaultID = vaultID
        self.recordKind = recordKind
        self.recordID = recordID
        self.wireID = wireID
        self.revisionAtQueueing = revisionAtQueueing
        self.lamportAtQueueing = lamportAtQueueing
        self.queuedAtMonotonic = queuedAtMonotonic
    }
}

/// What `listLocalDeletions` returns: **the same value-free projection fields
/// `renderList` returns, filtered to the queue**, plus `queuedAt`.
///
/// It is filtered rather than flagged because a suppressed record *"does not
/// render"* by consequence 1, and the restore sheet still has to name what it is
/// restoring — while `renderList` returning suppressed rows with a flag is the
/// *"banner on a fully live item"* shape version 1 was faulted for.
///
/// **No ciphertext, no wrap row, no `value`.**
public struct VaultDeletionQueueProjection: Sendable, Equatable {
    public let wireID: String
    public let label: String
    public let type: String
    public let folderID: UUID?
    public let queuedAtMonotonic: TimeInterval

    public init(wireID: String, label: String, type: String, folderID: UUID?, queuedAtMonotonic: TimeInterval) {
        self.wireID = wireID
        self.label = label
        self.type = type
        self.folderID = folderID
        self.queuedAtMonotonic = queuedAtMonotonic
    }
}

public enum VaultDeletionQueueRefusal: Error, Equatable, Sendable, LocalizedError {
    case presenceDenied
    case notQueued(wireID: String)

    public var errorDescription: String? {
        switch self {
        case .presenceDenied: "Vaultage could not confirm it is you, so nothing was restored."
        case .notQueued: "That record is not hidden on this Mac."
        }
    }
}

/// §7.3 part A's queue: **broker-owned, device-only, and beside
/// `VaultCipherStore` and the retained head chain**, at the same protection
/// class, and a row in §10's table and its container manifest.
///
/// **On iOS it lives in the containing app's own container**, same shape, same
/// protection class, same three operations and the same presence gate — and
/// **consequence 4's structural half does not transfer there**, which BL-107
/// states rather than inherits. This ticket ships the macOS form.
public actor VaultDeletionQueue {
    private let container: BrokerContainer
    private let monotonic: any MonotonicClock
    /// **The injection point is the restore path's own evaluation and not
    /// `OwnerAuthenticating`** (fifteenth pass, DB15-M3): that seam is the
    /// shortcut the rule excludes, and a builder resolving the contradiction
    /// alone keeps the seam. A headless run cannot prompt, so the evaluation is
    /// injectable — **here**.
    private let presence: any PresenceEvaluating

    public init(
        container: BrokerContainer,
        presence: any PresenceEvaluating,
        monotonic: any MonotonicClock = SystemMonotonicClock()
    ) {
        self.container = container
        self.presence = presence
        self.monotonic = monotonic
    }

    public nonisolated var root: URL { container.directory(.deletionQueue) }

    private nonisolated func file(_ vaultID: UUID) -> URL {
        root.appendingPathComponent("\(vaultID.uuidString.lowercased()).json")
    }

    // MARK: - The three XPC operations

    /// **No presence** — nothing is destroyed and nothing leaves the device.
    ///
    /// **Deleting raises no prompt; restoring does.** The asymmetry is
    /// deliberate: deleting is reversible and destroys nothing, so it is not
    /// worth a prompt; restoring is the step that puts a record back into a view
    /// the owner may be relying on, and it is the step an attacker would use to
    /// undo an owner's deliberate suppression.
    @discardableResult
    public func enqueueLocalDeletion(
        vaultID: UUID,
        subject: VaultRecordSubject,
        wireID: String,
        revision: Int,
        lamport: Int
    ) throws -> VaultDeletionQueueEntry {
        var entries = self.entries(vaultID)
        let entry = VaultDeletionQueueEntry(
            vaultID: vaultID,
            recordKind: subject.kind,
            recordID: subject.recordID,
            wireID: wireID,
            revisionAtQueueing: revision,
            lamportAtQueueing: lamport,
            queuedAtMonotonic: monotonic.uptime
        )
        entries.removeAll { $0.wireID == wireID }
        entries.append(entry)
        try save(entries, vaultID: vaultID)
        return entry
    }

    public func entries(_ vaultID: UUID) -> [VaultDeletionQueueEntry] {
        guard let data = try? Data(contentsOf: file(vaultID)),
              let entries = try? JSONDecoder().decode([VaultDeletionQueueEntry].self, from: data)
        else { return [] }
        return entries
    }

    /// **Suppression is local and total — on the Mac.** While an entry is in the
    /// queue the record does not render, cannot be revealed, copied, delivered
    /// or AutoFilled **on this device**. It is untouched everywhere else,
    /// including on the relay.
    public func isSuppressed(vaultID: UUID, wireID: String) -> Bool {
        entries(vaultID).contains { $0.wireID == wireID }
    }

    /// The count the vault surface shows — *"3 items deleted on this Mac only"*.
    public func count(_ vaultID: UUID) -> Int { entries(vaultID).count }

    /// **Value-free projections**, resolved from the same projection
    /// `renderList` serves, filtered to the queue.
    public func listLocalDeletions(
        vaultID: UUID,
        resolve: (VaultDeletionQueueEntry) -> (label: String, type: String, folderID: UUID?)?
    ) -> [VaultDeletionQueueProjection] {
        entries(vaultID).compactMap { entry in
            guard let fields = resolve(entry) else { return nil }
            return VaultDeletionQueueProjection(
                wireID: entry.wireID,
                label: fields.label,
                type: fields.type,
                folderID: fields.folderID,
                queuedAtMonotonic: entry.queuedAtMonotonic
            )
        }
    }

    /// **Restore is one action and it is presence-gated — and the proof has a
    /// type.**
    ///
    /// > The proof is evaluated in the broker, on an `LAContext` **created for
    /// > that call** and **invalidated as soon as the evaluation returns, before
    /// > any queue entry is touched**. It is **not** an `OwnerAuthentication`
    /// > and takes none. It **yields no token**, and nothing may be spent under
    /// > it.
    ///
    /// **The parameter list is not the control, and version 17 names the seam
    /// instead** (fifteenth pass, DB15-H4): the shipped
    /// `OwnerAuthenticating.authenticateOwner(reason:unlocking:)` takes **no**
    /// `LAContext` and **no** `OwnerAuthentication` parameter,
    /// `LocalOwnerAuthentication` constructs its own context at **60 seconds**,
    /// and the broker holds one as a stored property — so restore reaches the
    /// exact shortcut DB13-H3 was raised to forbid **with no parameter at all**
    /// and satisfies every clause verbatim. So the rule is about the **call**:
    /// this path **does not call `OwnerAuthenticating` and constructs no
    /// `OwnerAuthentication`**, and its own context sets
    /// `touchIDAuthenticationAllowableReuseDuration = 0`.
    ///
    /// **The invalidation point is the evaluation's return and not the call's**
    /// (fourteenth pass, DB14-H4): `restoreAllLocalDeletions` is one proof for a
    /// queue §7.3 consequence 5 says a single folder deletion can fill with the
    /// entire vault, so holding the context for the walk would be this design's
    /// only uncapped, unchunked evaluated context, in the process §2.4.2
    /// concedes. The proof authorizes the action; it need not be held during it.
    @discardableResult
    public func restoreLocalDeletion(vaultID: UUID, wireID: String) throws -> Int {
        try proveOwnerPresence(reason: "Un-hide 1 record deleted on this Mac only?")
        var entries = self.entries(vaultID)
        guard entries.contains(where: { $0.wireID == wireID }) else {
            throw VaultDeletionQueueRefusal.notQueued(wireID: wireID)
        }
        entries.removeAll { $0.wireID == wireID }
        try save(entries, vaultID: vaultID)
        // **Restoring removes the entry; the record was never touched.**
        return 1
    }

    /// **One proof for the whole queue, however large it is.**
    @discardableResult
    public func restoreAllLocalDeletions(vaultID: UUID) throws -> Int {
        let held = entries(vaultID).count
        try proveOwnerPresence(reason: "Un-hide \(held) records deleted on this Mac only?")
        try save([], vaultID: vaultID)
        return held
    }

    /// The proof. It **returns nothing spendable** — `Void` — and the context is
    /// invalidated the instant the evaluation returns, **before any queue entry
    /// is touched**.
    private func proveOwnerPresence(reason: String) throws {
        let evaluated: EvaluatedPresence
        do {
            evaluated = try presence.evaluate(reason: reason)
        } catch {
            throw VaultDeletionQueueRefusal.presenceDenied
        }
        evaluated.invalidate()
    }

    // MARK: - Files

    private func save(_ entries: [VaultDeletionQueueEntry], vaultID: UUID) throws {
        guard !entries.isEmpty else {
            try? FileManager.default.removeItem(at: file(vaultID))
            return
        }
        try container.ensure()
        let manager = FileManager.default
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(entries)
        let temporary = root.appendingPathComponent("queue-\(UUID().uuidString).tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw VaultCipherStoreError.storage("Could not create the deletion queue file.")
        }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try? handle.close()
        _ = try manager.replaceItemAt(file(vaultID), withItemAt: temporary, backupItemName: nil, options: [])
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(vaultID).path)
    }
}

/// The owner-facing sentences §7.3 part A requires, in the product's own words.
public enum VaultDeletionQueueNotice {
    /// **The residual, named rather than implied.** An owner who deletes a
    /// compromised credential and believes it gone everywhere is the failure
    /// this sentence exists to prevent, and it is a **product** statement, not a
    /// footnote.
    public static let macOSSuppressed = "deleted on this Mac only — deletions do not yet sync to your other devices"

    /// **On a phone the same sentence names the phone, and carries the second
    /// half of the gap** (thirteenth pass, DB13-H2): the queue lives in the
    /// containing app's private container and the AutoFill-enabled vaults'
    /// sealed stores are in the extension-shared one, so the extension cannot
    /// read the queue and keeps serving the item. BL-107 ships this form.
    public static let iOSSuppressed = "deleted on this iPhone only — it can still be filled by AutoFill until deletions sync"

    public static func vaultSurface(count: Int) -> String {
        "\(count) \(count == 1 ? "item" : "items") deleted on this Mac only"
    }

    /// **Blobs are not collected**: §8's tombstoned cross-device garbage
    /// collection needs a `tomb` the head covers, so in slice A a queued
    /// deletion frees **no** storage, locally or on the relay.
    public static let freesNoStorage = "Hiding a record here frees no storage, on this Mac or on the server."
}
