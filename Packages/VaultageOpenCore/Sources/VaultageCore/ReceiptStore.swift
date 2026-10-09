import Foundation
import Darwin

public struct DurableReceipt: Codable, Sendable {
    public let eventID: UUID
    public let correlationID: UUID
    public let at: Date
    /// Nil for BL-062 human-only disclosure, which is not scoped to a project
    /// or an environment: the human is retrieving one vault item, not acting in
    /// a project. Every earlier record carries both.
    public let projectID: UUID?
    public let environmentID: UUID?
    /// Nil for local runtime delivery and for human disclosure, neither of
    /// which has a provider binding.
    public let bindingID: UUID?
    /// BL-062. The vault item a human reveal or copy named. Set only on that
    /// path, and an identifier only — never a label derived from a value, never
    /// a Keychain account, never any part of the value itself.
    public let vaultItemID: UUID?
    public let operation: String
    public let requestDigest: String
    public let decision: AuditDecision
    public let result: String
    /// BL-060. Set when this invocation skipped the approval sheet because a
    /// grant authorized it, so every auto-allowed action is attributable to the
    /// exact grant the human approved. Absent on every other path, and absent
    /// from every receipt written before schema 7.
    public let grantID: UUID?
    /// BL-091. The provider-side resource id this invocation acted on or
    /// created, and the one-sentence effect. Both are required by the ticket
    /// ("receipts carry the resource id and the effect") and both are bounded,
    /// closed-charset projections produced by the adapter — never a provider
    /// value and never raw provider text. Absent on every path that has no
    /// resource, and on every receipt written before schema 14.
    public let resourceID: String?
    public let effect: String?
    /// BL-099 §4.6. **Which device decided this**, when it was not this Mac.
    /// Two identifiers rather than one name, because the receipt has to survive
    /// an unpairing: the id is what the grant and the kill stamp are keyed by,
    /// and the name is the local pin record's at the moment of the decision —
    /// never the roster's at render time (§4.8), so a relay that renames a
    /// device cannot change what the owner's own history says happened.
    /// Absent on every local decision and on every receipt written before this
    /// ticket.
    public let decidingDeviceID: String?
    public let decidingDeviceName: String?
    /// **BL-100 slice A — the record-shaped variant** (`13-MULTI-DEVICE-CUSTODY.md`
    /// version 17 §7.1; fifteenth pass, DB15-M2). §7.1's discard receipt has to
    /// name *"the vault, the `wireID` and the revision, and no label"*, and at
    /// version 16's pin this type had a field for none of the three: its one
    /// item-shaped field, `vaultItemID`, is scoped to BL-062's human reveal and
    /// is an identifier the app can resolve to a label.
    ///
    /// **No label, deliberately.** §2.4.1's residency rule says the projection
    /// is memory-only and is never written down, and a `wireID` is HMAC'd under
    /// `VIK_v` (§3.4), so it names nothing on disk that a reader of this file
    /// can resolve. Naming the record **to the owner** happens on the vault
    /// surface inside flow 7, from the prior revision's plaintext label the live
    /// projection already holds — so the owner is told *which record* and the
    /// disk is told *which `wireID`*, and neither rule is bent.
    ///
    /// Absent on every path that is not a sealed-record discard, and on every
    /// receipt written before this slice.
    public let vaultID: UUID?
    public let recordWireID: String?
    public let recordRevision: Int?

    public init(
        eventID: UUID,
        correlationID: UUID,
        at: Date,
        projectID: UUID?,
        environmentID: UUID?,
        bindingID: UUID?,
        vaultItemID: UUID? = nil,
        operation: String,
        requestDigest: String,
        decision: AuditDecision,
        result: String,
        grantID: UUID? = nil,
        resourceID: String? = nil,
        effect: String? = nil,
        decidingDeviceID: String? = nil,
        decidingDeviceName: String? = nil,
        vaultID: UUID? = nil,
        recordWireID: String? = nil,
        recordRevision: Int? = nil
    ) {
        self.eventID = eventID
        self.correlationID = correlationID
        self.at = at
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.vaultItemID = vaultItemID
        self.operation = operation
        self.requestDigest = requestDigest
        self.decision = decision
        self.result = result
        self.grantID = grantID
        self.resourceID = resourceID
        self.effect = effect
        self.decidingDeviceID = decidingDeviceID
        self.decidingDeviceName = decidingDeviceName
        self.vaultID = vaultID
        self.recordWireID = recordWireID
        self.recordRevision = recordRevision
    }
}

/// One invocation's durable history, derived from the receipt file.
public struct ReceiptInvocation: Sendable, Equatable {
    public let correlationID: UUID
    public let projectID: UUID?
    public let environmentID: UUID?
    public let operation: String
    public let decisions: [AuditDecision]

    public var terminal: AuditDecision? { decisions.last(where: { $0.isTerminal }) }
    /// A recorded invocation with no terminal decision is unknown. It is never
    /// reported as success, and it is never retried automatically.
    public var isUnknown: Bool { terminal == nil || terminal == .resultUnknown }
}

/// What opening the receipt log had to repair.
public struct ReceiptRecovery: Sendable, Equatable {
    public var records = 0
    public var quarantinedTailBytes = 0
    public var malformedLines = 0
    public var pendingClosedAsUnknown: [ReceiptInvocation] = []

    public init() {}

    public var isClean: Bool {
        quarantinedTailBytes == 0 && malformedLines == 0 && pendingClosedAsUnknown.isEmpty
    }
}

/// Deterministic fault injection for the durable-receipt self-tests. The default
/// is inert, so production callers never construct a faulted store; there is no
/// preference, argument, or environment variable that can turn these on.
public struct ReceiptStoreFaults: Sendable, Equatable {
    /// Write only this many bytes of each line, then report a write failure.
    public var truncateWriteAfterBytes: Int?
    public var failFsync: Bool
    /// Simulates a rollback that cannot remove a partially written line.
    public var failRollback: Bool

    public init(truncateWriteAfterBytes: Int? = nil, failFsync: Bool = false, failRollback: Bool = false) {
        self.truncateWriteAfterBytes = truncateWriteAfterBytes
        self.failFsync = failFsync
        self.failRollback = failRollback
    }

    public var isInert: Bool { truncateWriteAfterBytes == nil && !failFsync && !failRollback }
}

/// Separate append-only local receipt log. It is intentionally value-free; each
/// line is committed before a protected read or reported provider completion.
public protocol ReceiptPersisting: Sendable {
    func append(_ receipt: DurableReceipt) async throws
    /// Repairs and reports the log at process start. There is deliberately no
    /// default implementation: a store that cannot say what it recovered would
    /// silently report a clean log.
    func recover() async throws -> ReceiptRecovery
}

/// Durable append-only JSONL receipts with defined crash semantics.
///
/// **Durable, not tamper-evident** (audit M-06). The log survives a crash with
/// the guarantees below; it does not survive a same-user process that edits
/// it, and nothing here claims otherwise. A receipt is the product's own
/// record of what it did, kept so a human can read it back, and its integrity
/// against the owner's other processes is the file system's, not a signature.
///
/// The reviewed contract, in the order the file enforces it:
///
/// 1. **A line is durable or it is absent.** Every append records the file
///    length first. If the write or the `fsync` fails, the file is truncated
///    back to that length and re-synced, so a half-written line never survives
///    a reported failure.
/// 2. **A tail that could not be rolled back is quarantined, not repaired in
///    place.** If truncation itself fails — or the process died mid-line — the
///    next open moves the bytes after the final newline into
///    `receipts.quarantine.jsonl` and truncates the log to that newline. Every
///    earlier record is preserved; a complete but unparseable line is left
///    alone and counted, because it is still a durable record.
/// 3. **A pending invocation with no terminal decision is unknown.** Opening the
///    log closes each one with a durable `resultUnknown` line. It is never
///    reported as success and never retried automatically.
/// 4. **One terminal decision per invocation, within one process.** A second
///    terminal append for a correlation ID that already has one is ignored
///    rather than written, so a terminal line that reached the file before
///    `fsync` reported failure cannot be contradicted by a later
///    `resultUnknown` for the same invocation. The rule is enforced from
///    `terminalCorrelations`, an in-memory set seeded when *this* store opened
///    — so it does not hold between processes (RP-12). Two `ReceiptStore`s over
///    one directory in different processes cannot see each other's terminal
///    writes, and two concurrent recoveries can each close the same dangling
///    pending. The `flock` protects the bytes, not the rule. Enforcing it from
///    the file under the lock is the fix and is not built.
/// 5. **A repair that could not be completed is not latched.** `prepared` is
///    set only after every dangling pending has been closed, so a failure in
///    that loop surfaces from this call and from every later `recover()` and
///    `append()` until it succeeds. A store that cannot say what the log
///    already holds refuses to add to it.
public actor ReceiptStore: ReceiptPersisting {
    private let url: URL
    private let quarantineURL: URL
    private let lockURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let faults: ReceiptStoreFaults
    private var prepared = false
    private var lastRecovery = ReceiptRecovery()
    private var terminalCorrelations: Set<UUID> = []

    /// Audit M-05. Whether opening this store closes dangling pending
    /// invocations as `resultUnknown`. The broker's store does; a second
    /// store over the same directory — the window's, which only reads — must
    /// not, or a live pending action the broker is still running is closed
    /// under it and the broker's own terminal contradicts it later.
    private let recoversDanglingInvocations: Bool

    public init(directory: URL = MetadataStore.defaultDirectory, faults: ReceiptStoreFaults = ReceiptStoreFaults(), recoversDanglingInvocations: Bool = true) {
        self.recoversDanglingInvocations = recoversDanglingInvocations
        url = directory.appendingPathComponent("receipts.jsonl")
        quarantineURL = directory.appendingPathComponent("receipts.quarantine.jsonl")
        lockURL = directory.appendingPathComponent("receipts.lock")
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.faults = faults
    }

    public func append(_ receipt: DurableReceipt) throws {
        try prepareIfNeeded()
        // Replay rule: an invocation gets at most one terminal decision. A
        // caller that reports a second one after an ambiguous write is asking
        // for a contradiction, not for a new fact.
        if receipt.decision.isTerminal, terminalCorrelations.contains(receipt.correlationID) { return }
        try commit(receipt)
    }

    @discardableResult
    public func recover() throws -> ReceiptRecovery {
        try prepareIfNeeded()
    }

    /// Every invocation the durable log knows about, oldest first.
    public func invocations() throws -> [ReceiptInvocation] {
        try prepareIfNeeded()
        return try withLock { try ledger().invocations }
    }

    // MARK: - Opening

    @discardableResult
    private func prepareIfNeeded() throws -> ReceiptRecovery {
        if prepared { return lastRecovery }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        var recovery = ReceiptRecovery()
        var dangling: [DurableReceipt] = []
        let state = try withLock { () -> Ledger in
            recovery.quarantinedTailBytes = try quarantineTruncatedTail()
            return try ledger()
        }
        recovery.records = state.records
        recovery.malformedLines = state.malformed
        terminalCorrelations = state.terminal
        let unresolved = state.invocations.filter { $0.terminal == nil }
        dangling = unresolved.compactMap { state.lastPending[$0.correlationID] }
        // RP-04. `prepared` is latched *after* the loop below, never before it.
        // Latching first meant that if a commit in the loop threw — a full
        // disk, a permissions change, a failing fsync — the first `recover()`
        // threw but every later one returned the default-constructed
        // `lastRecovery`: zero records, no pendings, `isClean == true`, while
        // the dangling pending was still open on disk. A crashed invocation
        // vanished from the durable log's own report of itself. The repair must
        // stay retryable and must stay visible, so a failure here leaves the
        // store unprepared and the next `recover()` (or `append()`) tries
        // again and reports the same failure.
        //
        // Closing a dangling pending goes through the ordinary append path, so
        // it obeys the same durability and at-most-once rules.
        for pending in (recoversDanglingInvocations ? dangling : []) {
            let unknown = DurableReceipt(
                eventID: UUID(),
                correlationID: pending.correlationID,
                at: Date(),
                projectID: pending.projectID,
                environmentID: pending.environmentID,
                bindingID: pending.bindingID,
                vaultItemID: pending.vaultItemID,
                operation: pending.operation,
                requestDigest: pending.requestDigest,
                decision: .resultUnknown,
                result: "A pending receipt had no terminal decision when Vaultage reopened the durable log. The result is unknown; do not retry automatically.",
                // An interrupted auto-allowed invocation stays attributable to
                // the grant that authorized it.
                grantID: pending.grantID
            )
            try commit(unknown)
        }
        recovery.pendingClosedAsUnknown = unresolved
        lastRecovery = recovery
        prepared = true
        return recovery
    }

    /// Moves anything after the final newline into the quarantine file and then
    /// truncates the log to that newline. Quarantine is written and synced
    /// first, so a failure there cannot destroy the bytes it was meant to keep.
    private func quarantineTruncatedTail() throws -> Int {
        guard FileManager.default.fileExists(atPath: url.path) else { return 0 }
        let contents = try Data(contentsOf: url)
        guard !contents.isEmpty else { return 0 }
        guard let lastNewline = contents.lastIndex(of: 0x0A) else {
            // The whole file is one truncated line.
            try quarantine(contents, reason: "truncated_tail_whole_file")
            try truncateLog(to: 0)
            return contents.count
        }
        let tailStart = contents.index(after: lastNewline)
        guard tailStart < contents.endIndex else { return 0 }
        let tail = Data(contents[tailStart...])
        try quarantine(tail, reason: "truncated_tail")
        try truncateLog(to: off_t(contents.distance(from: contents.startIndex, to: tailStart)))
        return tail.count
    }

    private func quarantine(_ bytes: Data, reason: String) throws {
        let record = """
        {"at":"\(ISO8601DateFormatter().string(from: Date()))","reason":"\(reason)","byteCount":\(bytes.count),"base64":"\(bytes.base64EncodedString())"}
        """
        let fd = open(quarantineURL.path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw VaultageError.storage("Could not quarantine a truncated durable receipt tail.") }
        defer { close(fd) }
        _ = fchmod(fd, S_IRUSR | S_IWUSR)
        try writeAll(Data(record.utf8) + Data([0x0A]), to: fd, allowFault: false)
        guard fsync(fd) == 0 else { throw VaultageError.storage("Could not quarantine a truncated durable receipt tail.") }
    }

    private func truncateLog(to offset: off_t) throws {
        let fd = open(url.path, O_WRONLY)
        guard fd >= 0 else { throw VaultageError.storage("Could not repair the durable receipt log.") }
        defer { close(fd) }
        guard ftruncate(fd, offset) == 0, fsync(fd) == 0 else {
            throw VaultageError.storage("Could not repair the durable receipt log.")
        }
    }

    // MARK: - Appending

    private func commit(_ receipt: DurableReceipt) throws {
        let data = try encoder.encode(receipt) + Data([0x0A])
        try withLock {
            let wasPresent = FileManager.default.fileExists(atPath: url.path)
            let fd = open(url.path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR)
            guard fd >= 0 else { throw VaultageError.storage("Could not persist a durable receipt.") }
            defer { close(fd) }
            guard fchmod(fd, S_IRUSR | S_IWUSR) == 0 else { throw VaultageError.storage("Could not protect durable receipts.") }
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw VaultageError.storage("Could not measure the durable receipt log.") }
            let startOffset = info.st_size
            do {
                try writeAll(data, to: fd, allowFault: true)
                guard !faults.failFsync, fsync(fd) == 0 else {
                    throw VaultageError.storage("Could not fsync a durable receipt.")
                }
            } catch {
                try rollback(fd, to: startOffset, after: receipt)
                throw error
            }
            if !wasPresent {
                let parent = open(url.deletingLastPathComponent().path, O_RDONLY)
                guard parent >= 0 else { throw VaultageError.storage("Could not fsync receipt directory.") }
                let parentSynced = fsync(parent) == 0
                close(parent)
                guard parentSynced else { throw VaultageError.storage("Could not fsync receipt directory.") }
            }
        }
        if receipt.decision.isTerminal { terminalCorrelations.insert(receipt.correlationID) }
    }

    /// Removes a line that was not durably committed. If the removal itself
    /// fails, a possibly torn terminal line may exist on disk, so the
    /// invocation is marked terminal here: a later `resultUnknown` for the same
    /// correlation ID must not be able to add a second, contradicting outcome.
    /// The torn bytes are quarantined at the next open.
    private func rollback(_ fd: Int32, to offset: off_t, after receipt: DurableReceipt) throws {
        if !faults.failRollback, ftruncate(fd, offset) == 0, fsync(fd) == 0 { return }
        if receipt.decision.isTerminal { terminalCorrelations.insert(receipt.correlationID) }
        throw VaultageError.storage("A durable receipt could not be completed and its partial line could not be removed. The receipt log tail is torn and is quarantined on the next open; treat this invocation as unknown.")
    }

    private func writeAll(_ data: Data, to fd: Int32, allowFault: Bool) throws {
        let limit = allowFault ? faults.truncateWriteAfterBytes.map { min($0, data.count) } : nil
        let target = limit ?? data.count
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { throw VaultageError.storage("Could not encode a durable receipt.") }
            var offset = 0
            while offset < target {
                let count = write(fd, base.advanced(by: offset), target - offset)
                if count > 0 {
                    offset += count
                    continue
                }
                if count < 0 && errno == EINTR { continue }
                throw VaultageError.storage("Could not persist a durable receipt.")
            }
        }
        if limit != nil {
            throw VaultageError.storage("Could not persist a durable receipt.")
        }
    }

    // MARK: - Reading

    private struct Ledger {
        var records = 0
        var malformed = 0
        var terminal: Set<UUID> = []
        var invocations: [ReceiptInvocation] = []
        var lastPending: [UUID: DurableReceipt] = [:]
    }

    private func ledger() throws -> Ledger {
        var ledger = Ledger()
        // RP-04. "Absent" and "unreadable" are different facts and only the
        // first one is an empty ledger. A log that exists but cannot be read —
        // permissions, a partially unmounted volume, an I/O error — used to be
        // reported as an empty, clean log, which would let recovery believe
        // there was nothing to repair and let the at-most-once rule start from
        // an empty terminal set. It fails closed instead.
        guard FileManager.default.fileExists(atPath: url.path) else { return ledger }
        let contents: Data
        do { contents = try Data(contentsOf: url) }
        catch {
            throw VaultageError.storage("The durable receipt log exists but could not be read, so Vaultage cannot tell what it already recorded.")
        }
        var order: [UUID] = []
        var decisions: [UUID: [AuditDecision]] = [:]
        var seed: [UUID: DurableReceipt] = [:]
        for line in contents.split(separator: 0x0A, omittingEmptySubsequences: true) {
            guard let receipt = try? decoder.decode(DurableReceipt.self, from: Data(line)) else {
                ledger.malformed += 1
                continue
            }
            ledger.records += 1
            if decisions[receipt.correlationID] == nil {
                order.append(receipt.correlationID)
                seed[receipt.correlationID] = receipt
            }
            decisions[receipt.correlationID, default: []].append(receipt.decision)
            if receipt.decision.isTerminal { ledger.terminal.insert(receipt.correlationID) }
            if receipt.decision == .pending { ledger.lastPending[receipt.correlationID] = receipt }
        }
        ledger.invocations = order.compactMap { id in
            guard let first = seed[id] else { return nil }
            return ReceiptInvocation(
                correlationID: id,
                projectID: first.projectID,
                environmentID: first.environmentID,
                operation: first.operation,
                decisions: decisions[id] ?? []
            )
        }
        return ledger
    }

    // MARK: - Locking

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(
            at: lockURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let lock = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard lock >= 0 else { throw VaultageError.storage("Could not lock durable receipts.") }
        defer { close(lock) }
        guard flock(lock, LOCK_EX) == 0 else { throw VaultageError.storage("Could not lock durable receipts.") }
        defer { flock(lock, LOCK_UN) }
        return try body()
    }
}
