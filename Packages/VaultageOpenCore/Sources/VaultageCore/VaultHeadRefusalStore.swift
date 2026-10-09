import CryptoKit
import Foundation

// BL-100 slice A — §7.1 stage 1's **head refusals**
// (`13-MULTI-DEVICE-CUSTODY.md` version 19; sixteenth pass, DB16-C1).
//
// **No size or count bound is evaluated inside the apply transaction.** All
// three of §3.1's bounds run at **transfer**, over the **whole served head**,
// and a head that fails any of them is refused **whole**: nothing is staged,
// nothing is written, **the watermark does not advance**, apply never sees a
// partial head, and `normalize` never runs over a hole.
//
// Version 17 put bound 2 and `maximumSealedRecordBytes` at apply and said
// neither which thing a refusal refuses nor what follows: refusing one record
// makes a partial head, and refusing the head from inside a transaction the
// watermark advances in makes a **permanent total sync halt** for that vault at
// the cost of one oversized record.

/// A refused head — **keyed on the head digest, recording the served-bytes
/// digests it has refused** (eighteenth pass, DB18-C1).
///
/// Version 19 keyed the retry on the head digest alone, and the head's `digest`
/// is over `(wireID, revision)` pairs and **not** over the bytes, so the marker
/// refused the honest re-serve of the same head from disk and an idle vault had
/// no exit. Version 20 made the key the **pair** — and the pair is not
/// evaluable at the moment it has to be evaluated: a device cannot know the
/// served-bytes digest before it has fetched the bytes. So *"refuses from the
/// marker instead of re-fetching those bytes"* was false of any implementation,
/// and worse, **every** re-serve then cost a transfer: A-1 re-serves one head
/// under a fresh byte encoding as often as it likes, and the device downloads
/// bound 1's 16 MiB, writes a marker and writes a receipt into an append-only
/// `receipts.jsonl` each time. Pass seventeen's own soundness argument — that
/// markers and receipts accrue at the **honest head-write rate**, because A-1
/// cannot mint a head — is severed by that, because a new byte encoding of an
/// old head is a new key.
///
/// **The key is the head digest, and the marker carries a bounded list of the
/// served-bytes digests it has already refused.** A re-serve is fetched and
/// tried only when its digest is not already on the marker, which is evaluable
/// where it has to be — after the fetch, before the store — and past
/// `maximumRefusedServedDigests` the head stays refused until a **new** head
/// arrives. So an idle vault still recovers through an honest re-serve, DB17-H1's
/// actual complaint, and A-1's channel is bounded at eight transfers and eight
/// receipts per head rather than at the relay's own rate.
public struct VaultHeadRefusalMarker: Codable, Sendable, Hashable {
    /// The bound on both the fetches and the receipts one refused head can
    /// cost. Eight is chosen rather than derived, and is said to be chosen.
    public static let maximumRefusedServedDigests = 8
    /// **A refusal spends, and an incomplete page sequence spends too**
    /// (nineteenth pass). Keying the budget on distinct served-bytes digests
    /// alone let a `pagesIncomplete` refusal cost nothing: the relay served
    /// three pages of four, stopped, and the sequence that never completed
    /// recorded no digest to spend against. The budget is therefore **bytes
    /// fetched per head digest** and **an attempt count**, and an incomplete
    /// sequence spends one attempt and the bytes it fetched — so the pre-fetch
    /// guard fires for it as it does for every other refusal.
    public static let maximumAttemptsPerHead = 8
    public static let maximumBytesFetchedPerHead = 128 * 1024 * 1024

    /// The canonical digest of what a transfer carried, **over the staged pages
    /// concatenated in index order, under one domain** (eighteenth pass,
    /// DB18-C2): per-page and per-staged-set give different markers for the same
    /// attack, and the design named no domain.
    public static func servedDigest(pages: [Int: [VaultSealedRecord]]) -> String {
        var fields = ["vaultage.vault.servedpages.v1", "\(pages.count)"]
        for index in pages.keys.sorted() {
            fields.append("\(index)")
            let page = pages[index] ?? []
            fields.append("\(page.count)")
            for record in page.sorted(by: { ($0.wireID, $0.revision) < ($1.wireID, $1.revision) }) {
                fields.append(record.wireID)
                fields.append("\(record.revision)")
                fields.append(SHA256.hash(data: record.sealed).map { String(format: "%02x", $0) }.joined())
            }
        }
        return CanonicalDigest.hex(fields)
    }

    /// One page's worth, for a caller that has no sequence.
    public static func servedDigest(_ records: some Collection<VaultSealedRecord>) -> String {
        servedDigest(pages: [0: Array(records)])
    }

    public let vaultID: UUID
    public let headDigest: String
    /// Every served-bytes digest this head has been refused at, oldest first,
    /// at most `maximumRefusedServedDigests`. It identifies a **repeat**, which
    /// costs no fetch, no entry and no receipt.
    public private(set) var servedDigests: [String]
    /// What this head has spent: one per refusal, whatever caused it.
    public private(set) var attempts: Int
    /// What this head has cost in bytes, which is the budget an incomplete
    /// sequence spends against.
    public private(set) var bytesFetched: Int
    /// Which bound it broke, as a value rather than as prose, so §10's row, the
    /// receipt and the notice read the same thing (seventeenth pass, DB17-M2).
    public let refusalReason: VaultRefusalNotice.Reason
    public let reason: String
    /// **The sequence's own state, on the marker** (custody plan version 23
    /// item 3; twentieth pass, DB20-H3). Rule 8's budget is four numbers — 15
    /// minutes from the **last completed page**, `maximumPagesPerHead` = 64,
    /// eight attempts and 128 MiB — and the two the counters above do not
    /// carry lived in actor memory, so a broker restart lost a multi-hundred-
    /// MiB restore's progress and the budget it had spent. The staged page
    /// indices and the instant the last page completed now travel with the
    /// in-progress hold and are cleared when the sequence ends, either way.
    public private(set) var stagedPageIndices: [Int]
    public private(set) var lastPageCompletedAtUptime: TimeInterval?

    public init(
        vaultID: UUID,
        headDigest: String,
        servedDigests: [String] = [],
        attempts: Int = 0,
        bytesFetched: Int = 0,
        refusalReason: VaultRefusalNotice.Reason,
        reason: String,
        stagedPageIndices: [Int] = [],
        lastPageCompletedAtUptime: TimeInterval? = nil
    ) {
        self.vaultID = vaultID
        self.headDigest = headDigest
        self.servedDigests = Array(servedDigests.prefix(Self.maximumRefusedServedDigests))
        self.attempts = attempts
        self.bytesFetched = bytesFetched
        self.refusalReason = refusalReason
        self.reason = reason
        self.stagedPageIndices = Array(Set(stagedPageIndices)).sorted().prefix(VaultRecordBudget.maximumPagesPerHead).map { $0 }
        self.lastPageCompletedAtUptime = lastPageCompletedAtUptime
    }

    private enum CodingKeys: String, CodingKey {
        case vaultID, headDigest, servedDigests, attempts, bytesFetched, refusalReason, reason
        case stagedPageIndices, lastPageCompletedAtUptime
    }

    /// Markers written before version 23 carry no sequence state; they decode
    /// as a sequence with no completed page, which is what they were.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            vaultID: try c.decode(UUID.self, forKey: .vaultID),
            headDigest: try c.decode(String.self, forKey: .headDigest),
            servedDigests: try c.decodeIfPresent([String].self, forKey: .servedDigests) ?? [],
            attempts: try c.decodeIfPresent(Int.self, forKey: .attempts) ?? 0,
            bytesFetched: try c.decodeIfPresent(Int.self, forKey: .bytesFetched) ?? 0,
            refusalReason: try c.decode(VaultRefusalNotice.Reason.self, forKey: .refusalReason),
            reason: try c.decode(String.self, forKey: .reason),
            stagedPageIndices: try c.decodeIfPresent([Int].self, forKey: .stagedPageIndices) ?? [],
            lastPageCompletedAtUptime: try c.decodeIfPresent(TimeInterval.self, forKey: .lastPageCompletedAtUptime)
        )
    }

    /// Whether this marker already answers for these bytes — either because it
    /// has refused them before, or because it has refused
    /// `maximumRefusedServedDigests` distinct encodings of this head already.
    public func answersFor(servedDigest: String) -> Bool {
        servedDigests.contains(servedDigest)
            || attempts >= Self.maximumAttemptsPerHead
            || bytesFetched >= Self.maximumBytesFetchedPerHead
    }

    /// **Whether this marker is holding a sequence rather than refusing one.**
    /// An in-progress restore holds the fence — a vault that is working is not
    /// a vault that has stopped hearing from its relay — and spends nothing
    /// until the sequence either completes or stalls (nineteenth pass).
    public var isInProgress: Bool { refusalReason == .pagesInProgress }

    /// **Zeroes the two counters and nothing else** (custody plan version 23
    /// item 2; twentieth pass, DB20-H1). §7.1 and §10 both already said the
    /// marker, its digest list and its reason survive the owner's retry, and
    /// the shipped reset deleted all three — which stops the repeat-digest rule
    /// recognising a repeat, so A-1 re-serves the **same eight encodings** as
    /// fresh failures and §10's *"at most eight per head digest"* receipt bound
    /// is void after one press of a button A-1 decides when to provoke.
    mutating func resetCounters() {
        attempts = 0
        bytesFetched = 0
    }

    /// Records one more refused encoding. Returns whether it was new, which is
    /// what bounds the receipts: **at most one receipt per served-bytes digest
    /// recorded on a marker**.
    mutating func record(servedDigest: String, bytes: Int) -> Bool {
        attempts += 1
        bytesFetched += max(0, bytes)
        guard !servedDigests.contains(servedDigest),
              servedDigests.count < Self.maximumRefusedServedDigests
        else { return false }
        servedDigests.append(servedDigest)
        return true
    }
}

/// The per-vault head refusals, in the broker's container at `headRefusals/` —
/// a row in §10's manifest, **with an iOS row beside it**.
///
/// **One marker per `(vault, head digest)`, cleared per marker** (version 20
/// item 4; seventeenth pass, DB17-L1; eighteenth pass, DB18-C1). One accepted
/// head clears the vault's set, and the reason is the chain's **linearity** —
/// no head below the watermark is offered as next, and a head above it has a
/// different preimage and therefore a different digest — stated rather than
/// assumed.
///
/// **Bounded by the retained heads, never evicted at a cap** (nineteenth
/// pass). A 256-marker cap dropping the oldest first is a cap a relay can walk:
/// it re-mints markers round-robin, and the marker that answers for the bytes
/// it is about to re-serve is the one the cap just dropped. The honest bound is
/// the one the chain already has — **one marker per retained head digest**,
/// dropped when that head leaves retention — because a head the device no
/// longer retains is not a head it will be offered as next, so a marker for it
/// answers for nothing.
public actor VaultHeadRefusalStore {

    private let container: BrokerContainer

    public init(container: BrokerContainer) { self.container = container }

    public nonisolated var root: URL { container.directory(.headRefusals) }

    private nonisolated func file(_ vaultID: UUID) -> URL {
        root.appendingPathComponent("\(vaultID.uuidString.lowercased()).json")
    }

    /// The vault's markers, oldest first.
    public func markers(_ vaultID: UUID) -> [VaultHeadRefusalMarker] { Self.markersSynchronously(file(vaultID)) }

    /// The most recent **refusal**, which is what the vault's view renders. An
    /// in-progress sequence is not one: it holds the fence and it is shown as
    /// progress, so a real refusal beside it is the one the owner is told about
    /// (nineteenth pass).
    public func refusal(_ vaultID: UUID) -> VaultHeadRefusalMarker? {
        let all = markers(vaultID)
        return all.last { !$0.isInProgress } ?? all.last
    }

    public func marker(vaultID: UUID, headDigest: String) -> VaultHeadRefusalMarker? {
        markers(vaultID).first { $0.headDigest == headDigest }
    }

    /// **Evaluated after the fetch, which is where it can be evaluated**
    /// (DB18-C1): the device has the bytes in hand, computes their digest, and
    /// refuses without storing anything. `true` means this head already answers
    /// for these bytes — it has refused them, or it has refused eight distinct
    /// encodings of this head already and stays refused until a new head
    /// arrives.
    public func hasRefused(vaultID: UUID, headDigest: String, servedDigest: String) -> Bool {
        marker(vaultID: vaultID, headDigest: headDigest)?.answersFor(servedDigest: servedDigest) ?? false
    }

    /// Whether this vault is holding a refusal at all — what the freeze fence
    /// reads, because a refused head is a head that **arrived** (seventeenth
    /// pass, DB17-M3).
    public nonisolated static func isHoldingARefusal(container: BrokerContainer, vaultID: UUID) -> Bool {
        !markersSynchronously(container.directory(.headRefusals)
            .appendingPathComponent("\(vaultID.uuidString.lowercased()).json")).isEmpty
    }

    static func markersSynchronously(_ url: URL) -> [VaultHeadRefusalMarker] {
        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode([VaultHeadRefusalMarker].self, from: data)
        else { return [] }
        return list
    }

    /// Records a refusal of `servedDigest` under this head. **Returns whether a
    /// receipt is owed**, which is how the receipt stream is bounded: at most
    /// one per served-bytes digest recorded on a marker, so at most eight per
    /// head (DB18-C1).
    @discardableResult
    public func record(
        _ marker: VaultHeadRefusalMarker,
        servedDigest: String,
        bytesFetched: Int = 0
    ) throws -> Bool {
        // **An in-progress hold spends nothing, and that includes the digest
        // list.** §7.1 says so in terms — *"it spends nothing"* — and recording
        // its served-bytes digest spent two things: an attempt, and the one
        // entry that would have owed the refusal's receipt, so a head refused
        // `namedAndNotServed` after a paged transfer produced **no** receipt and
        // §7.1's disclosure was lost in exactly the case DB17-H2 is about.
        //
        // The hold is written so the fence has something to hold on, and it is
        // superseded in place by whatever the sequence becomes.
        if marker.isInProgress {
            try writeHold(marker)
            return false
        }
        var list = markers(marker.vaultID)
        var owed: Bool
        if let index = list.firstIndex(where: { $0.headDigest == marker.headDigest }) {
            var existing = list[index]
            // **A real refusal supersedes an in-progress hold on the same
            // head**, carrying forward what that head has already spent: the
            // sequence was working and then stopped, and the owner is told the
            // second thing rather than the first.
            if existing.isInProgress, !marker.isInProgress {
                existing = VaultHeadRefusalMarker(
                    vaultID: existing.vaultID,
                    headDigest: existing.headDigest,
                    servedDigests: existing.servedDigests,
                    attempts: existing.attempts,
                    bytesFetched: existing.bytesFetched,
                    refusalReason: marker.refusalReason,
                    reason: marker.reason
                )
            }
            owed = existing.record(servedDigest: servedDigest, bytes: bytesFetched)
            list[index] = existing
        } else {
            var fresh = marker
            owed = fresh.record(servedDigest: servedDigest, bytes: bytesFetched)
            list.append(fresh)
        }
        try write(list, vaultID: marker.vaultID)
        return owed
    }

    /// The in-progress hold: the same marker on the same key, carrying whatever
    /// that head has already spent, with the reason set to `pagesInProgress` so
    /// §3.3's fence holds over a restore that is **working**. It adds no
    /// attempt, no bytes and no digest.
    private func writeHold(_ marker: VaultHeadRefusalMarker) throws {
        var list = markers(marker.vaultID)
        if let index = list.firstIndex(where: { $0.headDigest == marker.headDigest }) {
            let existing = list[index]
            // A head already refused for a real reason is **not** demoted back
            // to a hold: the sequence that follows it is the retry, and the
            // owner is told the refusal rather than "still arriving".
            guard existing.isInProgress else { return }
            list[index] = VaultHeadRefusalMarker(
                vaultID: existing.vaultID,
                headDigest: existing.headDigest,
                servedDigests: existing.servedDigests,
                attempts: existing.attempts,
                bytesFetched: existing.bytesFetched,
                refusalReason: .pagesInProgress,
                reason: marker.reason,
                stagedPageIndices: marker.stagedPageIndices,
                lastPageCompletedAtUptime: marker.lastPageCompletedAtUptime
            )
        } else {
            list.append(marker)
        }
        try write(list, vaultID: marker.vaultID)
    }

    /// **Per marker** — one refused head stops being refused.
    public func clear(vaultID: UUID, headDigest: String) throws {
        try write(markers(vaultID).filter { $0.headDigest != headDigest }, vaultID: vaultID)
    }

    /// **One acceptance clears the vault's set**, and the reason is the chain's
    /// linearity rather than an assumption.
    public func clear(_ vaultID: UUID) {
        try? FileManager.default.removeItem(at: file(vaultID))
    }

    /// **The owner's explicit retry from the notice** (nineteenth pass). An
    /// honest relay on a flaky transport spends the budget without ever being
    /// dishonest, and a marker that could only be cleared by a *new* head would
    /// leave that vault refused until the sequencer happened to write one. The
    /// owner asking again resets what the head has spent; it costs A-1 nothing
    /// it did not already have, because A-1 cannot press the button.
    public func resetForOwnerRetry(vaultID: UUID, headDigest: String) throws {
        var list = markers(vaultID)
        guard let index = list.firstIndex(where: { $0.headDigest == headDigest }) else { return }
        // **The marker stands.** What the retry costs is the two counters, so
        // the head may be fetched again; what it must not cost is the digest
        // list, because that is the only thing that tells a repeat encoding
        // from a fresh one, and the receipt bound rests on it.
        list[index].resetCounters()
        try write(list, vaultID: vaultID)
    }

    /// **The marker set is bounded by the retained heads.** A marker for a head
    /// the device no longer retains answers for nothing — the chain is linear,
    /// so that head will not be offered as next — and keeping it is what a cap
    /// was standing in for.
    public func pruneToRetainedHeads(vaultID: UUID, retained: Set<String>) throws {
        try write(markers(vaultID).filter { retained.contains($0.headDigest) }, vaultID: vaultID)
    }

    private func write(_ list: [VaultHeadRefusalMarker], vaultID: UUID) throws {
        guard !list.isEmpty else {
            try? FileManager.default.removeItem(at: file(vaultID))
            return
        }
        try container.ensure()
        let manager = FileManager.default
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(list)
        let temporary = root.appendingPathComponent("refusal-\(UUID().uuidString).tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw VaultCipherStoreError.storage("Could not create a head-refusal marker.")
        }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try? handle.close()
        _ = try manager.replaceItemAt(file(vaultID), withItemAt: temporary, backupItemName: nil, options: [])
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(vaultID).path)
    }
}
