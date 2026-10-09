import Foundation

// BL-100 slice A — §7.1's **three stages, and only the third needs a key**
// (`13-MULTI-DEVICE-CUSTODY.md` version 17, **as amended by the sixteenth
// independent pass**, `evidence/security-review-bl097-v16-2026-09-14.md`
// DB16-C1, DB16-H2, DB16-H3, DB16-M3; version 19 states them).
//
// 1. **Transfer** — background, ciphertext only, head signature and chain
//    verified with public keys and no Enclave operation. **And every size bound
//    is evaluated here, over the whole served head, before apply** (DB16-C1): a
//    refusal inside the transactional stage is the one thing that stage exists
//    to make impossible, because a head that is half-applied is a head
//    `normalize` runs over a hole — and at the pin `normalize` **mints a
//    replacement vault** when the `vault` record is missing.
// 2. **Apply** — **no key, no presence and no refusal that can leave a hole.**
//    Everything it decides is carried **outside** the AEAD, so nothing it does
//    reads a plaintext byte. **Runs locked**, like transfer.
// 3. **Open the metadata plane** — §2.4.1's **flow 7**, one presence proof per
//    vault, at an owner-initiated moment.

/// What transfer refuses — **the whole head, before anything is stored**.
public enum VaultTransferRefusal: Error, Equatable, Sendable, LocalizedError {
    /// **Bound 1, read from the receiving side, is a bound on what one transfer
    /// carries** (seventeenth pass, DB17-C2). Version 19 states it both ways —
    /// §7.1 stage 1 evaluates the bounds *"over the whole served head"* and
    /// §3.1 says *"this bound is on what one transfer carries, not on what the
    /// head names"* — and slice A shipped the first, under which a kit restore
    /// or a new pairing of any vault over 1,024 live records is refused whole,
    /// at every head, permanently, with a string blaming the relay for the size
    /// of the owner's own vault. The head's `digest` is over every live
    /// record, so a head **names** the whole vault; what one transfer
    /// **carries** is the relay's choice, and that is the quantity a receiving
    /// device can bound without breaking restore.
    case transferCarriesTooManyRecords(carried: Int, cap: Int)
    case transferBodyTooLarge(bytes: Int, cap: Int)
    /// **A page sequence that stopped** (eighteenth pass, DB18-C2). It is the
    /// one stall version 20's paging introduced that produced no marker, so the
    /// fence spoke over exactly the state it was written to silence.
    case pagesIncomplete(staged: Int, named: Int)
    /// **A page that belongs to another head.** It is refused and discarded and
    /// counts toward nothing — not the staged set, not the attempt budget, not
    /// the served-bytes digest — so it writes no marker either.
    case pageNamesAnotherHead(pageHead: String, staging: String)
    case recordTooLarge(wireID: String, bytes: Int)
    case vaultFull(liveRecords: Int, sealedBytes: Int)
    /// **A record the head names that no transfer carried** (seventeenth pass,
    /// DB17-H2). It was a hard error inside apply's transaction, which left it
    /// with no marker, no receipt, no notice and no keyed retry — so A-1
    /// reproduced version 17's permanent-halt-with-no-disclosure by
    /// *withholding* one named record instead of *oversizing* one. It is a
    /// refusal of the head, with the same machinery as the other four, raised
    /// **before** the transaction opens.
    case namedAndNotServed(wireID: String)
    /// Already refused once, at this head digest **and these bytes**
    /// (seventeenth pass, DB17-H1).
    case alreadyRefused(headDigest: String)

    /// **A diagnostic, and no owner surface renders it** (custody plan version
    /// 21; eighteenth pass, DB18-M3). A thrown error carries a description; the
    /// vault surface renders §7.1's string for that refusal — the one
    /// `VaultRefusalNotice` composes from `reason` — and nothing else. The two
    /// are separated here so a builder cannot reach the owner through the
    /// error by accident.
    public var errorDescription: String? {
        switch self {
        case .transferCarriesTooManyRecords(let carried, let cap):
            "A transfer carried \(carried) records against a cap of \(cap)."
        case .transferBodyTooLarge(let bytes, let cap):
            "A transfer carried \(bytes) bytes against a cap of \(cap)."
        case .recordTooLarge(_, let bytes):
            "A served record of \(bytes) bytes is over the per-record ceiling."
        case .vaultFull(let records, let bytes):
            "The vault is at \(records) records and \(bytes) bytes."
        case .namedAndNotServed(let wireID):
            "The head names a record no transfer carried (\(wireID.prefix(8)))."
        case .pagesIncomplete(let staged, let named):
            "The page sequence stopped at \(staged) of \(named) records."
        case .alreadyRefused(let digest):
            "This head was already refused at these bytes (\(digest.prefix(16)))."
        case .pageNamesAnotherHead(let pageHead, let staging):
            "A page named head \(pageHead.prefix(16)) while \(staging.prefix(16)) was staging."
        }
    }

    /// **The owner-facing string for this refusal**, which is §7.1's and the
    /// only thing a surface renders.
    public func ownerNotice(vaultDisplayName: String) -> String {
        VaultRefusalNotice.headRefused(vaultDisplayName: vaultDisplayName, reason: reason)
    }

    /// Which of the five a refusal is, so the notice, the marker and the
    /// receipt all read the same value rather than three renderings of it
    /// (seventeenth pass, DB17-M1, DB17-M2).
    public var reason: VaultRefusalNotice.Reason {
        switch self {
        case .transferCarriesTooManyRecords, .transferBodyTooLarge: .boundOne
        case .recordTooLarge: .maximumSealedRecordBytes
        case .vaultFull: .boundTwo
        case .namedAndNotServed, .alreadyRefused: .namedAndNotServed
        case .pagesIncomplete, .pageNamesAnotherHead: .pagesIncomplete
        }
    }

    /// The one-line reason the persisted marker carries. It names **no label**.
    public var markerReason: String {
        switch self {
        case .transferCarriesTooManyRecords(let carried, let cap): "transfer carries \(carried) records, cap \(cap)"
        case .transferBodyTooLarge(let bytes, let cap): "transfer body is \(bytes) bytes, cap \(cap)"
        case .recordTooLarge(_, let bytes): "a served record is \(bytes) bytes"
        case .vaultFull(let records, let bytes): "vault at \(records) records and \(bytes) bytes"
        case .namedAndNotServed(let wireID): "the head names a record no transfer carried (\(wireID.prefix(8)))"
        case .pagesIncomplete(let staged, let named): "the page sequence stopped at \(staged) of \(named) records"
        case .pageNamesAnotherHead(let pageHead, _): "a page named head \(pageHead.prefix(16))"
        case .alreadyRefused(let digest): "already refused at \(digest.prefix(16))"
        }
    }
}

/// What apply refuses. **Neither is a size bound** — both are facts about the
/// head's own signed digest, checked before a byte is written, so apply cannot
/// leave a partial head behind.
public enum VaultApplyRefusal: Error, Equatable, Sendable, LocalizedError {
    /// The served `(wireID, revision)` pairs do not hash to the head's signed
    /// `digest`. Catches a relay that edits the set in transit.
    case servedSetDoesNotMatchSignedDigest
    /// Transfer did not admit this head. Apply is not reachable without it.
    case notTransferred

    public var errorDescription: String? {
        switch self {
        case .servedSetDoesNotMatchSignedDigest:
            "The records this Mac was sent are not the records this vault's history names."
        case .notTransferred:
            "An update was applied without being verified first, and was refused."
        }
    }
}

/// What one fold did, and to which records.
public struct VaultFoldOutcome: Sendable, Equatable {
    public var promoted: [String] = []
    /// Opened-before records whose arriving revision did not open: **discarded
    /// with a receipt, and the last good revision stays current**.
    public var discarded: [String] = []
    /// Never-opened records whose arriving revision did not open: **retained**,
    /// with a per-record marker.
    public var retainedUnopenable: [String] = []
    /// The **blocking** markers this fold raised — a `vault` or `folder` record
    /// this device has never opened. `normalize` does not run, the projection is
    /// not rebuilt, nothing is sealed, the owner is told, and the previous
    /// projection is left standing **while one exists in memory**.
    public var blockingMarkers: [VaultFoldMarker] = []
    /// The non-blocking ones — an `item`, `value` or `blob` this device has
    /// never opened. **The vault still folds and projects around them**, and its
    /// view renders a **count** of records waiting for a readable copy
    /// (sixteenth pass, DB16-H3).
    public var recordsWaiting: [VaultFoldMarker] = []

    public var failed: Bool { !blockingMarkers.isEmpty }

    public init() {}
}

/// **One page of one head's records** (eighteenth pass, DB18-C2).
///
/// A paged transfer is **one head**, and every page says which: version 20 gave
/// paging a rule for its success and none for any of its failures, so nothing
/// bound a page to a head, nothing said what ends a sequence, and nothing said
/// what a page may carry that the head does not name. Interleaved pages of two
/// honestly-signed heads were the sharpest of those: bound 2 is evaluated over
/// the cumulative staged set, so pages of a second head inflate the count and
/// refuse a **legal** head with the vault-is-full notice, telling the owner
/// their vault is full when it is not, at no cost to the relay.
public struct VaultTransferPage: Sendable, Equatable {
    public let headDigest: String
    public let index: Int
    public let records: [VaultSealedRecord]

    public init(headDigest: String, index: Int, records: [VaultSealedRecord]) {
        self.headDigest = headDigest
        self.index = index
        self.records = records
    }
}

/// The three stages. The **broker** performs all three (seventh pass, DB7-L3);
/// the app drives them over XPC and never decrypts anything.
public actor VaultSyncApply {
    private let accountSubject: String
    private let store: VaultCipherStore
    private let heads: VaultHeadChainStore
    private let markers: VaultFoldFailureStore
    private let refusals: VaultHeadRefusalStore
    private let budget: VaultVaultBudget
    /// The stall budgets' clock. Uptime, like every other duration in this
    /// design, so a backwards wall clock contributes nothing.
    private let monotonic: any MonotonicClock

    /// Head digests transfer has admitted. Apply refuses a head that did not
    /// come through transfer, so the bounds cannot be skipped by calling the
    /// second stage directly.
    private var admitted: Set<String> = []

    /// **What the pages of one head have carried so far** (seventeenth pass,
    /// DB17-C2). A head names the whole live set, so a kit restore or a new
    /// pairing of a large vault is a head naming more records than bound 1
    /// admits in one transfer. It is fetched in **pages**, each page bounded,
    /// and **applied whole**: staging is where the pages meet, and apply opens
    /// its transaction only when every record the head names is here.
    private var staged: [String: [Int: [VaultSealedRecord]]] = [:]
    /// When a head's sequence began, which is the stall clock's reference
    /// only until its first page completes: from then on the reference is the
    /// **last completed page**, persisted on the in-progress marker (custody
    /// plan version 23 item 3; twentieth pass, DB20-H3), together with the
    /// staged page indices that are rule 8's page count.
    private var sequenceBegan: [String: TimeInterval] = [:]
    /// Served records a page carried that its head does not name. They were
    /// discarded; this is the count a contract reads.
    private var unnamedDiscarded: [String: Int] = [:]
    /// Refusals whose served-bytes digest was newly recorded, and which
    /// therefore owe a receipt. **At most eight per head** (DB18-C1).
    private var receiptsOwed: [VaultHeadRefusalMarker] = []

    public init(
        accountSubject: String,
        store: VaultCipherStore,
        heads: VaultHeadChainStore,
        foldFailures: VaultFoldFailureStore,
        headRefusals: VaultHeadRefusalStore? = nil,
        budget: VaultVaultBudget = .shipped,
        monotonic: any MonotonicClock = SystemMonotonicClock()
    ) {
        self.accountSubject = accountSubject
        self.store = store
        self.heads = heads
        self.markers = foldFailures
        self.refusals = headRefusals ?? VaultHeadRefusalStore(container: store.container)
        self.budget = budget
        self.monotonic = monotonic
    }

    // MARK: - Stage 1: transfer, which is where every size bound lives

    /// Background, ciphertext only. The head's signature and its chain are
    /// verified with **public keys** — no Enclave operation — so this runs
    /// locked, asleep-and-woken, backgrounded.
    ///
    /// **And this is where the bounds are** (sixteenth pass, DB16-C1). Bound 2,
    /// the per-record `maximumSealedRecordBytes` bound and the head-level count
    /// bound are evaluated over the **whole served head**, and a head that fails
    /// any of them is refused **as a whole**: a persisted `headRefusal` marker
    /// naming the head digest and the reason, a record-shaped receipt, an owner
    /// notice, **the watermark does not advance**, and the retry is keyed on the
    /// digest so the same bytes are not fetched again.
    ///
    /// Returns the receipt the caller writes, or `nil` when the head was
    /// admitted.
    @discardableResult
    public func transfer(
        head: SignedVaultHead,
        served: [VaultSealedRecord],
        namedPairs: [(wireID: String, revision: Int)],
        verifier: some VaultHeadVerifying,
        watermark: VaultHeadWatermark?
    ) async throws -> VaultHeadRefusalMarker? {
        let digest = head.head.chainDigest(accountSubject: accountSubject)
        let index = (staged[digest]?.keys.max()).map { $0 + 1 } ?? 0
        return try await transfer(
            head: head,
            page: VaultTransferPage(headDigest: digest, index: index, records: served),
            namedPairs: namedPairs, verifier: verifier, watermark: watermark
        )
    }

    @discardableResult
    public func transfer(
        head: SignedVaultHead,
        page: VaultTransferPage,
        namedPairs: [(wireID: String, revision: Int)],
        verifier: some VaultHeadVerifying,
        watermark: VaultHeadWatermark?
    ) async throws -> VaultHeadRefusalMarker? {
        try VaultHeadAdmission.admit(head, accountSubject: accountSubject, watermark: watermark, verifier: verifier)
        let vaultID = head.head.vaultID
        let digest = head.head.chainDigest(accountSubject: accountSubject)

        // **A paged transfer is one head, and a page that names another is
        // refused and discarded** (DB18-C2). It counts toward nothing: not the
        // staged set, not the attempt budget, not the served-bytes digest —
        // because interleaving two heads' pages is how a legal head is made to
        // fail bound 2 and show the owner a vault-is-full notice for a vault
        // that is not full.
        guard page.headDigest == digest else {
            throw VaultTransferRefusal.pageNamesAnotherHead(pageHead: page.headDigest, staging: digest)
        }

        // **A served record the head does not name is refused and discarded.**
        // Before paging this was unreachable — one transfer carried one head's
        // records and stage 2's digest check settled the set — and under paging
        // a builder who stages first and matches at apply gives A-1 a way to
        // put chosen ciphertext at a chosen `(wireID, revision)` into the
        // store, under a `wireID` the map cannot resolve and the never-opened
        // split has no branch for.
        let named = Set(namedPairs.map(\.wireID))
        let admissible = page.records.filter { named.contains($0.wireID) }
        let discarded = page.records.count - admissible.count

        var pages = staged[digest] ?? [:]
        pages[page.index] = admissible
        let servedDigest = VaultHeadRefusalMarker.servedDigest(pages: pages)
        // **Rule 8's state is read from the marker, not from actor memory**
        // (custody plan version 23 item 3; DB20-H3): the page indices this
        // sequence has completed and when the last one did survive a broker
        // restart there, so a restart neither loses a restore's progress nor
        // hands the head a fresh clock.
        let heldProgress = await refusals.marker(vaultID: vaultID, headDigest: digest).flatMap { $0.isInProgress ? $0 : nil }
        let knownIndices = Set((staged[digest] ?? [:]).keys).union(heldProgress?.stagedPageIndices ?? [])
        let isNewIndex = !knownIndices.contains(page.index)

        // **Keyed on the head digest, evaluated after the fetch** (DB18-C1).
        // **And a repeat spends** (custody plan version 23 item 2; twentieth
        // pass, DB20-H2). The bytes were fetched, so a repeat costs the attempt
        // and the bytes it cost — with **no** digest entry and **no** receipt,
        // which is what the digest list is for. Refusing a repeat for free
        // left A-1's channel at the relay's own rate: a withholding relay
        // re-serving identical bytes was fetched on every run, the marker never
        // moved past one attempt, and the pre-fetch guard never fired.
        if await refusals.hasRefused(vaultID: vaultID, headDigest: digest, servedDigest: servedDigest) {
            staged[digest] = pages
            throw try await refuse(
                .alreadyRefused(headDigest: digest), vaultID: vaultID, headDigest: digest, servedDigest: servedDigest
            )
        }

        do {
            // **Bound 1 bounds what one transfer carries** (seventeenth pass,
            // DB17-C2). A head naming more is paged; a **page** over either
            // number still refuses the head whole.
            guard page.records.count <= budget.maximumRecordsPerTransfer else {
                throw VaultTransferRefusal.transferCarriesTooManyRecords(
                    carried: page.records.count, cap: budget.maximumRecordsPerTransfer
                )
            }
            let bodyBytes = page.records.reduce(0) { $0 + $1.byteCount }
            guard bodyBytes <= budget.maximumTransferBodyBytes else {
                throw VaultTransferRefusal.transferBodyTooLarge(bytes: bodyBytes, cap: budget.maximumTransferBodyBytes)
            }
            for record in admissible where record.byteCount > budget.maximumSealedRecordBytes {
                throw VaultTransferRefusal.recordTooLarge(wireID: record.wireID, bytes: record.byteCount)
            }
            // **Bound 2's record half is a union, not a sum** (twentieth pass,
            // DB20-C1). DB18-M5 asked for the staged set to be summed with the
            // live set, and the guard shipped that way — but the head's digest
            // is over **every** live record, so the cumulative staged set of an
            // ordinary head **is** the live set, one arriving revision per
            // record. Summing the live set with itself evaluates `2L ≤ 50,000`
            // and refuses every head for a vault past 25,000 live records, with
            // §7.1's relay-caused vault-is-full string, on a vault at half its
            // cap — and it contradicts DB14-H1 one bullet away, which says an
            // arriving revision is *"invisible to the 50,000"*.
            //
            // So what is added to the live count is the staged records whose
            // `wireID` is **not already live**: a re-serve of a vault's own
            // records adds nothing, and a head that genuinely grows the vault
            // adds exactly what it grows it by.
            //
            // **The byte half is unchanged and is still a sum**, because §3.1's
            // own paragraph says so: an arriving revision is sealed store until
            // it is promoted, and *"the doubling is the working set's normal
            // case, not the attack case"*.
            let liveRecords = await store.liveRecordCount(vaultID: vaultID)
            let liveWireIDs = await store.liveWireIDs(vaultID: vaultID)
            let sealedBytes = await store.byteCount(vaultID: vaultID)
            let arriving = pages.values.flatMap { $0 }
            let arrivingBytes = arriving.reduce(0) { $0 + $1.byteCount }
            let addedRecords = Set(arriving.map(\.wireID)).subtracting(liveWireIDs).count
            guard liveRecords + addedRecords <= budget.maximumLiveRecords,
                  sealedBytes + arrivingBytes <= budget.maximumSealedBytes
            else {
                throw VaultTransferRefusal.vaultFull(
                    liveRecords: liveRecords + addedRecords, sealedBytes: sealedBytes + arrivingBytes
                )
            }
            // **What ends a page sequence**: every page the head names is
            // staged, or a compiled budget runs out. A sequence that simply
            // stops is the stall this refusal exists for — and **the stall
            // clock runs from the last completed page, refreshed by every
            // completed page** (custody plan version 23 item 3; DB20-H3), so
            // §3.1's own worked kit restore over a slow link is not refused at
            // 15 minutes while every page is landing. A page at an index the
            // sequence already holds completes nothing and refreshes nothing.
            // The page count is rule 8's `maximumPagesPerHead`, the fourth
            // number, over **distinct** indices.
            let began = sequenceBegan[digest] ?? monotonic.uptime
            let reference = heldProgress?.lastPageCompletedAtUptime ?? began
            let distinctPages = knownIndices.count + (isNewIndex ? 1 : 0)
            let stagedCount = pages.values.reduce(0) { $0 + $1.count }
            if stagedCount < namedPairs.count,
               distinctPages >= VaultRecordBudget.maximumPagesPerHead
                   || monotonic.uptime - reference >= VaultRecordBudget.pageSequenceStallSeconds {
                throw VaultTransferRefusal.pagesIncomplete(staged: stagedCount, named: namedPairs.count)
            }
            sequenceBegan[digest] = began
        } catch let refusal as VaultTransferRefusal {
            throw try await refuse(refusal, vaultID: vaultID, headDigest: digest, servedDigest: servedDigest)
        }

        if discarded > 0 {
            // Discarded, not stored, and said rather than silent.
            unnamedDiscarded[digest, default: 0] += discarded
        }
        staged[digest] = pages
        admitted.insert(digest)
        // **No vault-wide clear here** (custody plan version 23 item 2;
        // twentieth pass, DB20-H2). Version 22 reset the budget on a head this
        // device had not marked *arriving*; arrival is A-1's to schedule, so
        // its stock of unmarked admissible heads grew for the length of the
        // attack, each worth a fresh 128 MiB — and this clear ran at
        // **admission**, before staging, so one admissible page bought a fresh
        // budget for every head in the vault. The reset that survives is the one
        // on a head this device **accepts**, which is at apply.
        
        // **An in-progress sequence holds the fence** (nineteenth pass): a
        // vault in the middle of a restore is not a vault that has stopped
        // hearing from its relay, and §3.3's intervals would otherwise route a
        // working device's writes at 24 hours of a large restore. It is a
        // marker that spends nothing and clears the moment the head applies.
        let stagedNow = pages.values.reduce(0) { $0 + $1.count }
        if stagedNow < namedPairs.count {
            // The hold carries the sequence's state: every index staged so far
            // and the instant the last **new** one completed.
            let completedAt = isNewIndex ? monotonic.uptime : (heldProgress?.lastPageCompletedAtUptime ?? monotonic.uptime)
            _ = try? await refusals.record(
                VaultHeadRefusalMarker(
                    vaultID: vaultID, headDigest: digest,
                    refusalReason: .pagesInProgress,
                    reason: "staging \(stagedNow) of \(namedPairs.count) records",
                    stagedPageIndices: Array(knownIndices.union([page.index])),
                    lastPageCompletedAtUptime: completedAt
                ),
                servedDigest: servedDigest,
                bytesFetched: 0
            )
        }
        return nil
    }

    /// How many of this head's records the pages have carried so far — what a
    /// fetcher asks before deciding whether to ask for another page.
    public func stagedCount(head: SignedVaultHead) -> Int {
        (staged[head.head.chainDigest(accountSubject: accountSubject)] ?? [:]).values.reduce(0) { $0 + $1.count }
    }

    /// How many served records this head's pages carried that it does not name.
    /// They were discarded; this is what a contract counts.
    public func unnamedRecordsDiscarded(head: SignedVaultHead) -> Int {
        unnamedDiscarded[head.head.chainDigest(accountSubject: accountSubject)] ?? 0
    }

    /// **Whether the sequence is over**, which is what lets apply open its
    /// transaction: every record the head names is staged.
    public func isReadyToApply(head: SignedVaultHead, namedPairs: [(wireID: String, revision: Int)]) -> Bool {
        stagedCount(head: head) == namedPairs.count
    }

    /// The refusals whose served-bytes digest was newly recorded, drained by the
    /// caller that writes the receipts. **At most eight per head** (DB18-C1),
    /// which is what bounds an append-only `receipts.jsonl` against a relay
    /// re-encoding one head.
    public func drainReceiptsOwed() -> [VaultHeadRefusalMarker] {
        defer { receiptsOwed = [] }
        return receiptsOwed
    }

    /// **One refusal path, so every refusal gets the same four things**: the
    /// persisted marker, the receipt the caller writes from it, the notice, and
    /// an unmoved watermark. It is used by the five bounds **and** by the
    /// named-and-not-served failure, which had none of them (DB17-H2).
    private func refuse(
        _ refusal: VaultTransferRefusal,
        vaultID: UUID,
        headDigest: String,
        servedDigest: String
    ) async throws -> VaultTransferRefusal {
        let marker = VaultHeadRefusalMarker(
            vaultID: vaultID,
            headDigest: headDigest,
            servedDigests: [],
            refusalReason: refusal.reason,
            reason: refusal.markerReason
        )
        // **The refusal spends** (nineteenth pass): one attempt and the bytes
        // this head has fetched so far, so the pre-fetch guard fires for an
        // incomplete sequence as it does for every other refusal — the stall
        // that recorded no digest used to cost nothing.
        let spent = (staged[headDigest] ?? [:]).values.flatMap { $0 }.reduce(0) { $0 + $1.byteCount }
        if try await refusals.record(marker, servedDigest: servedDigest, bytesFetched: spent),
           let recorded = await refusals.marker(vaultID: vaultID, headDigest: headDigest) {
            receiptsOwed.append(recorded)
        }
        // Nothing this head carried survives the refusal, so the next served
        // head starts from an empty staging area rather than from a set the
        // relay half-chose.
        staged[headDigest] = nil
        sequenceBegan[headDigest] = nil
        unnamedDiscarded[headDigest] = nil
        admitted.remove(headDigest)
        return refusal
    }

    // MARK: - Stage 2: apply

    /// **No key and no presence.** The served `(wireID, revision)` pairs are
    /// checked against the head's signed `digest`; a record the head names and
    /// the relay did not serve is a **refusal of the head** with the marker, the
    /// receipt, the notice and the unmoved watermark — never a hard error here
    /// (eighteenth pass, item 6); the ciphertext is written into
    /// `VaultCipherStore` **transactionally per head**, beside the record's last
    /// revision that opened and never over it; the watermark advances.
    ///
    /// **Nothing here can refuse for size.** That was DB16-C1: a bound evaluated
    /// after the first write leaves a partial head in the store, which is
    /// exactly what the transaction exists to prevent, and `normalize` then runs
    /// over a hole.
    ///
    /// Returns the substitutions it performed — a replaced arriving revision —
    /// so the caller writes **one receipt per substitution** (DB16-M3).
    @discardableResult
    public func apply(
        head: SignedVaultHead,
        served: [VaultSealedRecord],
        namedPairs: [(wireID: String, revision: Int)],
        wallNow: Int
    ) async throws -> (chain: VaultHeadChainStore.Chain, substitutions: [VaultFoldMarker]) {
        let vaultID = head.head.vaultID
        let digest = head.head.chainDigest(accountSubject: accountSubject)
        guard admitted.contains(digest) else { throw VaultApplyRefusal.notTransferred }

        // The head's `digest` is over the sorted `(wireID, revision)` pairs of
        // the live set. A relay that edits the set in transit is caught here.
        guard VaultHeadWriter.liveSetDigest(namedPairs) == head.head.digest else {
            throw VaultApplyRefusal.servedSetDoesNotMatchSignedDigest
        }

        // **Applied whole, from every page** (DB17-C2), and **the transaction
        // begins only when every page the head names is staged** (DB18-C2).
        var servedByWire: [String: VaultSealedRecord] = [:]
        for page in (staged[digest] ?? [:]).sorted(by: { $0.key < $1.key }) {
            for record in page.value { servedByWire[record.wireID] = record }
        }
        let namedWireIDs = Set(namedPairs.map(\.wireID))
        for record in served where namedWireIDs.contains(record.wireID) {
            servedByWire[record.wireID] = record
        }
        let missing = namedPairs.first { servedByWire[$0.wireID] == nil }
        if let missing {
            // **Not a hard error inside the transaction** (DB17-H2). It is a
            // refusal of the head with the same machinery as the four bounds,
            // raised before a byte is written: marker, receipt, notice, the
            // watermark unmoved, and a retry on the next served head. A hard
            // error here aborted the transaction with no marker, no receipt and
            // no notice, so A-1 reproduced version 17's permanent halt by
            // withholding a named record instead of oversizing one.
            throw try await refuse(
                .namedAndNotServed(wireID: missing.wireID),
                vaultID: vaultID,
                headDigest: digest,
                servedDigest: VaultHeadRefusalMarker.servedDigest(servedByWire.values)
            )
        }
        let admittedRecords = namedPairs.compactMap { servedByWire[$0.wireID] }

        // **Either every record the head names is present and applied, or none
        // is** (first pass, M-3), because `VaultageMetadata.init` runs
        // `normalize` unconditionally and a replica that applied `folder`
        // records but not the `vault` record would silently lose the tree on
        // the next decode and then push the loss.
        var written: [String] = []
        var substitutions: [VaultFoldMarker] = []
        let held = await markers.markers(vaultID)
        do {
            for record in admittedRecords {
                let replaced = try await store.storeArriving(record, vaultID: vaultID)
                written.append(record.wireID)
                // **Once per substitution.** A replacement of a *retained
                // unopenable* revision is the one substitution A-1 gets per
                // revision, and A-1's row says the device says so each time.
                if replaced, let previous = held.first(where: { $0.wireID == record.wireID }) {
                    substitutions.append(VaultFoldMarker(
                        vaultID: vaultID, wireID: record.wireID,
                        revision: record.revision, recordKind: previous.recordKind
                    ))
                }
            }
        } catch {
            for wireID in written { try? await store.discardArriving(wireID: wireID, vaultID: vaultID) }
            throw error
        }

        // **The watermark advances at stage 2**, which is a claim about what
        // this device has **verified and stored**, not about what its owner has
        // looked at — so a locked Mac stays current and §3.3's freeze fence
        // stops tripping on an owner who simply did not unlock today.
        let chain = try await heads.accept(head, accountSubject: accountSubject, wallNow: wallNow)
        staged[digest] = nil
        sequenceBegan[digest] = nil
        // **The acknowledgement is sent at apply** (nineteenth pass), which is
        // the stage that has verified and stored: the vault's set of refusals
        // clears, and what survives is bounded by the heads still retained
        // rather than by a cap a relay can walk.
        await refusals.clear(vaultID)
        let retained = Set(chain.heads.map { $0.signed.head.chainDigest(accountSubject: accountSubject) })
        try? await refusals.pruneToRetainedHeads(vaultID: vaultID, retained: retained)
        return (chain, substitutions)
    }

    // MARK: - Stage 3's fold, which runs inside flow 7

    /// Promotes what opens, and applies §7.1's two rules to what does not.
    ///
    /// `open` is supplied by flow 7, which is the only thing in this design that
    /// holds `VCK_v`. This call does not obtain presence and does not open a key
    /// itself: it is the fold, and the flow is the key.
    public func fold(
        vaultID: UUID,
        arriving: [(wireID: String, subject: VaultRecordSubject)],
        open: (VaultSealedRecord, VaultRecordSubject) throws -> Data,
        receipts: (@Sendable (VaultFoldMarker) async -> Void)? = nil
    ) async throws -> VaultFoldOutcome {
        var outcome = VaultFoldOutcome()
        for entry in arriving {
            let held = try await store.record(wireID: entry.wireID, vaultID: vaultID)
            guard let candidate = held.arriving else { continue }
            let hasOpened = held.current != nil
            let marker = VaultFoldMarker(
                vaultID: vaultID, wireID: entry.wireID,
                revision: candidate.revision, recordKind: entry.subject.kind
            )
            do {
                _ = try open(candidate, entry.subject)
                try await store.promoteArriving(wireID: entry.wireID, vaultID: vaultID)
                try await markers.clear(vaultID: vaultID, wireID: entry.wireID)
                outcome.promoted.append(entry.wireID)
            } catch {
                if hasOpened {
                    // The **edit** case: the last good revision stays current
                    // and the arriving one is discarded with a receipt.
                    try await store.discardArriving(wireID: entry.wireID, vaultID: vaultID)
                    outcome.discarded.append(entry.wireID)
                } else {
                    // **This device has never opened the record.** The
                    // unopenable revision is **retained** — discarding it leaves
                    // `normalize` running over a missing record — and a
                    // **per-record marker** is written. Only a `vault` or
                    // `folder` marker blocks the vault (sixteenth pass,
                    // DB16-H3).
                    try await store.retainUnopenable(wireID: entry.wireID, vaultID: vaultID)
                    try await markers.record(marker)
                    outcome.retainedUnopenable.append(entry.wireID)
                    if marker.blocksVault {
                        outcome.blockingMarkers.append(marker)
                    } else {
                        outcome.recordsWaiting.append(marker)
                    }
                }
                await receipts?(marker)
            }
        }
        return outcome
    }

    /// §7.1's discard receipt, in the record shape version 17 gives it: the
    /// vault, the `wireID` and the revision, and **no label**.
    public nonisolated static func discardReceipt(
        _ marker: VaultFoldMarker,
        neverOpened: Bool,
        at now: Date = Date()
    ) -> DurableReceipt {
        DurableReceipt(
            eventID: UUID(),
            correlationID: UUID(),
            at: now,
            projectID: nil,
            environmentID: nil,
            bindingID: nil,
            operation: neverOpened
                ? (marker.blocksVault ? "vault.sync.fold_failed" : "vault.sync.record_waiting")
                : "vault.sync.revision_discarded",
            requestDigest: CanonicalDigest.hex([
                "vaultage.vault.discard.v1", "3",
                marker.vaultID.uuidString.lowercased(), marker.wireID, "\(marker.revision)"
            ]),
            decision: .denied,
            result: neverOpened
                ? "a change relayed for this vault could not be read, so it was not applied"
                : "an arriving revision did not open and was discarded; the previous revision still serves",
            vaultID: marker.vaultID,
            recordWireID: marker.wireID,
            recordRevision: marker.revision
        )
    }

    /// **One receipt per substitution** (sixteenth pass, DB16-M3), so BL-100's
    /// assertion (b) and A-1's *"says so once per substitution"* hold for a
    /// record that has never opened as well as for one that has.
    public nonisolated static func substitutionReceipt(
        _ marker: VaultFoldMarker,
        at now: Date = Date()
    ) -> DurableReceipt {
        DurableReceipt(
            eventID: UUID(),
            correlationID: UUID(),
            at: now,
            projectID: nil,
            environmentID: nil,
            bindingID: nil,
            operation: "vault.sync.revision_substituted",
            requestDigest: CanonicalDigest.hex([
                "vaultage.vault.substitution.v1", "3",
                marker.vaultID.uuidString.lowercased(), marker.wireID, "\(marker.revision)"
            ]),
            decision: .denied,
            result: "a replacement copy of a record this Mac could not read was relayed and retained",
            vaultID: marker.vaultID,
            recordWireID: marker.wireID,
            recordRevision: marker.revision
        )
    }

    /// The head-refusal receipt, same shape, with the head digest in the
    /// `wireID` position because a refused head names no single record.
    public nonisolated static func headRefusalReceipt(
        _ marker: VaultHeadRefusalMarker,
        at now: Date = Date()
    ) -> DurableReceipt {
        DurableReceipt(
            eventID: UUID(),
            correlationID: UUID(),
            at: now,
            projectID: nil,
            environmentID: nil,
            bindingID: nil,
            operation: "vault.sync.head_refused",
            requestDigest: CanonicalDigest.hex([
                "vaultage.vault.headrefusal.v1", "4",
                marker.vaultID.uuidString.lowercased(), marker.headDigest,
                marker.servedDigests.last ?? "", marker.refusalReason.rawValue
            ]),
            decision: .denied,
            result: "an update relayed for this vault was refused whole and none of it was stored",
            vaultID: marker.vaultID,
            recordWireID: marker.headDigest,
            recordRevision: nil
        )
    }
}
