import Foundation

// BL-100 slice A — **the broker's sync flow**: §7.1's three stages driven end to
// end over BL-102's routes, under the twelve XPC selectors that already exist.
//
// `VaultSyncTransport` carries bytes and `VaultSyncApply` decides what to do
// with them. Neither knows when to run. This is the thing that does: **one call,
// transfer → apply → acknowledge**, with §3.3's freeze fence and §10's refusal
// markers consulted on the way in and moved on the way out.
//
// **It composes the selectors rather than reaching past them.** `vaultStage` and
// `vaultApplyHead` are §3.2's rows and they are what the app drives over XPC; a
// flow that called `VaultSyncApply` directly would be a second path into the
// store with a different set of guards in front of it. So what is new here is
// the ordering and the network, and nothing else.

/// What one sync run was asked to do.
public struct VaultSyncRequest: Sendable, Equatable {
    public let vaultID: UUID
    /// The wall clock the applied head is stamped with, which is what §3.3's
    /// retention window is measured against. It decides no admission — head
    /// admission takes no clock at all.
    public let wallNow: Int
    /// **The `(wireID, revision)` pairs this device's own resolution gives it**,
    /// when it has one.
    ///
    /// A device with a resolved membership asks for exactly the records it needs
    /// through `POST …/records/by-wire-id`, and the answer's `missing` is the
    /// named cause DB17-H2 exists to give it — *this relay does not hold the
    /// record your head names*, which becomes a head refusal with a marker, a
    /// receipt and an unmoved watermark rather than a stall. A device that has
    /// no resolution — a kit restore with an empty store (§6.2a), a freshly
    /// paired device with a head floor and nothing else (§5.1) — pages the live
    /// set instead, because it cannot ask for a `wireID` it has never seen, and
    /// the listing is where its pairs come from.
    ///
    /// **Slice A's own flow passes `nil`**: resolving a `wireID` needs the
    /// membership inside the opened `vault` record, and the projection is a seam
    /// BL-106 fills. The named route is built, contracted, recorded and driven;
    /// what is not yet here is the resolution that feeds it, and that is said
    /// rather than implied.
    public let namedPairs: [VaultApplyHeadRequest.Pair]?

    public init(vaultID: UUID, wallNow: Int, namedPairs: [VaultApplyHeadRequest.Pair]? = nil) {
        self.vaultID = vaultID
        self.wallNow = wallNow
        self.namedPairs = namedPairs
    }
}

/// What one sync run did. **Counts, coordinates and a reason — never a record,
/// never a body, never a label.**
public struct VaultSyncRunOutcome: Sendable, Equatable {
    public enum Result: String, Sendable, Equatable {
        /// The relay's head is the one this device has already applied.
        case alreadyCurrent
        /// The vault has no head on the relay yet.
        case noHeadYet
        /// A head was transferred and applied.
        case applied
        /// The head was refused whole, with a marker, a receipt and an unmoved
        /// watermark.
        case refused
        /// A page sequence is still running; the fence is held rather than
        /// spoken through.
        case staging
        /// This head has already spent what §10's budget allows it.
        case alreadySpent
    }

    public let vaultID: UUID
    public let result: Result
    public let headDigest: String?
    public let pagesFetched: Int
    public let recordsStaged: Int
    public let recordsApplied: Int
    public let acknowledged: Bool
    /// The marker's own one-line reason, which names no label and no record.
    public let refusalReason: String?
    public let watermark: VaultWatermarkProjection
    public let fenceStage: String
    /// The receipts the run owes, drained from apply so the caller writes them.
    public let receipts: [VaultHeadRefusalMarker]
}

/// The network half of a broker that syncs. **`nil` on a Mac that does not** —
/// which is every existing test and every build with vault sync off — and
/// `syncVault` refuses rather than pretending, the same fail-closed rule the
/// twelve selectors apply.
public struct VaultSyncComposition: Sendable {
    public let transport: any VaultSyncTransport
    /// §3.3 change 3's acknowledgement is **`sig`-signed and costs no
    /// presence**: `Curve25519.Signing`, software, no ACL. It is a separate
    /// signer from the head's because on a phone they are different keys, and a
    /// composition that conflated them would make the phone's half unbuildable.
    public let acknowledgementSigner: any VaultHeadSigning
    public let deviceID: String

    public init(transport: any VaultSyncTransport, acknowledgementSigner: any VaultHeadSigning, deviceID: String) {
        self.transport = transport
        self.acknowledgementSigner = acknowledgementSigner
        self.deviceID = deviceID
    }
}

public extension VaultageBroker {
    /// Installs the network half. Separate from `installVaultCustody` for the
    /// reason that call is separate from `init`: a Mac acquires a relay session
    /// when it links an account, not when the process starts, and a broker with
    /// custody and no transport is a real state — an offline-by-design Mac.
    func installVaultSync(_ sync: VaultSyncComposition) {
        vaultSync = sync
    }

    /// **One run: transfer → apply → acknowledge.**
    ///
    /// The order below is the whole of it, and each step exists to make the next
    /// one safe:
    ///
    ///  1. **`GET …/head`.** A `200` is the *successful head exchange* §3.3's
    ///     fence is zeroed by, and it is zeroed **whatever the answer says** —
    ///     including `head: null`, which is why that route answers `200` and not
    ///     `404`. A vault that is talking to its relay is not a vault whose
    ///     owner should be told it has stopped.
    ///  2. **The refusal markers, before the fetch.** §10's budget is bytes and
    ///     attempts per head digest, and the digest is the only key a device
    ///     holds *before* it fetches — so a head that has spent its budget costs
    ///     no transfer at all.
    ///  3. **The chain, walked forward from the watermark.** Every intermediate
    ///     head is verified and retained; none of them carries records, and none
    ///     needs to. The head's digest is over the **whole live set**, not over a
    ///     delta, so the current head names everything the intermediate ones did
    ///     — which is exactly why §3.3 made it a whole-set digest.
    ///  4. **The records, in pages, into `vaultStage`.** Bound 1 is per transfer,
    ///     so a head naming more than one page is fetched in pages and applied
    ///     whole; each page is handed to the XPC selector with its index, and
    ///     apply opens its transaction only when every named record is staged.
    ///  5. **`vaultApplyHead`**, which advances the watermark, clears the vault's
    ///     refusals and prunes the markers to the retained heads.
    ///  6. **`PUT …/acks`**, at apply, signed by `sig`, costing no presence.
    ///
    /// Nothing here opens a key, raises a prompt or reads a plaintext byte: the
    /// whole run is §7.1's first two stages, and the third is flow 7's.
    func syncVault(_ request: VaultSyncRequest) async throws -> VaultSyncRunOutcome {
        let custody = try requireVaultCustody()
        let sync = try requireVaultSync()
        let vaultID = request.vaultID
        let subject = await custody.accountSubject

        // 1. The head exchange, and the fence it zeroes.
        let facts = try await sync.transport.fetchHead(vaultID: vaultID)
        _ = try? await custody.fence.recordSuccessfulHeadExchange(vaultID)
        guard let servedHead = facts.head else {
            return try await outcome(custody, vaultID: vaultID, result: .noHeadYet, headDigest: nil)
        }
        let signed = try servedHead.signedHead(accountSubject: subject, vaultID: vaultID)
        let digest = signed.head.chainDigest(accountSubject: subject)
        let watermark = await custody.heads.chain(vaultID).watermark
        if watermark?.headDigest == digest {
            return try await outcome(custody, vaultID: vaultID, result: .alreadyCurrent, headDigest: digest)
        }

        // 2. What this head has already spent, read before a byte is fetched.
        if let marker = await custody.headRefusals.marker(vaultID: vaultID, headDigest: digest),
           !marker.isInProgress, marker.answersFor(servedDigest: "") {
            return try await outcome(
                custody, vaultID: vaultID, result: .alreadySpent, headDigest: digest, refusalReason: marker.reason
            )
        }

        // 3. The chain from the watermark to it, verified link by link and
        //    retained. A gap is the relay being short of what §3.3 requires it
        //    to hold, and it is reported rather than walked around.
        try await catchUp(custody, sync: sync, vaultID: vaultID, subject: subject, target: signed, wallNow: request.wallNow)

        // 4. The records the head names, in pages, through the staging selector.
        var pages = 0
        var staged = 0
        var namedPairs: [(wireID: String, revision: Int)] = []
        var missing: [String] = []
        do {
            if let known = request.namedPairs, !known.isEmpty {
                namedPairs = known.map { (wireID: $0.wireID, revision: $0.revision) }
                (pages, staged, missing) = try await stageNamed(
                    custody, sync: sync, request: request, head: signed, digest: digest,
                    generation: servedHead.keyGeneration, namedPairs: namedPairs
                )
            } else {
                (pages, staged, namedPairs) = try await stagePaged(
                    custody, sync: sync, request: request, head: signed, digest: digest,
                    generation: servedHead.keyGeneration
                )
            }
        } catch let refusal as VaultTransferRefusal {
            return try await outcome(
                custody, vaultID: vaultID, result: .refused, headDigest: digest,
                pagesFetched: pages, recordsStaged: staged, refusalReason: refusal.markerReason,
                receipts: await custody.apply.drainReceiptsOwed()
            )
        }
        // **`missing` is a cause and `deferred` is a page boundary**, and the
        // difference is what decides whether this run waits or refuses. A
        // sequence that is merely incomplete holds the fence and comes back; a
        // sequence the relay has told us it cannot complete goes to apply, which
        // is where `namedAndNotServed` gets its marker, its receipt, its notice
        // and its unmoved watermark (DB17-H2).
        if missing.isEmpty, await !custody.apply.isReadyToApply(head: signed, namedPairs: namedPairs) {
            return try await outcome(
                custody, vaultID: vaultID, result: .staging, headDigest: digest,
                pagesFetched: pages, recordsStaged: staged
            )
        }

        // 5. Apply, through the selector.
        let applied: VaultTransferOutcomeProjection
        do {
            applied = try await vaultApplyHead(VaultApplyHeadRequest(
                vaultID: vaultID, head: signed,
                namedPairs: namedPairs.map { .init(wireID: $0.wireID, revision: $0.revision) },
                page: nil, wallNow: request.wallNow
            ))
        } catch let refusal as VaultTransferRefusal {
            return try await outcome(
                custody, vaultID: vaultID, result: .refused, headDigest: digest,
                pagesFetched: pages, recordsStaged: staged, refusalReason: refusal.markerReason,
                receipts: await custody.apply.drainReceiptsOwed()
            )
        }

        // 6. The acknowledgement, **at apply**, signed by `sig`, costing no
        //    presence. It is best effort: a relay that refuses it has not
        //    unapplied anything, and a device that could not say where it is is
        //    not a device that has failed to sync.
        let acknowledged = await acknowledge(sync: sync, subject: subject, vaultID: vaultID, head: signed, digest: digest)
        return try await outcome(
            custody, vaultID: vaultID, result: .applied, headDigest: digest,
            pagesFetched: pages, recordsStaged: staged, recordsApplied: applied.applied,
            acknowledged: acknowledged, receipts: await custody.apply.drainReceiptsOwed()
        )
    }

    // MARK: - The chain

    /// Every head between this device's watermark and the one it is about to
    /// apply, verified and retained.
    ///
    /// **None of them carries records and none needs to.** The head's `digest`
    /// is over the whole live set, so the target head names everything the
    /// intermediate ones named; retaining them is what §3.3's thirty days of
    /// verified chain means, and skipping them would make the target's
    /// `previousHeadDigest` a chain break against a watermark that never moved.
    private func catchUp(
        _ custody: VaultCustodyComposition,
        sync: VaultSyncComposition,
        vaultID: UUID,
        subject: String,
        target: SignedVaultHead,
        wallNow: Int
    ) async throws {
        // **A device with no watermark walks nothing.** §5.1 gives a freshly
        // paired device its floor out of band and §6.2a leaves a restored one
        // with an empty store, and head admission admits any head against a nil
        // watermark for exactly that reason. Walking the chain for it would
        // advance the watermark through heads whose records it never stored,
        // which is the one thing the watermark is not allowed to claim.
        let chain = await custody.heads.chain(vaultID)
        guard let held = chain.watermark else { return }
        let targetDigest = target.head.chainDigest(accountSubject: subject)
        guard held.headDigest != target.head.previousHeadDigest else { return }
        let page = try await sync.transport.walkHeads(vaultID: vaultID, from: held.headDigest)
        for served in page.heads {
            let candidate = try served.signedHead(accountSubject: subject, vaultID: vaultID)
            guard candidate.head.chainDigest(accountSubject: subject) != targetDigest else { break }
            let watermark = await custody.heads.chain(vaultID).watermark
            try VaultHeadAdmission.admit(candidate, accountSubject: subject, watermark: watermark, verifier: await custody.headVerifier())
            _ = try await custody.heads.accept(candidate, accountSubject: subject, wallNow: wallNow)
        }
    }

    // MARK: - Staging

    /// The kit-restore and fresh-pairing path: page the live set, because a
    /// device that has never opened this vault cannot ask for a `wireID` it has
    /// never seen (§6.2a, §5.1).
    private func stagePaged(
        _ custody: VaultCustodyComposition,
        sync: VaultSyncComposition,
        request: VaultSyncRequest,
        head: SignedVaultHead,
        digest: String,
        generation: Int
    ) async throws -> (Int, Int, [(wireID: String, revision: Int)]) {
        var pages = 0
        var pairs: [(wireID: String, revision: Int)] = []
        var after: String?
        repeat {
            let page = try await sync.transport.pageRecords(vaultID: request.vaultID, generation: generation, after: after)
            pairs.append(contentsOf: page.records.map { (wireID: $0.wireId, revision: $0.revision) })
            _ = try await vaultStage(VaultApplyHeadRequest(
                vaultID: request.vaultID, head: head,
                namedPairs: pairs.map { .init(wireID: $0.wireID, revision: $0.revision) },
                page: .init(headDigest: digest, index: pages, records: try page.records.map { try $0.sealedRecord() }),
                wallNow: request.wallNow
            ))
            pages += 1
            after = page.nextAfter
            if page.complete || page.records.isEmpty { break }
        } while pages < VaultRecordBudget.maximumPagesPerHead
        return (pages, await custody.apply.stagedCount(head: head), pairs)
    }

    /// The incremental path: ask for exactly the names this device holds, and
    /// **let `missing` be the cause**. A record the head names that the relay
    /// does not hold is `namedAndNotServed` at apply, with a marker, a receipt,
    /// a notice and an unmoved watermark — never a silent stall.
    private func stageNamed(
        _ custody: VaultCustodyComposition,
        sync: VaultSyncComposition,
        request: VaultSyncRequest,
        head: SignedVaultHead,
        digest: String,
        generation: Int,
        namedPairs: [(wireID: String, revision: Int)]
    ) async throws -> (Int, Int, [String]) {
        var pages = 0
        var missing: [String] = []
        var wanted = namedPairs.map(\.wireID)
        while !wanted.isEmpty, pages < VaultRecordBudget.maximumPagesPerHead {
            let answer = try await sync.transport.fetchRecords(
                vaultID: request.vaultID, generation: generation,
                wireIDs: Array(wanted.prefix(VaultSyncBounds.maximumRecordsPerTransfer))
            )
            _ = try await vaultStage(VaultApplyHeadRequest(
                vaultID: request.vaultID, head: head,
                namedPairs: namedPairs.map { .init(wireID: $0.wireID, revision: $0.revision) },
                page: .init(headDigest: digest, index: pages, records: try answer.records.map { try $0.sealedRecord() }),
                wallNow: request.wallNow
            ))
            pages += 1
            // **The three facts, kept apart.** `deferred` is *the page ended* and
            // is asked for again; `missing` is *the relay does not hold it* and
            // is not — asking again for a record a relay has said it lacks is
            // the retry loop with a worse name.
            missing.append(contentsOf: answer.missing)
            wanted = answer.deferred
            if answer.records.isEmpty, answer.deferred.isEmpty { break }
        }
        return (pages, await custody.apply.stagedCount(head: head), missing)
    }

    // MARK: - The acknowledgement

    private func acknowledge(
        sync: VaultSyncComposition,
        subject: String,
        vaultID: UUID,
        head: SignedVaultHead,
        digest: String
    ) async -> Bool {
        let ack = VaultHeadAck(
            deviceId: sync.deviceID,
            ackedKeyGeneration: head.head.keyGeneration,
            ackedHeadSeq: head.head.headSeq,
            ackedHeadDigest: digest,
            ackedAt: head.head.writtenAt
        )
        guard let signature = try? sync.acknowledgementSigner.sign(ack.preimage(accountSubject: subject, vaultID: vaultID)) else {
            return false
        }
        do {
            try await sync.transport.putAck(vaultID: vaultID, ack: ack, signature: signature)
            return true
        } catch {
            // Best effort by design. §3.3 states the trade: an acknowledgement
            // authorizes nothing, and a device that could not say where it is has
            // still verified and stored what it verified and stored.
            return false
        }
    }

    // MARK: - Fail closed, and the outcome

    private func requireVaultCustody() throws -> VaultCustodyComposition {
        guard let custody = vaultCustody else {
            throw VaultageError.unsupported("Vault sync is not enabled on this Mac.")
        }
        return custody
    }

    private func requireVaultSync() throws -> VaultSyncComposition {
        guard let sync = vaultSync else {
            throw VaultageError.unsupported("This Mac has no relay session for vault sync.")
        }
        return sync
    }

    private func outcome(
        _ custody: VaultCustodyComposition,
        vaultID: UUID,
        result: VaultSyncRunOutcome.Result,
        headDigest: String?,
        pagesFetched: Int = 0,
        recordsStaged: Int = 0,
        recordsApplied: Int = 0,
        acknowledged: Bool = false,
        refusalReason: String? = nil,
        receipts: [VaultHeadRefusalMarker] = []
    ) async throws -> VaultSyncRunOutcome {
        let fence = try await vaultFenceState(vaultID)
        return VaultSyncRunOutcome(
            vaultID: vaultID,
            result: result,
            headDigest: headDigest,
            pagesFetched: pagesFetched,
            recordsStaged: recordsStaged,
            recordsApplied: recordsApplied,
            acknowledged: acknowledged,
            refusalReason: refusalReason,
            watermark: try await vaultWatermark(vaultID),
            fenceStage: fence.stage,
            receipts: receipts
        )
    }
}
