import CryptoKit
import Foundation

// BL-100 slice A — **the twelve XPC selectors, wired into the broker's own
// composition** (`13-MULTI-DEVICE-CUSTODY.md` §3.2's slice-A rows).
//
// The first pass built what each of them needs in `VaultageCore` and left them
// replying `failed` with a sentence naming why, because an unwired surface that
// says so is honest and an unwired surface that pretends is not. This is the
// step that reaches them.
//
// **What crosses is what §3.2's table says crosses, and nothing else.** No
// sealed record, no wrap row, no ciphertext, no Keychain account, no local
// path, and no enumeration of any of them. Every reply below is a value-free
// projection of counts, labels and identifiers the app is already permitted to
// hold — which is the bound, because a container plus an RPC hop is an
// indirection and what bounds "read the sealed store from disk" is what this
// interface returns and what it accepts.

/// `watermark`'s reply: `(keyGeneration, headSeq, headDigest)`, value-free.
public struct VaultWatermarkProjection: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let keyGeneration: Int?
    public let headSeq: Int?
    public let headDigest: String?

    public init(vaultID: UUID, keyGeneration: Int?, headSeq: Int?, headDigest: String?) {
        self.vaultID = vaultID
        self.keyGeneration = keyGeneration
        self.headSeq = headSeq
        self.headDigest = headDigest
    }
}

/// `liveness`'s reply — §3.3's C-2 screen, *"your iPhone last saw this Mac 3
/// days ago"*. The `acks` vector, value-free.
public struct VaultLivenessProjection: Codable, Sendable, Equatable {
    public struct Device: Codable, Sendable, Equatable {
        public let deviceID: String
        public let headSeq: Int
        public init(deviceID: String, headSeq: Int) {
            self.deviceID = deviceID
            self.headSeq = headSeq
        }
    }

    public let vaultID: UUID
    public let devices: [Device]
    public init(vaultID: UUID, devices: [Device]) {
        self.vaultID = vaultID
        self.devices = devices
    }
}

/// `fenceState`'s reply: §3.3's accumulator, from broker-owned state the app
/// cannot write. **The stage carries the refused-head hold**, so the surface
/// renders §7.1's notice rather than a message about time (seventeenth pass,
/// DB17-M3).
public struct VaultFenceProjection: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let stage: String
    public let elapsedSeconds: TimeInterval
    public let unsentChanges: Int
    public let offlineByDesign: Bool
    public let refusalNotice: String?

    public init(
        vaultID: UUID,
        stage: String,
        elapsedSeconds: TimeInterval,
        unsentChanges: Int,
        offlineByDesign: Bool,
        refusalNotice: String?
    ) {
        self.vaultID = vaultID
        self.stage = stage
        self.elapsedSeconds = elapsedSeconds
        self.unsentChanges = unsentChanges
        self.offlineByDesign = offlineByDesign
        self.refusalNotice = refusalNotice
    }
}

/// `renderList`'s reply. **`item`, `folder` and `vault` projections only** —
/// labels, the folder tree, item types, revisions, counts, attachment names and
/// sizes, plus the count of applied records not yet folded in and the count of
/// records waiting for a readable copy. No `value` record, no wrap row, no
/// ciphertext.
public struct VaultSurfaceProjection: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let state: String
    public let notice: String?
    public let waitingNotice: String?
    public let appliedNotYetFolded: Int
    public let recordsWaiting: Int
    public let items: [Item]
    public let folders: [Folder]

    public struct Item: Codable, Sendable, Equatable {
        public let itemID: UUID
        public let label: String
        public let type: String
        public let folderID: UUID?
        public let revision: Int
        public let attachmentNames: [String]
        public let attachmentBytes: [Int]
    }

    public struct Folder: Codable, Sendable, Equatable {
        public let folderID: UUID
        public let parentID: UUID?
        public let name: String
        public let sortOrder: Int
    }

    public init(
        vaultID: UUID,
        state: String,
        notice: String?,
        waitingNotice: String?,
        appliedNotYetFolded: Int,
        recordsWaiting: Int,
        items: [Item],
        folders: [Folder]
    ) {
        self.vaultID = vaultID
        self.state = state
        self.notice = notice
        self.waitingNotice = waitingNotice
        self.appliedNotYetFolded = appliedNotYetFolded
        self.recordsWaiting = recordsWaiting
        self.items = items
        self.folders = folders
    }
}

/// What `applyHead` and `stage` report. **No read-back**: a count and a
/// watermark, never the records.
public struct VaultTransferOutcomeProjection: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let staged: Int
    public let named: Int
    public let readyToApply: Bool
    public let applied: Int
    public let unnamedDiscarded: Int
    public let watermark: VaultWatermarkProjection

    public init(
        vaultID: UUID,
        staged: Int,
        named: Int,
        readyToApply: Bool,
        applied: Int,
        unnamedDiscarded: Int,
        watermark: VaultWatermarkProjection
    ) {
        self.vaultID = vaultID
        self.staged = staged
        self.named = named
        self.readyToApply = readyToApply
        self.applied = applied
        self.unnamedDiscarded = unnamedDiscarded
        self.watermark = watermark
    }
}

/// `enqueueLocalDeletion`, `restoreLocalDeletion` and
/// `restoreAllLocalDeletions` report the queue's own count. §7.3 part A: no
/// presence to enqueue, because nothing is destroyed and nothing leaves the
/// device.
public struct VaultDeletionQueueCountProjection: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let queued: Int
    public let restored: Int
    public init(vaultID: UUID, queued: Int, restored: Int) {
        self.vaultID = vaultID
        self.queued = queued
        self.restored = restored
    }
}

/// `listLocalDeletions`'s reply: **value-free projections** of the suppressed
/// records — the same fields `renderList` returns, filtered to the queue, plus
/// `queuedAt`.
public struct VaultDeletionQueueProjectionList: Codable, Sendable, Equatable {
    public struct Row: Codable, Sendable, Equatable {
        public let wireID: String
        public let label: String
        public let type: String
        public let folderID: UUID?
        public let queuedAtMonotonic: TimeInterval
    }

    public let vaultID: UUID
    public let rows: [Row]
    public init(vaultID: UUID, rows: [Row]) {
        self.vaultID = vaultID
        self.rows = rows
    }
}

/// The request shapes. **Every one is identifiers, counts and already-sealed
/// ciphertext the app fetched and never decrypted** — the app hands over what
/// the relay served and receives a count back.
public struct VaultApplyHeadRequest: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let head: SignedVaultHead
    public let namedPairs: [Pair]
    public let page: Page?
    public let wallNow: Int

    public struct Pair: Codable, Sendable, Equatable {
        public let wireID: String
        public let revision: Int
        public init(wireID: String, revision: Int) {
            self.wireID = wireID
            self.revision = revision
        }
    }

    public struct Page: Codable, Sendable, Equatable {
        public let headDigest: String
        public let index: Int
        public let records: [VaultSealedRecord]
        public init(headDigest: String, index: Int, records: [VaultSealedRecord]) {
            self.headDigest = headDigest
            self.index = index
            self.records = records
        }
    }

    public init(vaultID: UUID, head: SignedVaultHead, namedPairs: [Pair], page: Page?, wallNow: Int) {
        self.vaultID = vaultID
        self.head = head
        self.namedPairs = namedPairs
        self.page = page
        self.wallNow = wallNow
    }
}

public struct VaultWriteMetadataRequest: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let displayName: String?
    public let subjectKind: String
    public let subjectID: String
    public let revision: Int
    public let keyGeneration: Int
    public let plaintext: Data

    public init(
        vaultID: UUID, displayName: String?, subjectKind: String, subjectID: String,
        revision: Int, keyGeneration: Int, plaintext: Data
    ) {
        self.vaultID = vaultID
        self.displayName = displayName
        self.subjectKind = subjectKind
        self.subjectID = subjectID
        self.revision = revision
        self.keyGeneration = keyGeneration
        self.plaintext = plaintext
    }
}

public struct VaultEnqueueDeletionRequest: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let wireID: String
    public let subjectKind: String
    public let subjectID: String
    public let revision: Int
    public let lamport: Int

    public init(vaultID: UUID, wireID: String, subjectKind: String, subjectID: String, revision: Int, lamport: Int) {
        self.vaultID = vaultID
        self.wireID = wireID
        self.subjectKind = subjectKind
        self.subjectID = subjectID
        self.revision = revision
        self.lamport = lamport
    }
}

public struct VaultRestoreDeletionRequest: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let wireID: String
    public init(vaultID: UUID, wireID: String) {
        self.vaultID = vaultID
        self.wireID = wireID
    }
}

/// **The broker's custody composition.** It is `nil` on a broker that was not
/// given one — which is every existing test and every build with vault sync
/// off — and a composition without one refuses every selector below rather than
/// pretending it worked, the same fail-closed rule the mirroring methods and
/// the grant methods already apply.
public actor VaultCustodyComposition {
    public let accountSubject: String
    public let container: BrokerContainer
    public let store: VaultCipherStore
    public let heads: VaultHeadChainStore
    public let foldFailures: VaultFoldFailureStore
    public let headRefusals: VaultHeadRefusalStore
    public let apply: VaultSyncApply
    public let queue: VaultDeletionQueue
    public let plane: VaultMetadataPlane
    public let fence: VaultFenceAccumulator
    private let verifier: any VaultHeadVerifying
    /// `VIK_v`, which the broker holds and the app never sees. It is here
    /// because `writeMetadata` computes the record's `wireID` and nothing on the
    /// other side of the boundary may.
    private let identity: SymmetricKey

    public init(
        accountSubject: String,
        container: BrokerContainer,
        plane: VaultMetadataPlane,
        verifier: any VaultHeadVerifying,
        identityKey: SymmetricKey,
        presence: any PresenceEvaluating,
        monotonic: any MonotonicClock = SystemMonotonicClock()
    ) {
        identity = identityKey
        self.accountSubject = accountSubject
        self.container = container
        store = VaultCipherStore(container: container)
        heads = VaultHeadChainStore(container: container, monotonic: monotonic)
        foldFailures = VaultFoldFailureStore(container: container)
        headRefusals = VaultHeadRefusalStore(container: container)
        apply = VaultSyncApply(
            accountSubject: accountSubject,
            store: VaultCipherStore(container: container),
            heads: VaultHeadChainStore(container: container, monotonic: monotonic),
            foldFailures: VaultFoldFailureStore(container: container),
            headRefusals: VaultHeadRefusalStore(container: container),
            monotonic: monotonic
        )
        queue = VaultDeletionQueue(container: container, presence: presence, monotonic: monotonic)
        self.plane = plane
        fence = VaultFenceAccumulator(container: container, monotonic: monotonic)
        self.verifier = verifier
    }

    func headVerifier() -> any VaultHeadVerifying { verifier }
    func identityKey() -> SymmetricKey { identity }
}

public extension VaultageBroker {
    /// §7.1 stage 1 — transfer's staging path. **Ciphertext in, no read-back.**
    func vaultStage(_ request: VaultApplyHeadRequest) async throws -> VaultTransferOutcomeProjection {
        let custody = try requireCustody()
        let pairs = request.namedPairs.map { (wireID: $0.wireID, revision: $0.revision) }
        let page = request.page.map {
            VaultTransferPage(headDigest: $0.headDigest, index: $0.index, records: $0.records)
        } ?? VaultTransferPage(headDigest: "", index: 0, records: [])
        let watermark = await custody.heads.chain(request.vaultID).watermark
        _ = try await custody.apply.transfer(
            head: request.head, page: page, namedPairs: pairs,
            verifier: await custody.headVerifier(), watermark: watermark
        )
        return await outcome(custody, request: request, applied: 0)
    }

    /// §7.1 stage 2 — apply. **No key, no presence, runs locked.**
    func vaultApplyHead(_ request: VaultApplyHeadRequest) async throws -> VaultTransferOutcomeProjection {
        let custody = try requireCustody()
        let pairs = request.namedPairs.map { (wireID: $0.wireID, revision: $0.revision) }
        _ = try await custody.apply.apply(
            head: request.head, served: [], namedPairs: pairs, wallNow: request.wallNow
        )
        _ = try? await custody.fence.recordSuccessfulHeadExchange(request.vaultID)
        return await outcome(custody, request: request, applied: pairs.count)
    }

    func vaultWatermark(_ vaultID: UUID) async throws -> VaultWatermarkProjection {
        let custody = try requireCustody()
        return await watermarkProjection(custody, vaultID: vaultID)
    }

    func vaultLiveness(_ vaultID: UUID) async throws -> VaultLivenessProjection {
        let custody = try requireCustody()
        let chain = await custody.heads.chain(vaultID)
        let acks: [VaultHeadAck] = chain.heads.last?.signed.head.acks ?? []
        let devices = acks.map {
            VaultLivenessProjection.Device(deviceID: $0.deviceId, headSeq: $0.ackedHeadSeq)
        }
        return VaultLivenessProjection(vaultID: vaultID, devices: devices)
    }

    func vaultFenceState(_ vaultID: UUID) async throws -> VaultFenceProjection {
        let custody = try requireCustody()
        let stage = try await custody.fence.stage(vaultID)
        let state = await custody.fence.state(vaultID)
        // **The refused-head notice travels with the stage**, so the surface
        // renders §7.1's string for a refusal rather than the fence's message
        // about time (seventeenth pass, DB17-M3).
        var notice: String?
        let subject = await custody.accountSubject
        if stage == .heldByRefusedHead, let marker = await custody.headRefusals.refusal(vaultID) {
            notice = VaultRefusalNotice.headRefused(
                vaultDisplayName: VaultDisplayName.resolve(
                    lastOpenedName: nil, vaultID: vaultID, accountSubject: subject
                ),
                reason: marker.refusalReason
            )
        }
        return VaultFenceProjection(
            vaultID: vaultID,
            stage: stage.rawValue,
            elapsedSeconds: state.persistedElapsed,
            unsentChanges: state.unsentChanges,
            offlineByDesign: state.offlineByDesign,
            refusalNotice: notice
        )
    }

    func vaultRenderList(_ vaultID: UUID, lastOpenedName: VaultLastOpenedName?) async throws -> VaultSurfaceProjection {
        let custody = try requireCustody()
        let surface = try await custody.plane.renderList(vaultID: vaultID, lastOpenedName: lastOpenedName)
        let live = await custody.store.liveRecordCount(vaultID: vaultID)
        let waitingNotice = await custody.plane.recordsWaitingNotice(vaultID: vaultID, liveRecords: live)
        let waiting = await custody.foldFailures.recordsWaitingForAReadableCopy(vaultID)
        let applied = await custody.store.arrivingRecordCount(vaultID: vaultID)
        switch surface {
        case .current(let projection):
            return VaultSurfaceProjection(
                vaultID: vaultID, state: "current", notice: nil, waitingNotice: waitingNotice,
                appliedNotYetFolded: applied, recordsWaiting: waiting,
                items: projection.items.map {
                    .init(itemID: $0.itemID, label: $0.label, type: $0.type, folderID: $0.folderID,
                          revision: $0.revision, attachmentNames: $0.attachmentNames, attachmentBytes: $0.attachmentBytes)
                },
                folders: projection.folders.map {
                    .init(folderID: $0.folderID, parentID: $0.parentID, name: $0.name, sortOrder: $0.sortOrder)
                }
            )
        case .foldFailed(let notice, let previous):
            return VaultSurfaceProjection(
                vaultID: vaultID, state: "foldFailed", notice: notice, waitingNotice: waitingNotice,
                appliedNotYetFolded: applied, recordsWaiting: waiting,
                items: (previous?.items ?? []).map {
                    .init(itemID: $0.itemID, label: $0.label, type: $0.type, folderID: $0.folderID,
                          revision: $0.revision, attachmentNames: $0.attachmentNames, attachmentBytes: $0.attachmentBytes)
                },
                folders: (previous?.folders ?? []).map {
                    .init(folderID: $0.folderID, parentID: $0.parentID, name: $0.name, sortOrder: $0.sortOrder)
                }
            )
        }
    }

    /// §2.4.1's **flow 7**. Presence-gated, one prompt per vault, **no value
    /// returned** — the row exists so the app can ask for the flow at a moment
    /// the owner expects a prompt, not so it can obtain a key.
    func vaultOpenMetadataPlane(_ vaultIDs: [UUID], displayNames: [String]) async throws {
        let custody = try requireCustody()
        try await custody.plane.openMetadataPlane(vaultIDs: vaultIDs, displayNames: displayNames)
    }

    func vaultWriteMetadata(_ request: VaultWriteMetadataRequest) async throws {
        let custody = try requireCustody()
        guard let kind = VaultRecordKind(rawValue: request.subjectKind), kind.isSliceA else {
            throw VaultageError.invalidInput("That is not a record kind this release writes.")
        }
        let subject = await custody.accountSubject
        _ = try await custody.plane.writeMetadata(
            vaultID: request.vaultID,
            displayName: request.displayName ?? VaultDisplayName.resolve(
                lastOpenedName: nil, vaultID: request.vaultID, accountSubject: subject
            ),
            subject: VaultRecordSubject(kind: kind, recordID: request.subjectID),
            plaintext: request.plaintext,
            revision: request.revision,
            keyGeneration: request.keyGeneration,
            identityKey: await custody.identityKey()
        )
    }

    func vaultEnqueueLocalDeletion(_ request: VaultEnqueueDeletionRequest) async throws -> VaultDeletionQueueCountProjection {
        let custody = try requireCustody()
        guard let kind = VaultRecordKind(rawValue: request.subjectKind), kind.isSliceA else {
            throw VaultageError.invalidInput("That is not a record kind this release queues.")
        }
        _ = try await custody.queue.enqueueLocalDeletion(
            vaultID: request.vaultID,
            subject: VaultRecordSubject(kind: kind, recordID: request.subjectID),
            wireID: request.wireID,
            revision: request.revision,
            lamport: request.lamport
        )
        let queued = await custody.queue.count(request.vaultID)
        return VaultDeletionQueueCountProjection(vaultID: request.vaultID, queued: queued, restored: 0)
    }

    func vaultListLocalDeletions(_ vaultID: UUID) async throws -> VaultDeletionQueueProjectionList {
        let custody = try requireCustody()
        // **Resolved from the same projection `renderList` serves**, so a
        // queued row carries the labels the surface already holds and nothing
        // the store holds.
        let surface = try await vaultRenderList(vaultID, lastOpenedName: nil)
        let byItem = Dictionary(
            surface.items.map { ($0.itemID.uuidString.lowercased(), $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let rows = await custody.queue.listLocalDeletions(vaultID: vaultID) { entry in
            guard let item = byItem[entry.recordID] else { return nil }
            return (label: item.label, type: item.type, folderID: item.folderID)
        }.map {
            VaultDeletionQueueProjectionList.Row(
                wireID: $0.wireID, label: $0.label, type: $0.type,
                folderID: $0.folderID, queuedAtMonotonic: $0.queuedAtMonotonic
            )
        }
        return VaultDeletionQueueProjectionList(vaultID: vaultID, rows: rows)
    }

    func vaultRestoreLocalDeletion(_ request: VaultRestoreDeletionRequest) async throws -> VaultDeletionQueueCountProjection {
        let custody = try requireCustody()
        let restored = try await custody.queue.restoreLocalDeletion(vaultID: request.vaultID, wireID: request.wireID)
        let queued = await custody.queue.count(request.vaultID)
        return VaultDeletionQueueCountProjection(vaultID: request.vaultID, queued: queued, restored: restored)
    }

    func vaultRestoreAllLocalDeletions(_ vaultID: UUID) async throws -> VaultDeletionQueueCountProjection {
        let custody = try requireCustody()
        let restored = try await custody.queue.restoreAllLocalDeletions(vaultID: vaultID)
        let queued = await custody.queue.count(vaultID)
        return VaultDeletionQueueCountProjection(vaultID: vaultID, queued: queued, restored: restored)
    }

    // MARK: - Fail closed

    private func requireCustody() throws -> VaultCustodyComposition {
        guard let custody = vaultCustody else {
            throw VaultageError.unsupported("Vault sync is not enabled on this Mac.")
        }
        return custody
    }

    private func watermarkProjection(_ custody: VaultCustodyComposition, vaultID: UUID) async -> VaultWatermarkProjection {
        let watermark = await custody.heads.chain(vaultID).watermark
        return VaultWatermarkProjection(
            vaultID: vaultID,
            keyGeneration: watermark?.keyGeneration,
            headSeq: watermark?.headSeq,
            headDigest: watermark?.headDigest
        )
    }

    private func outcome(
        _ custody: VaultCustodyComposition,
        request: VaultApplyHeadRequest,
        applied: Int
    ) async -> VaultTransferOutcomeProjection {
        let pairs = request.namedPairs.map { (wireID: $0.wireID, revision: $0.revision) }
        return VaultTransferOutcomeProjection(
            vaultID: request.vaultID,
            staged: await custody.apply.stagedCount(head: request.head),
            named: request.namedPairs.count,
            readyToApply: await custody.apply.isReadyToApply(head: request.head, namedPairs: pairs),
            applied: applied,
            unnamedDiscarded: await custody.apply.unnamedRecordsDiscarded(head: request.head),
            watermark: await watermarkProjection(custody, vaultID: request.vaultID)
        )
    }
}
