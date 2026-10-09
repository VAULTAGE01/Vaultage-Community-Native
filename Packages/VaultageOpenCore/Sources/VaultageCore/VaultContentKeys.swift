import CryptoKit
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// BL-100 slice A — the vault's keys, **flow 7 — the metadata plane** — and the
// projection `renderList` serves (`13-MULTI-DEVICE-CUSTODY.md` version 17
// §2.2, §2.4.1, §3.2, §7.1 stage 3).
//
// **Apply opens no key**, and flow 7 is the vault's whole metadata plane: the
// deterministic merge, `normalize`, the projection build, and the seal of any
// `vault`, `item` or `folder` record this device writes. One flow, one key, one
// prompt.

// MARK: - The keys

/// §2.2's three keys per vault. **Slice A does not create `vkx` and writes no
/// wrap addressed to one** — that is slice B, and `kSecAttrAccessGroup` is fixed
/// at creation, which is the one irreversible act BL-109 prices. What slice A
/// owns is the **shape**: which key covers which records, and which of them
/// `openVaultContentKey` returns.
public enum VaultKeyRole: String, Sendable, CaseIterable {
    /// `VCK_v` — the only key that opens `vault`, `item` and `folder` records.
    case contentKey
    /// `VIK_v` — attachment content addressing, deduplication, and the `wireID`
    /// HMAC. Full re-seal only.
    case identityKey
    /// `IK(i,f,c)` — one per `value` record. **Random and pinned by default**,
    /// so unwrapping one credential is its own Enclave operation.
    case itemKey
    /// `RK_v` — the vault's standing **recovery recipient**, so a kit covers
    /// credentials created after it was printed.
    case recoveryRecipient
}

/// The one path that would create `vkx` or open a wrap addressed to one.
///
/// **Slice A refuses it in terms**, so *"nothing in slice A creates `vkx`"* is
/// enforced rather than described: the seam exists from slice A's first commit,
/// and slice B replaces this implementation rather than threading a key through
/// the machinery afterwards.
public struct SliceBPendingKeyCustody: VaultKeyCustody {
    public init() {}

    public static let refusal = """
        This build cannot open a vault key yet. Creating the device key that opens them \
        fixes which Keychain access group it lives in, and that decision has not been taken.
        """

    public func itemKey(_ subject: ValueSubject, presence: EvaluatedPresence) throws -> VaultSecret {
        throw VaultageError.storage(Self.refusal)
    }

    public func keychainValue(_ subject: KeychainSubject, presence: EvaluatedPresence) throws -> VaultSecret {
        throw VaultageError.storage(Self.refusal)
    }

    public func vaultContentKey(_ subject: VaultSubject, presence: EvaluatedPresence) throws -> VaultSecret {
        throw VaultageError.storage(Self.refusal)
    }
}

#if canImport(LocalAuthentication)
/// The production evaluator. It constructs a context **for this evaluation and
/// for no other**, at reuse duration `0`, and hands it to the machinery, which
/// owns it privately and invalidates it on every exit path.
public struct LocalAuthenticationPresence: PresenceEvaluating {
    public init() {}

    public func evaluate(reason: String) throws -> EvaluatedPresence {
        let context = LAContext()
        // Explicit, not defaulted. An evaluation that is meant to raise its own
        // prompt must not be silently satisfied by an unrelated Touch ID the
        // owner performed seconds ago somewhere else in the app — and reuse `0`
        // on a **shared** instance is not the control, which is why the
        // instance is constructed here and nowhere else.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = reason
        var thrown: Error?
        let gate = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            if !success { thrown = error ?? VaultageError.approvalDenied }
            gate.signal()
        }
        gate.wait()
        if thrown != nil {
            context.invalidate()
            throw BatchPresenceRefusal.presenceDenied
        }
        return EvaluatedPresence(handle: context)
    }
}
#endif

// MARK: - The projection

/// What the rail, the tree, the list and search need — **and nothing else**.
///
/// **No `value` record, no wrap row, no ciphertext.** Splitting `item` from
/// `value` is what lets a phone render a list, a folder tree and a search result
/// **without unwrapping a credential**, and it is the reason §2.4's residual is
/// metadata rather than everything.
public struct VaultListProjection: Sendable, Equatable {
    public struct Item: Sendable, Equatable {
        public let itemID: UUID
        public let label: String
        public let type: String
        public let folderID: UUID?
        public let revision: Int
        public let attachmentNames: [String]
        public let attachmentBytes: [Int]

        public init(itemID: UUID, label: String, type: String, folderID: UUID?, revision: Int, attachmentNames: [String] = [], attachmentBytes: [Int] = []) {
            self.itemID = itemID
            self.label = label
            self.type = type
            self.folderID = folderID
            self.revision = revision
            self.attachmentNames = attachmentNames
            self.attachmentBytes = attachmentBytes
        }
    }

    public struct Folder: Sendable, Equatable {
        public let folderID: UUID
        public let parentID: UUID?
        public let name: String
        public let sortOrder: Int

        public init(folderID: UUID, parentID: UUID?, name: String, sortOrder: Int) {
            self.folderID = folderID
            self.parentID = parentID
            self.name = name
            self.sortOrder = sortOrder
        }
    }

    public let vaultID: UUID
    public let vaultName: String
    public let folders: [Folder]
    public let items: [Item]
    /// **Plus the count of applied records not yet folded in** — the vault says
    /// *"12 changes waiting"* rather than the projection being wrong. A head
    /// that arrives while a projection is live leaves the projection **behind**,
    /// not wrong.
    public let waitingRecords: Int
    /// **And the count of records waiting for a readable copy** (sixteenth
    /// pass, DB16-H3): `item`, `value` and `blob` records this device has never
    /// opened and whose arriving revision did not open. The vault folds and
    /// projects around them. **It is a count and not a list**, because on a kit
    /// restore it is most of the vault.
    public let recordsWaitingForAReadableCopy: Int

    public init(
        vaultID: UUID,
        vaultName: String,
        folders: [Folder],
        items: [Item],
        waitingRecords: Int,
        recordsWaitingForAReadableCopy: Int = 0
    ) {
        self.vaultID = vaultID
        self.vaultName = vaultName
        self.folders = folders
        self.items = items
        self.waitingRecords = waitingRecords
        self.recordsWaitingForAReadableCopy = recordsWaitingForAReadableCopy
    }
}

/// What `renderList` answers with when the vault cannot be folded.
public enum VaultSurfaceState: Sendable, Equatable {
    case current(VaultListProjection)
    /// **The previous projection is left standing while one exists in memory**,
    /// with the notice beside it; after a restart there is none, and the vault
    /// renders in the fold-failed state with the same string.
    case foldFailed(notice: String, previousProjection: VaultListProjection?)
}

// MARK: - Flow 7

/// §2.4.1's **flow 7 — the vault's metadata plane**, and §7.1's stage 3.
///
/// **Its trigger is three parts**, all of them owner-initiated moments, which is
/// the property that matters — the prompt arrives when the owner opened the
/// vault or changed something in it, never mid-scroll and never in the
/// background:
///
/// 1. `renderList` is called and the broker holds **no projection** for that
///    vault — **a restart is the common case**, and version 12's list omitted it;
/// 2. `renderList` is called and **applied records are waiting** to be merged;
/// 3. **this device is writing** a `vault`, `item` or `folder` record.
///
/// **Residency: the projection is memory-only, lives exactly as long as the
/// broker process, and is never written down.** There is no on-disk projection
/// cache, no idle timer and no new duration. **The key is not the projection**:
/// the token is consumed at flow exit and the key bytes go with it, so what the
/// broker retains between flows is *plaintext it has already derived*, never the
/// ability to derive more.
///
/// **What it costs, said plainly:** one prompt per vault per owner-initiated
/// moment, recurring on every metadata write and every fold, with sustained
/// editing re-prompting at the 30-second ceiling. In the shipped product, where
/// metadata is a plaintext JSON file, a rename costs **zero** — so this is a real
/// new cost and the design states it rather than meeting it as a usability
/// complaint.
public actor VaultMetadataPlane {
    private let presence: VaultBatchPresence
    private let store: VaultCipherStore
    private let apply: VaultSyncApply
    private let foldFailures: VaultFoldFailureStore
    private let accountSubject: String

    /// **Memory only.** §10's manifest declares no path for it, and a builder's
    /// on-disk cache is a path in the broker's container that the container walk
    /// fails on — which is a different test from the `VaultageMetadata` one and
    /// is the one that can actually see it.
    private var projections: [UUID: VaultListProjection] = [:]
    private var waiting: [UUID: [(wireID: String, subject: VaultRecordSubject)]] = [:]
    /// Vaults whose fold may be retried, because a new head or revision has
    /// arrived since the last failure. **Memory-only**, like the projection:
    /// after a restart the vault renders in the fold-failed state from the
    /// persisted markers and waits for the next arrival, which is the behaviour
    /// DB16-H2 asks for rather than a prompt.
    private var retryArmed: Set<UUID> = []

    public init(
        accountSubject: String,
        presence: VaultBatchPresence,
        store: VaultCipherStore,
        apply: VaultSyncApply,
        foldFailures: VaultFoldFailureStore
    ) {
        self.accountSubject = accountSubject
        self.presence = presence
        self.store = store
        self.apply = apply
        self.foldFailures = foldFailures
    }

    /// Apply tells the plane what is waiting. This is not a key operation and
    /// raises nothing.
    public func noteApplied(vaultID: UUID, records: [(wireID: String, subject: VaultRecordSubject)]) {
        waiting[vaultID, default: []].append(contentsOf: records)
        // **A new head or a new revision for this vault re-arms the retry**, and
        // nothing else does — which is what keeps a fold-failed vault from
        // prompting on every render.
        if !records.isEmpty { retryArmed.insert(vaultID) }
    }

    public func waitingCount(vaultID: UUID) -> Int { waiting[vaultID]?.count ?? 0 }

    public func hasProjection(vaultID: UUID) -> Bool { projections[vaultID] != nil }

    /// The app may drop the projection explicitly; the broker drops it on exit.
    public func dropProjection(vaultID: UUID) { projections[vaultID] = nil }

    /// **Listing names and structure needs no item key and no evaluation.**
    /// `renderList` serves the projection: **no Enclave operation, no
    /// `LAContext`, no token, nothing to spend and nothing to steal.**
    ///
    /// When there is no projection, or records are waiting, it enters **flow 7**
    /// first — triggers 1 and 2.
    ///
    /// **A fold-failed vault does not satisfy those triggers** (sixteenth pass,
    /// DB16-H2). Version 17's rule made *"no projection for the vault"* true
    /// forever on a vault whose fold cannot succeed, so every render raised a
    /// prompt for a flow that was going to fail — one prompt per render, on the
    /// one surface the owner returns to precisely because it is broken. So the
    /// fold-failed state renders **without a prompt**, and the retry runs only
    /// when a **new head or a new revision arrives for that vault**: one prompt
    /// then.
    public func renderList(vaultID: UUID, lastOpenedName: VaultLastOpenedName?) throws -> VaultSurfaceState {
        let display = VaultDisplayName.resolve(
            lastOpenedName: lastOpenedName, vaultID: vaultID, accountSubject: accountSubject
        )
        let blocked = foldFailures.isFoldedSynchronously(vaultID)
        let armed = retryArmed.contains(vaultID)
        if blocked && !armed {
            return .foldFailed(notice: VaultFoldFailureNotice.text(vaultDisplayName: display), previousProjection: projections[vaultID])
        }
        if projections[vaultID] == nil || !(waiting[vaultID] ?? []).isEmpty {
            try enterFlow(vaultIDs: [vaultID], displayNames: [display])
        }
        if foldFailures.isFoldedSynchronously(vaultID) {
            return .foldFailed(notice: VaultFoldFailureNotice.text(vaultDisplayName: display), previousProjection: projections[vaultID])
        }
        guard let projection = projections[vaultID] else {
            return .foldFailed(notice: VaultFoldFailureNotice.text(vaultDisplayName: display), previousProjection: nil)
        }
        return .current(projection)
    }

    /// The owner-facing count of records waiting for a readable copy, rendered
    /// as a **count**.
    ///
    /// **`liveRecords` decides the second sentence** (version 20 item 3):
    /// *"Everything else in this vault is up to date."* is true only where the
    /// vault holds a live record that is not waiting, and on the kit restore
    /// this count was written for there is nothing else.
    public func recordsWaitingNotice(vaultID: UUID, liveRecords: Int) -> String? {
        let waiting = foldFailures.markersSynchronously(vaultID).filter { !$0.blocksVault }.count
        guard waiting > 0 else { return nil }
        return VaultFoldFailureNotice.recordsWaiting(count: waiting, hasOtherLiveRecords: liveRecords > waiting)
    }

    /// The XPC row that exists so the app can ask for the flow **at a moment the
    /// owner expects a prompt** — opening the vault surface, or beginning an
    /// edit — rather than having one appear mid-scroll. **One prompt per vault,
    /// no value returned.**
    public func openMetadataPlane(vaultIDs: [UUID], displayNames: [String]) throws {
        try enterFlow(vaultIDs: vaultIDs, displayNames: displayNames)
    }

    /// Seals a `vault`, `item` or `folder` record for sync. **Needs `VCK_v`, so
    /// it runs inside flow 7**, and the broker enters the flow if it is not
    /// already in one — trigger 3.
    ///
    /// Named because version 13's surface had no write at all while §7 required
    /// one, and *"what bounds the step is what the interface returns"* applies to
    /// what it **accepts** as well.
    @discardableResult
    public func writeMetadata(
        vaultID: UUID,
        displayName: String,
        subject: VaultRecordSubject,
        plaintext: Data,
        revision: Int,
        keyGeneration: Int,
        identityKey: SymmetricKey
    ) throws -> VaultSealedRecord {
        // **And so is the vault's name** (nineteenth pass): bounding it here
        // is what makes the over-cap `vault` state unreachable by name alone,
        // rather than only truncated when it is rendered.
        if subject.kind == .vault { try VaultDisplayName.requireWritableName(displayName) }
        // **The account is bounded at the write** (custody plan version 21;
        // eighteenth pass, DB18-H1): a `value` id's account half is what the
        // `vault` record's 8 MiB derivation rests on, and nothing bounded it,
        // so an `item` whose account is not the minted UUID string never
        // reaches the map that would have to carry it.
        if subject.kind == .value {
            let account = String(subject.recordID.prefix { $0 != "|" })
            guard VaultMembership.isMintedAccount(account) else {
                throw VaultageError.invalidInput("A credential's account must be an identifier Vaultage minted.")
            }
        }
        guard subject.kind == .vault || subject.kind == .item || subject.kind == .folder else {
            throw VaultageError.invalidInput("Only a vault, item or folder record is sealed through the metadata plane.")
        }
        var sealed: VaultSealedRecord?
        try presence.withBatchPresence(
            subjects: [.vault(VaultSubject(vaultID: vaultID))],
            flow: .metadataPlane(vaults: [displayName])
        ) { token in
            let key = try presence.openVaultContentKey(token, vault: VaultSubject(vaultID: vaultID))
            var bytes = Data()
            key.withBytes { bytes = Data($0) }
            defer { bytes.resetBytes(in: bytes.startIndex ..< bytes.endIndex) }
            sealed = try VaultRecordEnvelope.seal(
                plaintext: plaintext,
                key: SymmetricKey(data: bytes),
                accountSubject: accountSubject,
                vaultID: vaultID,
                subject: subject,
                keyGeneration: keyGeneration,
                revision: revision,
                wireID: VaultWireID.compute(identityKey: identityKey, subject: subject)
            )
        }
        guard let sealed else { throw VaultageError.storage("The metadata plane sealed nothing.") }
        return sealed
    }

    /// The flow itself. **Its subject set is the vault content keys it covers**
    /// — one subject per vault — and **not** a set of `ValueSubject`s. It opens
    /// **no item key and no credential**.
    private func enterFlow(vaultIDs: [UUID], displayNames: [String]) throws {
        let subjects = Set(vaultIDs.map { PresenceSubject.vault(VaultSubject(vaultID: $0)) })
        try presence.withBatchPresence(subjects: subjects, flow: .metadataPlane(vaults: displayNames)) { token in
            for (index, vaultID) in vaultIDs.enumerated() {
                // **The one caller of `openVaultContentKey`.** *Apply is not a
                // caller*: version 13 wrote that it was, which required apply to
                // hold a `BatchToken` it had no construct to obtain, and the
                // cheapest way out for a builder was a shared evaluated
                // context — DB10-H1 one layer down.
                let key = try presence.openVaultContentKey(token, vault: VaultSubject(vaultID: vaultID))
                var bytes = Data()
                key.withBytes { bytes = Data($0) }
                defer { bytes.resetBytes(in: bytes.startIndex ..< bytes.endIndex) }
                try foldAndProject(
                    vaultID: vaultID,
                    displayName: displayNames.indices.contains(index) ? displayNames[index] : "",
                    contentKey: SymmetricKey(data: bytes)
                )
            }
        }
    }

    /// The merge, `normalize`, the projection build. **`normalize` runs only on
    /// a complete state** — stage 2's transaction gives it presence and the
    /// current-revision rule gives it openability — and it does **not** run at
    /// all when the fold failed.
    ///
    /// §7's per-kind merge table and §7.2's two `normalize` halves are
    /// **BL-106's**; what this ticket owns is the flow they run inside.
    private func foldAndProject(vaultID: UUID, displayName: String, contentKey: SymmetricKey) throws {
        let arriving = waiting[vaultID] ?? []
        let accountSubject = self.accountSubject
        let outcome = try foldSynchronously(vaultID: vaultID, arriving: arriving) { record, subject in
            try VaultRecordEnvelope.open(
                record, key: contentKey,
                accountSubject: accountSubject, vaultID: vaultID, subject: subject
            )
        }
        waiting[vaultID] = []
        // The retry has run. It re-arms only when a new head or revision
        // arrives.
        retryArmed.remove(vaultID)
        guard !outcome.failed else {
            // **No `normalize`, no projection rebuild, no seal**, the owner is
            // told, and the previous projection is left standing while one
            // exists in memory.
            return
        }
        projections[vaultID] = try rebuild(vaultID: vaultID, displayName: displayName, contentKey: contentKey)
    }

    private var foldBridge: ((UUID, [(wireID: String, subject: VaultRecordSubject)], (VaultSealedRecord, VaultRecordSubject) throws -> Data) throws -> VaultFoldOutcome)?

    /// Flow 7 is synchronous inside its closure — the token is `~Copyable` and
    /// cannot cross a suspension — so the fold is reached through a bridge the
    /// caller installs. `VaultSyncApply.fold` is the implementation; this keeps
    /// the token's scope a compile-time fact rather than a convention.
    public func installFoldBridge(
        _ bridge: @escaping (UUID, [(wireID: String, subject: VaultRecordSubject)], (VaultSealedRecord, VaultRecordSubject) throws -> Data) throws -> VaultFoldOutcome
    ) {
        foldBridge = bridge
    }

    private func foldSynchronously(
        vaultID: UUID,
        arriving: [(wireID: String, subject: VaultRecordSubject)],
        open: (VaultSealedRecord, VaultRecordSubject) throws -> Data
    ) throws -> VaultFoldOutcome {
        guard let foldBridge else { return VaultFoldOutcome() }
        return try foldBridge(vaultID, arriving, open)
    }

    private var projectionSource: ((UUID) -> VaultListProjection)?

    /// The projection's source of plaintext. In the broker it is the decrypted
    /// `vault`, `item` and `folder` records; the seam exists so BL-106's merge
    /// can replace it without reopening this flow.
    public func installProjectionSource(_ source: @escaping (UUID) -> VaultListProjection) {
        projectionSource = source
    }

    private func rebuild(vaultID: UUID, displayName: String, contentKey: SymmetricKey) throws -> VaultListProjection {
        let waitingForCopy = foldFailures.markersSynchronously(vaultID).filter { !$0.blocksVault }.count
        if let projectionSource {
            let built = projectionSource(vaultID)
            return VaultListProjection(
                vaultID: built.vaultID, vaultName: built.vaultName, folders: built.folders,
                items: built.items, waitingRecords: built.waitingRecords,
                recordsWaitingForAReadableCopy: waitingForCopy
            )
        }
        return VaultListProjection(
            vaultID: vaultID, vaultName: displayName, folders: [], items: [],
            waitingRecords: 0, recordsWaitingForAReadableCopy: waitingForCopy
        )
    }
}

