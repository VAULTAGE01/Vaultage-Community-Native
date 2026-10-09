import Foundation

// BL-100 slice A — the record store's three budgets
// (`13-MULTI-DEVICE-CUSTODY.md` **version 17** §3.1; twelfth pass, DB12-H5).
//
// The `head` chain has been bounded since version 10 *for exactly this
// attacker* — *"A-2's compromised phone can fill every paired device's disk at
// will"*. The store the heads are **about** was bounded by nothing: a size
// bucket caps one record, and nothing capped the number of records, the bytes
// they occupy, or `n`, the number of records in a write certificate's push
// body.
//
// **All three are refused with a plain owner-facing error rather than
// silently.** These bound **growth**, and growth is recoverable; none of them is
// an accumulator in §7.3's sense, because nothing is being destroyed.

public enum VaultRecordBudget {
    // MARK: - Bound 1: per push

    /// A write certificate covering more is refused by the sequencer **before
    /// it folds anything**, and the pushing device is told why. BL-110 inherits
    /// this closed, which removes one of DB11-C1's three paths before that
    /// finding is re-opened.
    public static let maximumRecordsPerPush = 1_024
    public static let maximumPushBodyBytes = 16 * 1024 * 1024

    // MARK: - Paging, and what ends a page sequence

    /// **A page sequence has a completion rule and two stall budgets**
    /// (eighteenth pass, DB18-C2). Version 20 introduced paging with a rule for
    /// its success and none for any of its failures: three pages and stop left
    /// nothing applied, the watermark unmoved, **no bound failed** and therefore
    /// no marker, no receipt and no notice — and the fence, which version 20
    /// holds *"while a marker is live"*, had no marker to hold it, so at 6 hours
    /// the owner got a message about **time** for a relay that stopped sending.
    ///
    /// Both budgets are **compiled**, and both are chosen rather than derived.
    /// The attempt budget is above what a vault at bound 2's cap needs — 50,000
    /// records at 1,024 a page is 49 pages — so an honest restore never reaches
    /// it.
    /// **Rule 8's fourth number** (custody plan version 23 item 3; twentieth
    /// pass, DB20-H3): a page sequence is over when every named page is staged
    /// or when one of four compiled numbers runs out — this page ceiling, the
    /// 15-minute stall clock below measured from the **last completed page**,
    /// and the marker's eight attempts and 128 MiB. The four are asserted
    /// together in `VaultRecordBudgetContracts`.
    public static let maximumPagesPerHead = 64
    public static let pageSequenceStallSeconds: TimeInterval = 15 * 60

    // MARK: - Bound 2: per vault

    /// §3.1's addressable cap: what a vault holds that an owner can name.
    public static let maximumAddressableRecordsPerVault = 50_000

    /// **The `index` page ceiling, derived from the cap above and not chosen**
    /// (custody plan version 22 item 4): the map is `index` pages of at most
    /// `maximumIndexEntriesPerPage` entries, so a vault at its addressable cap
    /// needs `ceil(50,000 / 96)` = **521** of them.
    public static let maximumIndexPagesPerVault =
        (maximumAddressableRecordsPerVault + VaultMembership.maximumIndexEntriesPerPage - 1)
            / VaultMembership.maximumIndexEntriesPerPage

    /// **Bound 2's record half: 50,521, and an `index` page counts like every
    /// other record** (twentieth pass, DB20-C2).
    ///
    /// Version 22 exempted `index` pages from the 50,000 and gave a good reason
    /// — a cap that counted its own index would be a function of itself — but
    /// put the bound at **transfer**, which is the one stage that cannot tell an
    /// `index` page from any other record: §3.2's `wireID` is a forward-only
    /// HMAC that hides the kind, apply holds no key, the store is keyed on
    /// `wireID`, and the map that resolves one is memory-only and built inside
    /// flow 7 — which on a kit restore has never run and whose `index` pages are
    /// among the records arriving.
    ///
    /// So the exemption is replaced by a **number**: the cap is the addressable
    /// records **plus the derived page ceiling**, and every record counts.
    /// §3.1's self-reference argument survives, because 521 is derived from
    /// 50,000 and not from itself.
    public static let maximumLiveRecordsPerVault =
        maximumAddressableRecordsPerVault + maximumIndexPagesPerVault
    public static let maximumSealedBytesPerVault = 2 * 1024 * 1024 * 1024

    /// **A record is bounded at transfer, derived from the record shape rather
    /// than chosen** (fifteenth pass, DB15-H3).
    ///
    /// `folder` and `item` top out at §3.2's **16 KiB** bucket; **`vault` at its
    /// own class's top bucket**, which is derived from bound 2 because the
    /// record carries the vault's membership (seventeenth pass, DB17-C1);
    /// `value` at the **1 MiB** bucket, which is
    /// `CompositeCredential.swift:"public static let maximumFieldBytes = 64 * 1024"`
    /// × `CompositeCredential.swift:"public static let maximumFields = 8"` with
    /// overhead; and `maximumAttachmentsPerItem` = 32 bounds how many `blob`
    /// records an item has and **not** how large one is, so the ceiling is the
    /// `blob` bucket's **10 MiB** cap plus one 64 KiB bucket step for the
    /// envelope. **Apply cannot tell which kind it is holding** — `wireID`
    /// hides that — so it applies the largest of them to all of them.
    public static let maximumSealedRecordBytes = 10 * 1024 * 1024 + 64 * 1024

    /// **The gate DB17-C1 asks for, in the code rather than in a sentence.**
    /// Giving the `vault` record its own size class is only safe while that
    /// class's top bucket still fits under the per-record ceiling every kind is
    /// held to — apply cannot tell which kind it is holding, so a class whose
    /// top bucket exceeded this would be a class whose records are refused at
    /// transfer by the bound above. `VaultRecordBudgetContracts` asserts it,
    /// and the derivation in `VaultMembership` is what makes it arithmetic.
    public static var vaultClassFitsTheRecordBound: Bool {
        guard let top = VaultRecordSizeClass.vault.buckets.last else { return false }
        return top == 8 * 1024 * 1024
            && top >= VaultMembership.maximumVaultRecordBytes
            && top <= maximumSealedRecordBytes
    }

    // MARK: - Bound 3: per device, per sliding window

    /// **Per device**, so an honest bulk import from the owner's own Mac is not
    /// throttled by a phone's behaviour, and **account-wide across every synced
    /// vault** — DB5-H6 is the precedent and it went this way, because per
    /// vault an account with six synced vaults would give one compromised phone
    /// 12,000 records a day.
    public static let maximumRecordsPerDevicePerWindow = 2_000
    public static let deviceWindow: TimeInterval = 24 * 60 * 60

    // MARK: - The owner-facing strings

    /// Bound 2's refusal, in the product's own words.
    ///
    /// **Opening the vault is named first** because it is the one space-freeing
    /// act slice A has, and it is the one that applies in the state this
    /// design's own apply rule creates (fourteenth pass, DB14-H1). Revoking
    /// stops the flooding device; it does not shrink the vault. **Nothing else
    /// frees space until BL-110**, and the string says so rather than naming an
    /// action that does nothing — version 14's told the owner to *"delete
    /// something, or move some of it to another vault"* against the same
    /// version's *"a queued deletion frees no storage"*.
    public static let vaultFullMessage = """
        Open this vault to fold in the changes waiting for it. Changes that have arrived and \
        not been opened are stored twice, and folding them in is the one thing in this \
        release that frees space. This vault is full — 50,000 items, fields and attachments, \
        or 2 GB. Nothing else frees space in this version. If a device has been adding \
        records you did not make, revoke it in Settings › Devices to stop it adding more. To \
        keep working, export this vault and start a new one. Freeing space needs deletion \
        sync, which is not in this release.
        """

    /// **The relay-caused variant** (sixteenth pass, DB16-M4), which version 20
    /// keeps as one of §7.1's six strings and which
    /// `VaultRefusalNotice.headRefused` returns for `boundTwo`. Bound 2 is
    /// evaluated at transfer, so the party that trips it is most often **A-1**,
    /// which the owner cannot revoke — and offering *"revoke it in Settings ›
    /// Devices"* against a refusal the relay caused tells the owner to punish
    /// their own phone for something it did not do. **It is not the
    /// refused-head string**, which would name the wrong cause and the wrong
    /// remedy for the one reason that has a remedy (seventeenth pass,
    /// DB17-M2).
    public static let relayCausedVaultFullMessage = """
        Open this vault to fold in the changes waiting for it. Changes that have arrived and \
        not been opened are stored twice, and folding them in is the one thing in this \
        release that frees space. This vault is full — 50,000 items, fields and attachments, \
        or 2 GB. Nothing else frees space in this version. To keep working, export this vault \
        and start a new one. Freeing space needs deletion sync, which is not in this release.
        """

    /// Bound 3's, which destroys nothing and raises no sheet: it refuses
    /// further pushes from that device until the window slides, and the vault
    /// surface says which device and how many.
    public static func deviceRateMessage(deviceName: String, records: Int) -> String {
        "\(deviceName) has added \(records) items in the last day, which is as many as one "
            + "device may add. It can add more once the day has passed. Nothing has been lost."
    }

    public static func pushTooLargeMessage(records: Int, bytes: Int) -> String {
        "A device tried to send \(records) records in one push. Vaultage accepts at most "
            + "\(maximumRecordsPerPush) records or 16 MB at a time, so nothing was folded in."
    }

    public static let recordTooLargeMessage = """
        A device sent a record larger than any Vaultage record can legally be, so it was not \
        stored. Nothing already in this vault has changed.
        """
}

public enum VaultBudgetRefusal: Error, Equatable, Sendable, LocalizedError {
    case pushTooLarge(records: Int, bytes: Int)
    case vaultFull(liveRecords: Int, sealedBytes: Int)
    case recordTooLarge(bytes: Int)
    case deviceWindowExhausted(deviceID: String, records: Int)

    public var errorDescription: String? {
        switch self {
        case .pushTooLarge(let records, let bytes):
            VaultRecordBudget.pushTooLargeMessage(records: records, bytes: bytes)
        case .vaultFull:
            VaultRecordBudget.vaultFullMessage
        case .recordTooLarge:
            VaultRecordBudget.recordTooLargeMessage
        case .deviceWindowExhausted(let deviceID, let records):
            VaultRecordBudget.deviceRateMessage(deviceName: deviceID, records: records)
        }
    }
}

/// Bound 1, checked by the sequencer **before it folds anything**.
///
/// **This is the push side and it is unchanged.** The receiving side's reading
/// of the same two numbers moved from *what the head names* to *what one
/// transfer carries* (seventeenth pass, DB17-C2), and that half lives in
/// `VaultSyncApply.transfer`.
public enum VaultPushBudget {
    public static func admit(records: Int, bodyBytes: Int) throws {
        guard records <= VaultRecordBudget.maximumRecordsPerPush,
              bodyBytes <= VaultRecordBudget.maximumPushBodyBytes
        else { throw VaultBudgetRefusal.pushTooLarge(records: records, bytes: bodyBytes) }
    }
}

/// Bound 3's sliding window.
///
/// **The window is uptime-measured and a reboot clears it, said plainly rather
/// than implied** (thirteenth pass, DB13-M2). Every duration in §7's box is
/// *elapsed time since one named event*, which is what an accumulator can
/// persist and resume; a sliding window over 2,000 discrete push events needs
/// **each event's age**, which is a different structure. The two things a
/// builder reaches for are per-push wall-clock timestamps — which four passes
/// were spent removing from this design — or a reset at boot. **This takes
/// neither and adds no structure**: the window lives in the broker's own memory
/// on its uptime clock, so a reboot clears it, and the bound that survives a
/// reboot is bound 2.
public actor VaultDeviceRateWindow {
    private let monotonic: any MonotonicClock
    /// One entry per pushed record, by the broker's uptime at the push.
    /// Account-wide across every synced vault, keyed by device.
    private var pushes: [String: [TimeInterval]] = [:]

    public init(monotonic: any MonotonicClock = SystemMonotonicClock()) {
        self.monotonic = monotonic
    }

    /// Admits `records` from `deviceID`, or refuses the whole push. Crossing
    /// the bound **destroys nothing and raises no sheet**.
    public func admit(records: Int, deviceID: String) throws {
        let now = monotonic.uptime
        var window = (pushes[deviceID] ?? []).filter { now - $0 < VaultRecordBudget.deviceWindow }
        guard window.count + records <= VaultRecordBudget.maximumRecordsPerDevicePerWindow else {
            pushes[deviceID] = window
            throw VaultBudgetRefusal.deviceWindowExhausted(deviceID: deviceID, records: window.count)
        }
        window.append(contentsOf: Array(repeating: now, count: records))
        pushes[deviceID] = window
    }

    public func recorded(deviceID: String) -> Int {
        let now = monotonic.uptime
        return (pushes[deviceID] ?? []).filter { now - $0 < VaultRecordBudget.deviceWindow }.count
    }
}


/// The three numbers bound 2 and the per-record bound are evaluated against.
///
/// It is a value rather than three `static let` reads for **one** reason: a
/// contract has to be able to drive *"a vault at 50,000 records or 2 GiB
/// refuses the next write"* without writing 2 GiB to a temporary directory,
/// exactly as `MetadataStore.supportedSchemaVersion` is a parameter so a
/// refusal test can *be* an older build. **Nothing in the product constructs
/// anything but `.shipped`**, and the shipped numbers are asserted against
/// `VaultRecordBudget`'s constants on their own.
public struct VaultVaultBudget: Sendable, Equatable {
    public let maximumLiveRecords: Int
    public let maximumSealedBytes: Int
    public let maximumSealedRecordBytes: Int
    /// **Bound 1, read from the receiving side: what one transfer carries**
    /// (seventeenth pass, DB17-C2). It is a parameter for the same reason the
    /// three above are — a contract has to be able to drive *"a head naming
    /// more than one transfer carries is paged"* without building 1,025
    /// records, exactly as it drives bound 2 without writing 2 GiB.
    public let maximumRecordsPerTransfer: Int
    public let maximumTransferBodyBytes: Int

    public init(
        maximumLiveRecords: Int,
        maximumSealedBytes: Int,
        maximumSealedRecordBytes: Int,
        maximumRecordsPerTransfer: Int = VaultRecordBudget.maximumRecordsPerPush,
        maximumTransferBodyBytes: Int = VaultRecordBudget.maximumPushBodyBytes
    ) {
        self.maximumLiveRecords = maximumLiveRecords
        self.maximumSealedBytes = maximumSealedBytes
        self.maximumSealedRecordBytes = maximumSealedRecordBytes
        self.maximumRecordsPerTransfer = maximumRecordsPerTransfer
        self.maximumTransferBodyBytes = maximumTransferBodyBytes
    }

    public static let shipped = VaultVaultBudget(
        maximumLiveRecords: VaultRecordBudget.maximumLiveRecordsPerVault,
        maximumSealedBytes: VaultRecordBudget.maximumSealedBytesPerVault,
        maximumSealedRecordBytes: VaultRecordBudget.maximumSealedRecordBytes,
        maximumRecordsPerTransfer: VaultRecordBudget.maximumRecordsPerPush,
        maximumTransferBodyBytes: VaultRecordBudget.maximumPushBodyBytes
    )
}
