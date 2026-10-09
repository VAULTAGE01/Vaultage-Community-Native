import CryptoKit
import Foundation

// BL-100 slice A — §7.1's persisted fold markers
// (`13-MULTI-DEVICE-CUSTODY.md` version 17, **as amended by the sixteenth
// independent pass**, `evidence/security-review-bl097-v16-2026-09-14.md`
// DB16-H2, DB16-H3, DB16-H4, DB16-H1, DB16-M4; version 19 states them).
//
// *"The previous projection is left standing"* is vacuous across a restart, and
// **flow 7's own trigger *is* a restart**, so the failure is written down. Three
// things the sixteenth pass changed about that:
//
// 1. **One marker per `(vault, record)`, a set** (DB16-H4). A vault leaves fold
//    failure when its blocking set is empty, so one record clearing does not
//    clear the vault and a second unopenable record does not overwrite the
//    first.
// 2. **Only a `vault` or `folder` record blocks the vault** (DB16-H3). A
//    never-opened `item`, `value` or `blob` gets the same retain-and-retry rule
//    with a **per-record marker**, and the vault folds and projects around it:
//    on a kit restore that is most records, so the vault's view renders a
//    **count** of records waiting for a readable copy, not a list.
// 3. **A fold-failed vault does not satisfy flow 7's triggers** (DB16-H2).
//    `renderList` shows the fold-failed state **without a prompt**, and the
//    retry runs only when a new head or a new revision arrives for that vault —
//    one prompt then, rather than one per render.

/// One record's marker. It carries **no label**: a record this device has never
/// opened has none, and §2.4.1's residency rule forbids writing the projection
/// down in any case.
public struct VaultFoldMarker: Codable, Sendable, Hashable {
    public let vaultID: UUID
    public let wireID: String
    public let revision: Int
    /// Which record class this was. **`vault` and `folder` block the vault**,
    /// because `normalize` cannot run over a missing one; everything else is a
    /// record waiting for a readable copy.
    public let recordKind: VaultRecordKind

    public init(vaultID: UUID, wireID: String, revision: Int, recordKind: VaultRecordKind) {
        self.vaultID = vaultID
        self.wireID = wireID
        self.revision = revision
        self.recordKind = recordKind
    }

    public var blocksVault: Bool { recordKind == .vault || recordKind == .folder }
}

public enum VaultDisplayNameError: Error, Equatable, Sendable, LocalizedError {
    case notTheVaultRecord(VaultRecordKind)
    case nameTooLong(characters: Int, cap: Int)

    public var errorDescription: String? {
        switch self {
        case .notTheVaultRecord(let kind):
            "A vault's name comes from its own record's label field; a \(kind.rawValue) record cannot supply one."
        case .nameTooLong(_, let cap):
            "A vault's name is at most \(cap) characters."
        }
    }
}

/// **A name a device may render for a vault, and the only thing that can supply
/// one** (seventeenth pass, DB17-H3).
///
/// §7.1 closes the string block with *"`{vault}` is rule 1's name-or-short-id
/// … Neither is attacker-chosen."* The second half is false: the vault's name
/// lives in the `vault` record and is written by **any device that can write
/// one**, which is A-2 — a compromised paired device with its own row in this
/// document's threat model, its own conceded write path, and an explicit
/// residual that *"revoking, rekeying and rotating remove nothing the device
/// added"*. Rule 1 bounded where the name comes from and said nothing about
/// what it may be, and §3.1's table let a `vault` record carry the whole of
/// its bucket — so the notice rendered attacker-chosen plaintext at the head of
/// a security string, in the owner's most alarmed moment, in a design whose
/// §6.3 exists because an owner asked for their recovery code should know they
/// are being phished.
///
/// Two things make the claim true rather than aspirational. **It is rendered as
/// data**: every control, format and line-breaking scalar becomes a space, runs
/// of blanks collapse, and the result is trimmed — so a name cannot end a
/// sentence, start a line or carry an invisible directional override.
/// **And it is bounded to a compiled length**, so it cannot outrun the sentence
/// it sits in. **The type is the other half**: the only initializer takes the
/// subject of the record the label was read out of and refuses anything but a
/// `vault` record, so a rendered name can never come from a **value field**.
public struct VaultLastOpenedName: Sendable, Equatable {
    public let rendered: String

    /// The only way to make one. `subject` is the record this device opened to
    /// read the label, and it has to be the vault's own; `label` is that
    /// record's **label-typed field** (eighteenth pass, DB18-H3).
    ///
    /// **"Never a value field" is the check, not "never a value"**: the name
    /// comes from one typed field of one kind of record, which a type can
    /// enforce, rather than from a comparison against a value's plaintext,
    /// which a 64-character truncation makes vacuous — a truncated hostile name
    /// equals no value field either.
    public init(openedVaultRecord subject: VaultRecordSubject, label: String) throws {
        guard subject.kind == .vault else { throw VaultDisplayNameError.notTheVaultRecord(subject.kind) }
        rendered = VaultDisplayName.renderAsData(label)
    }
}

/// How a vault names itself to its owner.
///
/// **Never a compile-time constant** (sixteenth pass, DB16-H1): the notice is
/// about a vault whose name may never have been read on this device, so it is
/// the **last-opened name** when one exists and the vault's **short id**
/// otherwise. Rule 1 bans *reaching for* the constant; it does not ban the
/// name — a vault whose genuine last-opened name is `Personal` renders
/// `Personal`, and a builder implementing *"never by a compile-time constant"*
/// literally would suppress the one correct case (seventeenth pass, DB17-M4).
public enum VaultDisplayName {
    /// The compiled ceiling on a rendered name, in characters (version 20 item
    /// 3: *"truncated to a compiled maximum of 64 characters"*).
    public static let maximumRenderedCharacters = 64
    public static let truncationMark = "…"

    /// **The short id has a derivation, and it is not a prefix of the vault
    /// id** (seventeenth pass, DB17-M4). §7.1 said *"otherwise by its short
    /// id"* and nothing else, and the obvious construction — a prefix of the
    /// vault id — renders the **same characters** for the default vault on
    /// every install and in every account, because
    /// `VaultOrganization.swift:"public static let defaultID = UUID(uuidString: "`
    /// is a structured constant. That is rule 1's own failure arriving through
    /// the branch rule 1 added to avoid it. Binding the account subject makes
    /// the short id per-install while keeping it stable for a vault on one
    /// account, which is what the notice needs it for.
    /// **The first 8 lowercase hex characters of
    /// `SHA-256(accountSubject ‖ vaultID)`**, at version 20's own wording.
    public static func shortID(accountSubject: String, vaultID: UUID) -> String {
        var preimage = Data(accountSubject.utf8)
        preimage.append(Data(vaultID.uuidString.lowercased().utf8))
        let digest = SHA256.hash(data: preimage).map { String(format: "%02x", $0) }.joined()
        return String(digest.prefix(8))
    }

    /// Rendered as data: nothing in a name may act like the notice around it.
    public static func renderAsData(_ name: String) -> String {
        var out = ""
        var lastWasBlank = true
        for scalar in name.unicodeScalars {
            let category = scalar.properties.generalCategory
            let isBlank = CharacterSet.whitespacesAndNewlines.contains(scalar)
                || category == .control || category == .format
                || category == .lineSeparator || category == .paragraphSeparator
                || category == .privateUse || category == .surrogate
            if isBlank {
                if !lastWasBlank { out.append(" ") }
                lastWasBlank = true
                continue
            }
            out.unicodeScalars.append(scalar)
            lastWasBlank = false
        }
        while out.hasSuffix(" ") { out.removeLast() }
        guard out.count > maximumRenderedCharacters else { return out }
        return String(out.prefix(maximumRenderedCharacters)) + truncationMark
    }

    /// **The bound at the write, which is what makes the render's truncation
    /// unreachable by name** (nineteenth pass). Truncating at render is a
    /// display rule; it leaves a 16 KiB name in the record, where it counts
    /// against the `vault` record's own 8 MiB class and could reach the
    /// over-cap state by name alone. Bounding the write at the same 64
    /// characters makes that state unreachable that way, and leaves the render
    /// rule in place for a name written by an older build.
    public static func requireWritableName(_ name: String) throws {
        let rendered = renderAsData(name)
        guard !rendered.hasSuffix(truncationMark), name.count <= maximumRenderedCharacters else {
            throw VaultDisplayNameError.nameTooLong(characters: name.count, cap: maximumRenderedCharacters)
        }
    }

    public static func resolve(lastOpenedName: VaultLastOpenedName?, vaultID: UUID, accountSubject: String) -> String {
        if let lastOpenedName, !lastOpenedName.rendered.isEmpty { return lastOpenedName.rendered }
        return "the vault \(shortID(accountSubject: accountSubject, vaultID: vaultID))"
    }
}

public enum VaultFoldFailureNotice {
    /// **The three strings, quoted from §7.1, each with a string test**
    /// (sixteenth pass, DB16-H1; stated in version 19).
    ///
    /// Four rules shape all three. **(1)** The vault is named by its
    /// **last-opened name** where this device has one and by its **short id**
    /// where it does not — *never* by a compile-time constant, and in
    /// particular never by `VaultOrganization.swift:"public static let defaultName = "`,
    /// which is the one name available without opening anything. **(2)** The
    /// bytes are *"a change relayed for this vault"*, because attributing A-1's
    /// substitution to the owner's own hardware tells them to distrust the
    /// wrong thing. **(3)** It says **"record"**, not *"item"*: *"item"* is a
    /// kind claim §3.2's `wireID` hides. **(4)** The clearing sentence names no
    /// act the owner must perform.

    /// **Fold failure**, on the vault.
    public static func text(vaultDisplayName: String) -> String {
        "\(vaultDisplayName) can't be updated on this Mac. A change relayed for this vault "
            + "arrived as a record this Mac could not read, so nothing in this vault has "
            + "changed here and nothing has been sent from here. Your other devices are "
            + "unaffected. This clears when a readable copy arrives."
    }

    /// **Records waiting for a readable copy**, on the vault's own view — **a
    /// count and never a list** (sixteenth pass, DB16-H3), because on a kit
    /// restore that is every record.
    ///
    /// **And the second sentence appears only where there is something else**
    /// (version 20 item 3): on the kit restore this count was written for there
    /// **is** nothing else, and *"Everything else in this vault is up to date."*
    /// asserted a state the vault is not in.
    public static func recordsWaiting(count: Int, hasOtherLiveRecords: Bool) -> String {
        let noun = count == 1 ? "record is" : "records are"
        let first = "\(count) \(noun) waiting for a readable copy."
        return hasOtherLiveRecords ? first + " Everything else in this vault is up to date." : first
    }

}

/// **§7.1's refusal strings, quoted there and composed here** (version 20 item
/// 3; seventeenth pass, DB17-M1, DB17-M2).
///
/// Version 19 specified the served-head bound-2 refusal in §3.1 **and** a
/// different refused-head string in §7.1, both instructing this ticket — four
/// strings for three states — and the refused-head string named a **size** for
/// all of its reasons, two of which are not sizes. Version 20 makes §7.1 the
/// one normative place and gives **six** states six strings; three of the six
/// are refused heads and are composed below, the fold failure and the waiting
/// count are above, and the write-side vault-is-full one is §3.1's own.
public enum VaultRefusalNotice {
    /// §10's `headRefusals/` reason field, at its four values. The marker, the
    /// receipt and the string all read this rather than three renderings of it.
    public enum Reason: String, Sendable, Equatable, CaseIterable, Codable {
        /// Bound 1, read from the receiving side, **per transfer** — the count
        /// or the body bytes. Both render the same string, because both are a
        /// transfer that was larger than this Mac will accept.
        case boundOne
        case boundTwo
        case maximumSealedRecordBytes
        case namedAndNotServed
        /// **A page sequence that stopped** (eighteenth pass, DB18-C2). It
        /// shares the named-and-not-served string, because it is the same fact
        /// to the owner: the change arrived incomplete.
        case pagesIncomplete
        /// **A page sequence that is still working** (nineteenth pass). It is
        /// not a refusal: it holds the fence, because a vault in the middle of
        /// a restore is not a vault that has stopped hearing from its relay,
        /// and §3.3's intervals would otherwise route a working device's writes
        /// at 24 hours of a large restore. It spends nothing.
        case pagesInProgress
        /// **The `vault` record cannot be sealed** — the seventh state
        /// (eighteenth pass, DB18-H3). It is the one refusal in this design
        /// that fires on the owner's **own** write, inside flow 7, on a vault
        /// that is not full, and *"open this vault to fold in the changes"*
        /// frees nothing because the map is a function of the live set and
        /// slice A cannot shrink one.
        case vaultRecordOverItsCap
    }

    /// What the notice says where no vault name has been resolved — a core
    /// refusal crossing no owner surface. It is a **pronoun**, not a name: rule
    /// 1 bans reaching for a compile-time vault *name*, and `VaultDisplayName`
    /// is the only thing that supplies one.
    public static let unnamedVaultSubject = "This vault"

    /// The one clause that varies between the two refused-head strings that
    /// share a shape. Bound 2 does not share it (DB17-M2): it is the owner's
    /// vault being full and not a length the relay chose, so it keeps §3.1's
    /// own string and its own remedy.
    public static func cause(_ reason: Reason) -> String {
        switch reason {
        case .namedAndNotServed, .pagesIncomplete: "arrived incomplete"
        case .pagesInProgress: "is still arriving"
        default: "was larger than this Mac will accept"
        }
    }

    /// **The seventh string** (eighteenth pass, DB18-H3). §7.1 enumerated six
    /// and the over-cap `vault` record was not one of them; what a missing
    /// bucket produced instead named the kind and a byte count and no act. This
    /// names the state, and names **no act that does nothing**: the vault is not
    /// full, so bound 2's remedies are all false here, and folding in what is
    /// waiting frees nothing because the map is a function of the live set.
    public static func vaultRecordOverItsCap(vaultDisplayName: String) -> String {
        "\(vaultDisplayName) can't take any more records on this Mac. This vault holds as "
            + "many records as one vault can, so the change you just made was not saved and "
            + "nothing already in this vault has changed. To keep working, export this vault "
            + "and start a new one."
    }

    /// **Substituted as data into a fixed sentence rather than composed into
    /// it** (DB17-H3). `vaultDisplayName` is already bounded and stripped by
    /// `VaultLastOpenedName`; this is the sentence it is substituted into.
    public static func headRefused(vaultDisplayName: String, reason: Reason) -> String {
        if reason == .vaultRecordOverItsCap { return vaultRecordOverItsCap(vaultDisplayName: vaultDisplayName) }
        guard reason != .boundTwo else { return VaultRecordBudget.relayCausedVaultFullMessage }
        return "\(vaultDisplayName) can't be updated on this Mac. A change relayed for this vault "
            + "\(cause(reason)), so nothing in this vault has changed here and nothing has "
            + "been sent from here. Your other devices are unaffected. This clears when a "
            + "change this Mac can accept arrives."
    }

    public static func headRefused(reason: Reason) -> String {
        headRefused(vaultDisplayName: unnamedVaultSubject, reason: reason)
    }
}

/// The per-vault marker set, in the broker's container at `foldFailures/` — a
/// row in §10's manifest, **with an iOS row beside it** (DB16-H4, DB16-L2).
/// `headRefusals/` is `VaultHeadRefusalStore`'s, in its own file, because
/// version 19's Artifacts list names it as its own artefact.
public actor VaultFoldFailureStore {
    private let container: BrokerContainer

    public init(container: BrokerContainer) { self.container = container }

    public nonisolated var root: URL { container.directory(.foldFailures) }

    private nonisolated func file(_ vaultID: UUID) -> URL {
        root.appendingPathComponent("\(vaultID.uuidString.lowercased()).json")
    }

    // MARK: - Record markers

    public func markers(_ vaultID: UUID) -> Set<VaultFoldMarker> { Self.markersSynchronously(file(vaultID)) }

    /// **A vault is in fold failure while its blocking set is non-empty**, and
    /// leaves it when that set is empty.
    public func isFolded(_ vaultID: UUID) -> Bool { markers(vaultID).contains { $0.blocksVault } }

    /// The count the vault's view renders — never a list.
    public func recordsWaitingForAReadableCopy(_ vaultID: UUID) -> Int {
        markers(vaultID).filter { !$0.blocksVault }.count
    }

    public func record(_ marker: VaultFoldMarker) throws {
        var set = markers(marker.vaultID)
        set = set.filter { $0.wireID != marker.wireID }
        set.insert(marker)
        try save(set, vaultID: marker.vaultID)
    }

    /// **Until a later arriving revision for that record opens** — §10's horizon
    /// for this path, and the only thing that clears a marker.
    public func clear(vaultID: UUID, wireID: String) throws {
        let set = markers(vaultID).filter { $0.wireID != wireID }
        try save(set, vaultID: vaultID)
    }

    // MARK: - Files

    private func save(_ markers: Set<VaultFoldMarker>, vaultID: UUID) throws {
        guard !markers.isEmpty else {
            try? FileManager.default.removeItem(at: file(vaultID))
            return
        }
        try write(markers.sorted { $0.wireID < $1.wireID }, to: file(vaultID), directory: root)
    }

    private func write(_ value: some Encodable, to url: URL, directory: URL) throws {
        try container.ensure()
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        let temporary = directory.appendingPathComponent("marker-\(UUID().uuidString).tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw VaultCipherStoreError.storage("Could not create a fold marker.")
        }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try? handle.close()
        _ = try manager.replaceItemAt(url, withItemAt: temporary, backupItemName: nil, options: [])
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// A synchronous read, for the render path, which must be able to answer
    /// inside flow 7's non-escaping closure. It opens no key.
    static func markersSynchronously(_ url: URL) -> Set<VaultFoldMarker> {
        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode([VaultFoldMarker].self, from: data)
        else { return [] }
        return Set(list)
    }

    public nonisolated func markersSynchronously(_ vaultID: UUID) -> Set<VaultFoldMarker> {
        Self.markersSynchronously(file(vaultID))
    }

    public nonisolated func isFoldedSynchronously(_ vaultID: UUID) -> Bool {
        markersSynchronously(vaultID).contains { $0.blocksVault }
    }
}
