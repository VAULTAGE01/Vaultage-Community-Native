import Foundation

// BL-078 / D24 — multiple vaults and folders, as metadata structure only.
//
// Two properties hold everywhere in this file:
//
// 1. **No operation here touches a Keychain record.** A vault, a folder and an
//    item's filing are metadata; the value stays in the same user-presence
//    Keychain record under the same account, with the same credential version,
//    whatever happens to the tree above it. Moving an item between folders or
//    between vaults therefore cannot fail half way and cannot lose a value.
// 2. **Nothing here authorizes anything.** Filing is not policy: an item's
//    vault does not widen or narrow what a binding, a grant or a runtime
//    delivery may do with it. The broker resolves items by id and never reads
//    `vaultID`.
//
// Donor semantics (read, not copied — v1 native stores an encrypted collection
// graph that v2 does not have): `VaultFolderCreator` and `VaultFolderRenamer`
// for the name bounds and the trimmed, control-character-free identifier rule;
// `VaultFolderDeleter` for root protection and for refusing a stale revision;
// `VaultTreeItemMover` for cycle protection and for deterministic order.

/// What a vault *is*. `local` is the only kind this release can serve.
///
/// The other two cases exist so the model leaves room for BL-080 (D25):
/// a connected secret manager appears in the rail as its own read-through
/// vault. `unsupported` is what a record written by a newer build decodes to
/// here — it is rendered as a vault this build cannot open rather than as a
/// local vault whose items are simply missing, which is the fail-closed
/// reading of an unknown kind.
public enum VaultKind: Hashable, Sendable {
    case local
    case external(managerConnectionID: UUID)
    case unsupported(String)

    public static let localName = "local"
    public static let externalName = "external"

    public var isLocal: Bool { self == .local }

    /// True when this build can create, move and delete items in the vault.
    /// Only a local vault is writable today: an external manager is read
    /// through in BL-080, and an unsupported record is not understood at all.
    public var isWritable: Bool { isLocal }

    public var title: String {
        switch self {
        case .local: "Local"
        case .external: "Connected secret manager"
        case .unsupported: "Not supported by this version"
        }
    }
}

/// One vault: a top-level section of the rail, and the unit an item is filed
/// into.
///
/// The kind is stored as its raw name plus an optional manager connection id
/// rather than as an enum with an associated value, so that a build which does
/// not understand a kind re-encodes the record it read instead of flattening
/// it. An older build must be able to leave a newer record alone.
public struct Vault: Codable, Identifiable, Hashable, Sendable {
    /// The fixed id of the vault every pre-schema-12 item migrates into. It is
    /// a constant rather than a fresh UUID so the migration is deterministic
    /// and idempotent: running it twice cannot produce two default vaults.
    public static let defaultID = UUID(uuidString: "5641554C-0001-4000-8000-000000000001")!
    public static let defaultName = "Personal"
    public static let maximumNameLength = 128

    public let id: UUID
    public var name: String
    private var storedKind: String
    private var storedManagerConnectionID: UUID?
    public var createdAt: Date
    /// When the owner archived this vault. An archived vault keeps every item
    /// and folder; it is collapsed out of the rail and cannot be the active
    /// vault, and nothing new may be filed into it.
    public var archivedAt: Date?

    public var isArchived: Bool { archivedAt != nil }

    public var kind: VaultKind {
        get {
            switch storedKind {
            case VaultKind.localName: .local
            case VaultKind.externalName:
                if let storedManagerConnectionID { .external(managerConnectionID: storedManagerConnectionID) } else { .unsupported(VaultKind.externalName) }
            default: .unsupported(storedKind)
            }
        }
        set {
            switch newValue {
            case .local: storedKind = VaultKind.localName; storedManagerConnectionID = nil
            case .external(let id): storedKind = VaultKind.externalName; storedManagerConnectionID = id
            case .unsupported(let name): storedKind = name
            }
        }
    }

    public init(id: UUID = UUID(), name: String, kind: VaultKind = .local, createdAt: Date = .now, archivedAt: Date? = nil) {
        self.id = id
        self.name = name
        self.storedKind = VaultKind.localName
        self.storedManagerConnectionID = nil
        self.createdAt = createdAt
        self.archivedAt = archivedAt
        self.kind = kind
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, createdAt, archivedAt
        case storedKind = "kind"
        case storedManagerConnectionID = "managerConnectionID"
    }

    /// An absent `kind` is a record from a build that only had local vaults,
    /// and decodes to `local`. An absent name decodes to the default name
    /// rather than to an empty rail row.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        let decodedName = (try c.decodeIfPresent(String.self, forKey: .name))?.trimmingCharacters(in: .whitespacesAndNewlines)
        name = (decodedName?.isEmpty == false ? decodedName! : Vault.defaultName)
        storedKind = try c.decodeIfPresent(String.self, forKey: .storedKind) ?? VaultKind.localName
        storedManagerConnectionID = try c.decodeIfPresent(UUID.self, forKey: .storedManagerConnectionID)
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? .now
        archivedAt = try c.decodeIfPresent(Date.self, forKey: .archivedAt)
    }

    /// The default vault every migrated item lands in.
    public static func personal(createdAt: Date = .now) -> Vault {
        Vault(id: defaultID, name: defaultName, kind: .local, createdAt: createdAt)
    }
}

/// One folder inside one vault. A folder never spans vaults, and its parent is
/// always another folder in the same vault or the vault root (`nil`).
public struct Folder: Codable, Identifiable, Hashable, Sendable {
    public static let maximumNameLength = 128
    /// The vault root is depth 0 and a top-level folder is depth 1, so eight
    /// levels of folders can be nested. The bound exists because the rail
    /// indents per level and because every tree walk here is depth-first: a
    /// hand-edited file cannot make one of them unbounded.
    public static let maximumDepth = 8

    public let id: UUID
    public var vaultID: UUID
    /// `nil` means the folder sits at the vault root.
    public var parentID: UUID?
    public var name: String
    /// Order among siblings. Ties break on name, then on id, so the rail is
    /// deterministic even for a hand-edited file with duplicate orders.
    public var sortOrder: Int

    public init(id: UUID = UUID(), vaultID: UUID, parentID: UUID? = nil, name: String, sortOrder: Int = 0) {
        self.id = id
        self.vaultID = vaultID
        self.parentID = parentID
        self.name = name
        self.sortOrder = sortOrder
    }

    private enum CodingKeys: String, CodingKey { case id, vaultID, parentID, name, sortOrder }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        vaultID = try c.decode(UUID.self, forKey: .vaultID)
        parentID = try c.decodeIfPresent(UUID.self, forKey: .parentID)
        let decodedName = (try c.decodeIfPresent(String.self, forKey: .name))?.trimmingCharacters(in: .whitespacesAndNewlines)
        name = (decodedName?.isEmpty == false ? decodedName! : "Folder")
        sortOrder = try c.decodeIfPresent(Int.self, forKey: .sortOrder) ?? 0
    }
}

/// What a vault or folder operation actually changed, so a confirmation can
/// name its effect before it happens and a status line can report it
/// afterwards without either one guessing.
public struct VaultOrganizationEffect: Equatable, Sendable {
    public var vaults = 0
    public var folders = 0
    public var itemsMoved = 0

    public init(vaults: Int = 0, folders: Int = 0, itemsMoved: Int = 0) {
        self.vaults = vaults
        self.folders = folders
        self.itemsMoved = itemsMoved
    }
}

/// Every vault and folder mutation, as pure functions over `VaultageMetadata`.
///
/// They are written in the same shape as `MetadataRemoval` and for the same
/// reason: the caller runs them inside one `MetadataStore.update`, so each one
/// is serialized by the actor and by the cross-process file lock, and a refusal
/// leaves the file untouched.
public enum VaultOrganization {
    // MARK: - Validation

    public static func validatedName(_ raw: String, limit: Int = Vault.maximumNameLength, subject: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultageError.invalidInput("A \(subject) name is required.") }
        guard trimmed.count <= limit else { throw VaultageError.invalidInput("A \(subject) name may be at most \(limit) characters.") }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("A \(subject) name cannot contain control characters.")
        }
        return trimmed
    }

    /// The vault a caller may write into: it exists, it is not archived, and
    /// this build understands its kind.
    public static func requireWritableVault(_ id: UUID, in state: VaultageMetadata) throws -> Vault {
        guard let vault = state.vaults.first(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That vault no longer exists.")
        }
        guard !vault.isArchived else { throw VaultageError.policyDenied("\(vault.name) is archived. Unarchive it before changing what it holds.") }
        guard vault.kind.isWritable else {
            throw VaultageError.policyDenied("\(vault.name) is not a local vault, so Vaultage cannot file items into it from here.")
        }
        return vault
    }

    // MARK: - Vaults

    @discardableResult
    public static func createVault(name: String, kind: VaultKind = .local, id: UUID = UUID(), createdAt: Date = .now, in state: inout VaultageMetadata) throws -> Vault {
        let name = try validatedName(name, subject: "vault")
        guard !state.vaults.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("That vault already exists.") }
        guard !state.vaults.contains(where: { $0.name.localizedCaseInsensitiveCompare(name) == .orderedSame }) else {
            throw VaultageError.invalidInput("A vault called \(name) already exists.")
        }
        guard state.vaults.count < 64 else { throw VaultageError.policyDenied("Vaultage holds at most 64 vaults.") }
        let vault = Vault(id: id, name: name, kind: kind, createdAt: createdAt)
        state.vaults.append(vault)
        return vault
    }

    public static func renameVault(_ id: UUID, to name: String, in state: inout VaultageMetadata) throws {
        let name = try validatedName(name, subject: "vault")
        guard let index = state.vaults.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That vault no longer exists.")
        }
        guard !state.vaults.contains(where: { $0.id != id && $0.name.localizedCaseInsensitiveCompare(name) == .orderedSame }) else {
            throw VaultageError.invalidInput("A vault called \(name) already exists.")
        }
        state.vaults[index].name = name
    }

    public static func setVaultArchived(_ id: UUID, archived: Bool, at now: Date = .now, in state: inout VaultageMetadata) throws {
        guard let index = state.vaults.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That vault no longer exists.")
        }
        if archived {
            // Archiving the last vault a human could still use would leave the
            // rail with nothing selectable and nowhere to add an item.
            let remaining = state.vaults.filter { $0.id != id && !$0.isArchived }
            guard !remaining.isEmpty else { throw VaultageError.policyDenied("At least one vault must stay unarchived.") }
            state.vaults[index].archivedAt = now
            if state.activeVaultID == id { state.activeVaultID = remaining[0].id }
        } else {
            state.vaults[index].archivedAt = nil
        }
    }

    /// Deletes a vault.
    ///
    /// A vault that still holds items is refused unless the caller names
    /// another vault to move them into — the acceptance criterion that a
    /// delete must not strand an item. Moving is metadata only: each item
    /// keeps its Keychain account, its credential version and every connection,
    /// binding and runtime authorization that names it, and lands at the root
    /// of the destination vault because its folder does not exist there.
    @discardableResult
    public static func deleteVault(_ id: UUID, movingItemsTo destinationID: UUID? = nil, in state: inout VaultageMetadata) throws -> VaultOrganizationEffect {
        guard state.vaults.contains(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That vault no longer exists.")
        }
        guard state.vaults.filter({ $0.id != id }).contains(where: { !$0.isArchived }) else {
            throw VaultageError.policyDenied("At least one vault must remain.")
        }
        let itemIDs = Set(state.vaultItems.filter { $0.vaultID == id }.map(\.id))
        var effect = VaultOrganizationEffect()
        if !itemIDs.isEmpty {
            guard let destinationID else {
                throw VaultageError.policyDenied("This vault still holds \(itemIDs.count) protected item\(itemIDs.count == 1 ? "" : "s"). Choose another vault to move them into, or delete them first.")
            }
            guard destinationID != id else { throw VaultageError.invalidInput("Choose a different vault to move the items into.") }
            _ = try requireWritableVault(destinationID, in: state)
            // A value that is being deleted must not be re-filed underneath
            // the human's confirmation: the reservation is the authority here,
            // exactly as it is for a connection or a runtime authorization.
            guard !state.vaultItemDeletionReservations.contains(where: { itemIDs.contains($0.vaultItemID) }) else {
                throw VaultageError.policyDenied("A protected deletion is pending for an item in this vault. Finish or retry that deletion first.")
            }
            for index in state.vaultItems.indices where state.vaultItems[index].vaultID == id {
                state.vaultItems[index].vaultID = destinationID
                state.vaultItems[index].folderID = nil
                effect.itemsMoved += 1
            }
        }
        effect.folders = state.folders.filter { $0.vaultID == id }.count
        state.folders.removeAll { $0.vaultID == id }
        state.vaults.removeAll { $0.id == id }
        effect.vaults = 1
        if state.activeVaultID == id {
            state.activeVaultID = (state.vaults.first { !$0.isArchived } ?? state.vaults[0]).id
        }
        return effect
    }

    public static func setActiveVault(_ id: UUID, in state: inout VaultageMetadata) throws {
        guard let vault = state.vaults.first(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That vault no longer exists.")
        }
        guard !vault.isArchived else { throw VaultageError.policyDenied("\(vault.name) is archived. Unarchive it to make it active.") }
        state.activeVaultID = id
    }

    // MARK: - Folders

    @discardableResult
    public static func createFolder(vaultID: UUID, parentID: UUID? = nil, name: String, id: UUID = UUID(), in state: inout VaultageMetadata) throws -> Folder {
        let name = try validatedName(name, limit: Folder.maximumNameLength, subject: "folder")
        _ = try requireWritableVault(vaultID, in: state)
        guard !state.folders.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("That folder already exists.") }
        if let parentID {
            guard let parent = state.folders.first(where: { $0.id == parentID }) else {
                throw VaultageError.invalidInput("The parent folder no longer exists.")
            }
            guard parent.vaultID == vaultID else {
                throw VaultageError.invalidInput("A folder cannot be created under a parent in another vault.")
            }
            guard try depth(ofFolder: parentID, in: state) < Folder.maximumDepth else {
                throw VaultageError.policyDenied("Folders may be nested at most \(Folder.maximumDepth) levels deep.")
            }
        }
        guard !state.folders.contains(where: { $0.vaultID == vaultID && $0.parentID == parentID && $0.name.localizedCaseInsensitiveCompare(name) == .orderedSame }) else {
            throw VaultageError.invalidInput("A folder called \(name) is already here.")
        }
        let order = (state.folders.filter { $0.vaultID == vaultID && $0.parentID == parentID }.map(\.sortOrder).max() ?? -1) + 1
        let folder = Folder(id: id, vaultID: vaultID, parentID: parentID, name: name, sortOrder: order)
        state.folders.append(folder)
        return folder
    }

    public static func renameFolder(_ id: UUID, to name: String, in state: inout VaultageMetadata) throws {
        let name = try validatedName(name, limit: Folder.maximumNameLength, subject: "folder")
        guard let index = state.folders.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That folder no longer exists.")
        }
        let folder = state.folders[index]
        _ = try requireWritableVault(folder.vaultID, in: state)
        guard !state.folders.contains(where: { $0.id != id && $0.vaultID == folder.vaultID && $0.parentID == folder.parentID && $0.name.localizedCaseInsensitiveCompare(name) == .orderedSame }) else {
            throw VaultageError.invalidInput("A folder called \(name) is already here.")
        }
        state.folders[index].name = name
    }

    /// Moves a folder under another folder in the same vault, or to the vault
    /// root when `parentID` is nil.
    ///
    /// Refused when the destination is the folder itself or one of its own
    /// descendants (the cycle rule), when it is in another vault, and when the
    /// move would push any folder in the moved subtree past the depth bound.
    public static func moveFolder(_ id: UUID, toParent parentID: UUID?, in state: inout VaultageMetadata) throws {
        guard let index = state.folders.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That folder no longer exists.")
        }
        let folder = state.folders[index]
        _ = try requireWritableVault(folder.vaultID, in: state)
        guard folder.parentID != parentID else { return }
        var parentDepth = 0
        if let parentID {
            guard parentID != id else { throw VaultageError.invalidInput("A folder cannot be moved inside itself.") }
            guard let parent = state.folders.first(where: { $0.id == parentID }) else {
                throw VaultageError.invalidInput("The destination folder no longer exists.")
            }
            guard parent.vaultID == folder.vaultID else {
                throw VaultageError.invalidInput("A folder cannot be moved into another vault.")
            }
            guard !descendants(of: id, in: state).contains(parentID) else {
                throw VaultageError.invalidInput("A folder cannot be moved inside one of its own folders.")
            }
            parentDepth = try depth(ofFolder: parentID, in: state)
        }
        let subtreeHeight = height(of: id, in: state)
        guard parentDepth + subtreeHeight <= Folder.maximumDepth else {
            throw VaultageError.policyDenied("That move would nest folders more than \(Folder.maximumDepth) levels deep.")
        }
        guard !state.folders.contains(where: { $0.id != id && $0.vaultID == folder.vaultID && $0.parentID == parentID && $0.name.localizedCaseInsensitiveCompare(folder.name) == .orderedSame }) else {
            throw VaultageError.invalidInput("A folder called \(folder.name) is already there.")
        }
        state.folders[index].parentID = parentID
        state.folders[index].sortOrder = (state.folders.filter { $0.id != id && $0.vaultID == folder.vaultID && $0.parentID == parentID }.map(\.sortOrder).max() ?? -1) + 1
    }

    /// Deletes one folder.
    ///
    /// With `movingContentsToParent` false, a folder that still holds folders
    /// or items is refused rather than silently emptied. With it true, the
    /// child folders and the items move up one level — to the deleted folder's
    /// own parent, or to the vault root — and nothing is deleted but the
    /// folder record itself. No Keychain record is touched either way.
    @discardableResult
    public static func deleteFolder(_ id: UUID, movingContentsToParent: Bool, in state: inout VaultageMetadata) throws -> VaultOrganizationEffect {
        guard let folder = state.folders.first(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That folder no longer exists.")
        }
        _ = try requireWritableVault(folder.vaultID, in: state)
        let childFolders = state.folders.filter { $0.parentID == id }
        let itemIDs = state.vaultItems.filter { $0.folderID == id }.map(\.id)
        var effect = VaultOrganizationEffect()
        guard movingContentsToParent || (childFolders.isEmpty && itemIDs.isEmpty) else {
            throw VaultageError.policyDenied("\(folder.name) still holds \(childFolders.count) folder\(childFolders.count == 1 ? "" : "s") and \(itemIDs.count) item\(itemIDs.count == 1 ? "" : "s"). Move them up a level, or empty the folder first.")
        }
        for index in state.folders.indices where state.folders[index].parentID == id {
            state.folders[index].parentID = folder.parentID
        }
        for index in state.vaultItems.indices where state.vaultItems[index].folderID == id {
            state.vaultItems[index].folderID = folder.parentID
            effect.itemsMoved += 1
        }
        state.folders.removeAll { $0.id == id }
        effect.folders = 1
        return effect
    }

    // MARK: - Items

    /// Files one item into a vault and optionally a folder. Metadata only: the
    /// Keychain account and the credential version are not read, not written
    /// and not compared here, because nothing about the value changes.
    public static func moveItem(_ id: UUID, toVault vaultID: UUID, folder folderID: UUID?, in state: inout VaultageMetadata) throws {
        guard let index = state.vaultItems.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("The protected vault item no longer exists.")
        }
        guard MetadataRemoval.deletionReservation(forVaultItem: id, in: state) == nil else {
            throw VaultageError.policyDenied("A protected deletion is pending for this item, so it cannot be moved.")
        }
        _ = try requireWritableVault(vaultID, in: state)
        if let folderID {
            guard let folder = state.folders.first(where: { $0.id == folderID }) else {
                throw VaultageError.invalidInput("That folder no longer exists.")
            }
            guard folder.vaultID == vaultID else {
                throw VaultageError.invalidInput("That folder is in another vault.")
            }
        }
        state.vaultItems[index].vaultID = vaultID
        state.vaultItems[index].folderID = folderID
    }

    // MARK: - Tree walks

    /// Depth of a folder, counting the vault root as 0. Bounded by the folder
    /// count so a hand-edited parent cycle terminates instead of hanging.
    public static func depth(ofFolder id: UUID, in state: VaultageMetadata) throws -> Int {
        var depth = 0
        var cursor: UUID? = id
        var seen = Set<UUID>()
        while let current = cursor {
            guard seen.insert(current).inserted else {
                throw VaultageError.storage("The folder tree contains a cycle and was not changed.")
            }
            guard let folder = state.folders.first(where: { $0.id == current }) else { break }
            depth += 1
            cursor = folder.parentID
        }
        return depth
    }

    /// Every folder below `id`, not including it.
    public static func descendants(of id: UUID, in state: VaultageMetadata) -> Set<UUID> {
        var found = Set<UUID>()
        var frontier = [id]
        while let current = frontier.popLast() {
            for child in state.folders where child.parentID == current && !found.contains(child.id) && child.id != id {
                found.insert(child.id)
                frontier.append(child.id)
            }
        }
        return found
    }

    /// How many levels the subtree rooted at `id` occupies, including `id`.
    public static func height(of id: UUID, in state: VaultageMetadata) -> Int {
        var height = 1
        var level = [id]
        var seen: Set<UUID> = [id]
        while !level.isEmpty {
            var next: [UUID] = []
            for parent in level {
                for child in state.folders where child.parentID == parent && seen.insert(child.id).inserted {
                    next.append(child.id)
                }
            }
            if next.isEmpty { break }
            height += 1
            level = next
            if height > Folder.maximumDepth * 2 { break }
        }
        return height
    }

    /// The folder names from the vault root down to `id`, for a breadcrumb.
    public static func path(toFolder id: UUID, in state: VaultageMetadata) -> [Folder] {
        var path: [Folder] = []
        var cursor: UUID? = id
        var seen = Set<UUID>()
        while let current = cursor, seen.insert(current).inserted {
            guard let folder = state.folders.first(where: { $0.id == current }) else { break }
            path.insert(folder, at: 0)
            cursor = folder.parentID
        }
        return path
    }

    // MARK: - Migration and repair

    /// Makes the stored tree coherent, in place, without ever dropping an item.
    ///
    /// This is the schema-12 migration and the repair pass for a hand-edited or
    /// partially written file, and it is the same code for both so there is
    /// only one definition of "coherent":
    ///
    /// - at least one vault exists (the default `Personal` one, if the file
    ///   named none);
    /// - every folder belongs to a vault that exists, and to a parent in the
    ///   same vault, at a depth within the bound and with no parent cycle;
    /// - every item belongs to a vault that exists and to a folder in that same
    ///   vault, or to no folder. **An item is never deleted here**: a dangling
    ///   reference re-homes the item to the default vault's root, because the
    ///   Keychain record behind it is real whatever the tree says.
    /// - the active vault exists and is not archived.
    public static func normalize(_ state: inout VaultageMetadata, at now: Date = .now) {
        if state.vaults.isEmpty {
            state.vaults = [Vault.personal(createdAt: now)]
        }
        if !state.vaults.contains(where: { !$0.isArchived }) {
            // Everything was archived by an edit. Unarchive the first, rather
            // than leaving a rail with no usable vault.
            state.vaults[0].archivedAt = nil
        }
        let vaultIDs = Set(state.vaults.map(\.id))
        let fallbackVaultID = (state.vaults.first { $0.id == Vault.defaultID && !$0.isArchived }
                               ?? state.vaults.first { !$0.isArchived }
                               ?? state.vaults[0]).id

        // Folders: drop those whose vault is gone (a folder holds nothing of
        // its own), then straighten parentage.
        state.folders.removeAll { !vaultIDs.contains($0.vaultID) }
        let foldersByID = Dictionary(state.folders.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for index in state.folders.indices {
            guard let parentID = state.folders[index].parentID else { continue }
            if parentID == state.folders[index].id || foldersByID[parentID]?.vaultID != state.folders[index].vaultID {
                state.folders[index].parentID = nil
            }
        }
        // Cycles and over-deep chains are cut at the offending folder rather
        // than by deleting anything.
        for index in state.folders.indices {
            var cursor = state.folders[index].parentID
            var seen: Set<UUID> = [state.folders[index].id]
            var depth = 1
            while let current = cursor {
                guard seen.insert(current).inserted, depth < Folder.maximumDepth,
                      let parent = state.folders.first(where: { $0.id == current }) else {
                    state.folders[index].parentID = nil
                    break
                }
                depth += 1
                cursor = parent.parentID
            }
        }

        // Items: re-home, never remove.
        let liveFolders = Dictionary(state.folders.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for index in state.vaultItems.indices {
            if !vaultIDs.contains(state.vaultItems[index].vaultID) {
                state.vaultItems[index].vaultID = fallbackVaultID
                state.vaultItems[index].folderID = nil
            }
            if let folderID = state.vaultItems[index].folderID,
               liveFolders[folderID]?.vaultID != state.vaultItems[index].vaultID {
                state.vaultItems[index].folderID = nil
            }
        }

        if !vaultIDs.contains(state.activeVaultID) || state.vaults.first(where: { $0.id == state.activeVaultID })?.isArchived == true {
            state.activeVaultID = fallbackVaultID
        }

        // BL-079. The per-item half of the same pass: field names, the
        // one-primary rule, the secret/metadata exclusion and the attachment
        // bounds. It runs here, on every decode, for the same reason the tree
        // repair does — there must be exactly one definition of a coherent
        // record, and it must be applied whether the file came from an older
        // schema, a newer one, or a text editor.
        for index in state.vaultItems.indices {
            VaultItemTypes.normalize(&state.vaultItems[index])
        }
    }
}
