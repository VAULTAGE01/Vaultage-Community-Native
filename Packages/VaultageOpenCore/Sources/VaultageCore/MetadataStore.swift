import Foundation
import Darwin

/// A versioned JSON store. The actor serializes this process; flock protects the
/// short read-modify-write critical section if another Vaultage process exists.
///
/// **What it is not** (audit M-06): an authenticated store. `metadata.json` is a
/// same-user-writable file, and nothing here detects an edit made by another
/// process running as the owner. The two things that must survive such an
/// edit are protected on their own terms — a grant by its MAC under the
/// broker-only key (BL-136 step 1) and a revocation by the anchor outside the
/// file (audit H-08). Everything else in the file is configuration the owner
/// may edit, and a same-user writer *is* the owner for this purpose.
public actor MetadataStore {
    private let fileURL: URL
    private let lockURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    /// Nonisolated because it is immutable, `Sendable`, and read by every
    /// composition that has to build a sibling store in the same directory —
    /// the receipt log and, since BL-079, the sealed attachment store.
    public nonisolated let directory: URL

    /// The schema number this store accepts, which is `VaultageMetadata`'s in
    /// every shipped composition.
    ///
    /// It is a parameter for exactly one reason: `metadataAtSchema17IsRefusedByASchema16Build`
    /// (BL-099, DB-H36) has to be able to *be* a schema-16 build, and a constant
    /// cannot be lowered at runtime. Without it that test degrades to asserting
    /// the constant against itself, which is the defect §12 item 9 records for
    /// `currentPolicyRevision` and the exact reason the gate moved to 17.
    /// Nothing in the product passes it.
    private let supportedSchemaVersion: Int

    public init(directory: URL = MetadataStore.defaultDirectory) {
        self.init(directory: directory, supportedSchemaVersion: VaultageMetadata.schemaVersion)
    }

    public init(directory: URL, supportedSchemaVersion: Int) {
        self.supportedSchemaVersion = supportedSchemaVersion
        self.directory = directory
        self.fileURL = directory.appendingPathComponent("metadata.json")
        self.lockURL = directory.appendingPathComponent("metadata.lock")
        self.encoder = JSONEncoder(); self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; self.encoder.dateEncodingStrategy = .iso8601
        self.decoder = JSONDecoder(); self.decoder.dateDecodingStrategy = .iso8601
    }

    /// The Info.plist key `Scripts/build-app.sh` writes, and the one value that
    /// means "this bundle was signed as a production release". Read the same way
    /// `BrokerComposition` and the Settings view read it: from observable facts
    /// about the running bundle, never from an argument or an environment
    /// variable an agent could influence.
    public static let buildChannelInfoKey = "VaultageBuildChannel"
    public static let productionBuildChannel = "production-signed"

    /// Development-only override of the metadata directory.
    ///
    /// Without it, screenshot seeding, the MCP smoke test and any throwaway tool
    /// all write the owner's real
    /// `~/Library/Application Support/VaultageFoundation20260910`, and two lanes
    /// running at once corrupt each other's state — observed and recorded in
    /// `blueprint/evidence/ui-lane-bl067-2026-09-11.md` §6. Redirecting `HOME`
    /// does not work: Foundation resolves the home directory from `getpwuid`
    /// and ignores `$HOME` (same note, §5).
    ///
    /// A production-signed bundle ignores this variable entirely, so it cannot
    /// be used to point a shipped release at an attacker-chosen directory.
    public static let directoryOverrideEnvironmentKey = "VAULTAGE_METADATA_DIRECTORY"

    /// The build channel of a bundle, or `nil` when the bundle declares none
    /// (self-tests, `swift run`, and unsigned development builds).
    public static func buildChannel(of bundle: Bundle = .main) -> String? {
        bundle.object(forInfoDictionaryKey: buildChannelInfoKey) as? String
    }

    /// The store directory, honouring `VAULTAGE_METADATA_DIRECTORY` only when
    /// `bundle` is not a production-signed build. The receipt store follows it:
    /// `ReceiptStore` defaults to `MetadataStore.defaultDirectory`, and a broker
    /// built with an explicit store uses that store's `directory`.
    public static func resolvedDirectory(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        bundle: Bundle = .main
    ) -> URL {
        guard buildChannel(of: bundle) != productionBuildChannel,
              let override = environment[directoryOverrideEnvironmentKey],
              !override.isEmpty
        else { return standardDirectory }
        return URL(fileURLWithPath: (override as NSString).expandingTildeInPath, isDirectory: true).standardizedFileURL
    }

    /// The real per-user location. A production-signed build always uses it.
    public static var standardDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("VaultageFoundation20260910", isDirectory: true)
    }

    public static var defaultDirectory: URL { resolvedDirectory() }

    public func load() throws -> VaultageMetadata {
        try withLock { try loadUnlocked() }
    }

    @discardableResult public func update(_ body: @Sendable (inout VaultageMetadata) throws -> Void) throws -> VaultageMetadata {
        try withLock {
            var value = try loadUnlocked()
            try body(&value)
            value.schemaVersion = supportedSchemaVersion
            try saveUnlocked(value)
            return value
        }
    }

    /// Runs a short, locked metadata mutation and returns a value derived from
    /// the same committed state. This avoids reopening a race after a caller
    /// reserves a record for an OS-controlled operation.
    @discardableResult public func updateResult<T: Sendable>(_ body: @Sendable (inout VaultageMetadata) throws -> T) throws -> T {
        try withLock {
            var value = try loadUnlocked()
            let result = try body(&value)
            value.schemaVersion = supportedSchemaVersion
            try saveUnlocked(value)
            return result
        }
    }

    private func loadUnlocked() throws -> VaultageMetadata {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return VaultageMetadata() }
        do {
            let value = try decoder.decode(VaultageMetadata.self, from: Data(contentsOf: fileURL))
            guard value.schemaVersion <= supportedSchemaVersion else { throw VaultageError.storage("Unsupported local metadata version.") }
            return value
        } catch let error as VaultageError { throw error }
          catch { throw VaultageError.storage("Could not read local metadata: \(error.localizedDescription)") }
    }

    private func saveUnlocked(_ value: VaultageMetadata) throws {
        do {
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fileURL.deletingLastPathComponent().path)
            let data = try encoder.encode(value)
            let temporary = fileURL.deletingLastPathComponent().appendingPathComponent("metadata-\(UUID().uuidString).tmp")
            try data.write(to: temporary, options: [.atomic])
            _ = try FileManager.default.replaceItemAt(fileURL, withItemAt: temporary, backupItemName: nil, options: [])
        } catch CocoaError.fileNoSuchFile {
            do { try encoder.encode(value).write(to: fileURL, options: [.atomic]); try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path) }
            catch { throw VaultageError.storage("Could not save local metadata: \(error.localizedDescription)") }
        } catch { throw VaultageError.storage("Could not save local metadata: \(error.localizedDescription)") }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: lockURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw VaultageError.storage("Could not lock local metadata.") }
        _ = fchmod(fd, S_IRUSR | S_IWUSR)
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw VaultageError.storage("Could not lock local metadata.") }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
}

/// Small, relationship-aware metadata mutations used by the desktop's local
/// management controls. These functions never touch Keychain records: callers
/// must coordinate protected-value deletion separately so a failed Keychain
/// operation cannot make metadata claim a value was removed.
public struct MetadataRemovalEffect: Equatable, Sendable {
    public var projects = 0
    public var environments = 0
    public var connections = 0
    public var bindings = 0
    public var vaultItems = 0
    public var sourceAuthorizations = 0
    public var runtimeInjections = 0

    public init() {}
}

public enum MetadataRemoval {
    public static func project(_ id: UUID, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.projects.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("The project no longer exists.") }
        let environmentIDs = Set(state.environments.filter { $0.projectID == id }.map(\.id))
        let bindingIDs = Set(state.bindings.filter { $0.projectID == id || environmentIDs.contains($0.environmentID) }.map(\.id))
        var effect = MetadataRemovalEffect()
        effect.projects = remove(&state.projects) { $0.id == id }
        effect.environments = remove(&state.environments) { environmentIDs.contains($0.id) }
        effect.bindings = remove(&state.bindings) { bindingIDs.contains($0.id) }
        effect.sourceAuthorizations = remove(&state.runtimeSourceAuthorizations) {
            $0.projectID == id || environmentIDs.contains($0.environmentID) || bindingIDs.contains($0.bindingID)
        }
        effect.runtimeInjections = remove(&state.runtimeInjectionAuthorizations) {
            $0.projectID == id || environmentIDs.contains($0.environmentID)
        }
        return effect
    }

    public static func environment(_ id: UUID, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.environments.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("The environment no longer exists.") }
        let bindingIDs = Set(state.bindings.filter { $0.environmentID == id }.map(\.id))
        var effect = MetadataRemovalEffect()
        effect.environments = remove(&state.environments) { $0.id == id }
        effect.bindings = remove(&state.bindings) { bindingIDs.contains($0.id) }
        effect.sourceAuthorizations = remove(&state.runtimeSourceAuthorizations) { $0.environmentID == id || bindingIDs.contains($0.bindingID) }
        effect.runtimeInjections = remove(&state.runtimeInjectionAuthorizations) { $0.environmentID == id }
        return effect
    }

    public static func binding(_ id: UUID, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.bindings.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("The binding no longer exists.") }
        var effect = MetadataRemovalEffect()
        effect.bindings = remove(&state.bindings) { $0.id == id }
        effect.sourceAuthorizations = remove(&state.runtimeSourceAuthorizations) { $0.bindingID == id }
        return effect
    }

    public static func connection(_ id: UUID, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.connections.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("The connection no longer exists.") }
        let bindingIDs = Set(state.bindings.filter { $0.connectionID == id }.map(\.id))
        var effect = MetadataRemovalEffect()
        effect.connections = remove(&state.connections) { $0.id == id }
        effect.bindings = remove(&state.bindings) { bindingIDs.contains($0.id) }
        effect.sourceAuthorizations = remove(&state.runtimeSourceAuthorizations) { bindingIDs.contains($0.bindingID) }
        state.freeActiveConnectionIDs.remove(id)
        return effect
    }

    public static func references(toVaultItem id: UUID, in state: VaultageMetadata) -> (connections: Int, sourceAuthorizations: Int, runtimeInjections: Int) {
        (state.connections.filter { $0.vaultItemID == id }.count,
         state.runtimeSourceAuthorizations.filter { $0.sourceVaultItemID == id }.count,
         state.runtimeInjectionAuthorizations.filter { $0.vaultItemID == id }.count)
    }

    public static func deletionReservation(forVaultItem id: UUID, in state: VaultageMetadata) -> VaultItemDeletionReservation? {
        state.vaultItemDeletionReservations.first { $0.vaultItemID == id }
    }

    public static func requireUsableVaultItem(_ id: UUID, in state: VaultageMetadata) throws -> VaultItem {
        guard let item = state.vaultItems.first(where: { $0.id == id }) else { throw VaultageError.invalidInput("The protected vault item no longer exists.") }
        guard deletionReservation(forVaultItem: id, in: state) == nil else { throw VaultageError.policyDenied("The protected vault item is being deleted and cannot be used.") }
        return item
    }

    public static func reserveVaultItemDeletion(_ id: UUID, in state: inout VaultageMetadata) throws -> VaultItemDeletionReservation {
        guard let item = state.vaultItems.first(where: { $0.id == id }) else { throw VaultageError.invalidInput("The protected vault item no longer exists.") }
        guard deletionReservation(forVaultItem: id, in: state) == nil else { throw VaultageError.policyDenied("Deletion of this protected vault item is already pending.") }
        let references = references(toVaultItem: id, in: state)
        guard references.connections == 0, references.sourceAuthorizations == 0, references.runtimeInjections == 0 else {
            throw VaultageError.policyDenied("Detach its \(references.connections) connection(s), \(references.sourceAuthorizations) runtime source authorization(s), and \(references.runtimeInjections) runtime injection authorization(s) before deleting this protected vault item.")
        }
        let reservation = VaultItemDeletionReservation(vaultItemID: item.id, keychainAccount: item.keychainAccount, credentialVersion: item.credentialVersion)
        state.vaultItemDeletionReservations.append(reservation)
        return reservation
    }

    public static func clearVaultItemDeletionReservation(_ reservation: VaultItemDeletionReservation, from state: inout VaultageMetadata) throws {
        guard let item = state.vaultItems.first(where: { $0.id == reservation.vaultItemID }), item.keychainAccount == reservation.keychainAccount, item.credentialVersion == reservation.credentialVersion,
              state.vaultItemDeletionReservations.contains(reservation) else {
            throw VaultageError.policyDenied("The protected vault item changed while deletion was awaiting authentication.")
        }
        _ = remove(&state.vaultItemDeletionReservations) { $0.id == reservation.id }
    }

    public static func finalizeVaultItemDeletion(_ reservation: VaultItemDeletionReservation, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.vaultItemDeletionReservations.contains(reservation),
              let item = state.vaultItems.first(where: { $0.id == reservation.vaultItemID }),
              item.keychainAccount == reservation.keychainAccount,
              item.credentialVersion == reservation.credentialVersion else {
            throw VaultageError.policyDenied("The protected vault item changed while deletion was awaiting authentication. Metadata was retained.")
        }
        let references = references(toVaultItem: reservation.vaultItemID, in: state)
        guard references.connections == 0, references.sourceAuthorizations == 0, references.runtimeInjections == 0 else {
            throw VaultageError.policyDenied("A new connection or runtime authorization was added while deletion was awaiting authentication. Metadata was retained.")
        }
        var effect = MetadataRemovalEffect()
        effect.vaultItems = remove(&state.vaultItems) { $0.id == reservation.vaultItemID }
        _ = remove(&state.vaultItemDeletionReservations) { $0.id == reservation.id }
        return effect
    }

    public static func vaultItem(_ id: UUID, from state: inout VaultageMetadata) throws -> MetadataRemovalEffect {
        guard state.vaultItems.contains(where: { $0.id == id }) else { throw VaultageError.invalidInput("The protected vault item no longer exists.") }
        guard deletionReservation(forVaultItem: id, in: state) == nil else { throw VaultageError.policyDenied("Deletion of this protected vault item is already pending.") }
        let references = references(toVaultItem: id, in: state)
        guard references.connections == 0, references.sourceAuthorizations == 0, references.runtimeInjections == 0 else {
            throw VaultageError.policyDenied("Detach its \(references.connections) connection(s), \(references.sourceAuthorizations) runtime source authorization(s), and \(references.runtimeInjections) runtime injection authorization(s) before deleting this protected vault item.")
        }
        var effect = MetadataRemovalEffect()
        effect.vaultItems = remove(&state.vaultItems) { $0.id == id }
        return effect
    }

    private static func remove<T>(_ values: inout [T], where predicate: (T) -> Bool) -> Int {
        let before = values.count
        values.removeAll(where: predicate)
        return before - values.count
    }
}
