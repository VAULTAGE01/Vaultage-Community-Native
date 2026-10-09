import Foundation
import VaultageCore

/// Accountless local storage. Metadata contains labels and UUID references only.
/// Keychain accounts are derived here, never accepted from a metadata document.
public actor CommunityStore {
    public static let defaultDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("VaultageCommunityV2", isDirectory: true).resolvingSymlinksInPath()
    static let accountPrefix = "community-v2.secret."
    static let maximumValueBytes = 64 * 1024
    static let maximumMetadataBytes = 4 * 1024 * 1024
    private let directory: URL
    private let vault: any SecretVault
    private let metadataWriteCheck: (@Sendable () throws -> Void)?
    private let exportPublicationCheck: (@Sendable () throws -> Void)?

    public init(directory: URL = CommunityStore.defaultDirectory, vault: any SecretVault = KeychainVault()) {
        self.directory = directory
        self.vault = vault
        self.metadataWriteCheck = nil
        self.exportPublicationCheck = nil
    }

    /// Test SPI for deterministic disk-write failure tests; not part of the public
    /// UI API. The normal app initializer always uses real persistence. The seam
    /// can only refuse a write; it cannot redirect metadata or bypass the vault.
    @_spi(CommunityTesting)
    public init(directory: URL, vault: any SecretVault, metadataWriteCheck: @escaping @Sendable () throws -> Void,
                exportPublicationCheck: (@Sendable () throws -> Void)? = nil) {
        self.directory = directory
        self.vault = vault
        self.metadataWriteCheck = metadataWriteCheck
        self.exportPublicationCheck = exportPublicationCheck
    }

    public func snapshot() throws -> CommunitySnapshot {
        try withWorkspace { workspace in try load(workspace) }
    }

    public func createSecret(title: String, kind: SecretKind, folder: String, value: Data) throws -> SecretSummary {
        let title = try Self.label(title)
        let folder = try Self.label(folder, emptyAllowed: true, maximum: 512)
        let protected = VaultSecret(value)
        guard value.count > 0, value.count <= Self.maximumValueBytes, protected.isValidUTF8 else {
            throw CommunityError.invalidValue
        }
        return try withWorkspace { workspace in
            var state = try load(workspace)
            let summary = SecretSummary(title: title, kind: kind, folder: folder)
            state.secrets.append(summary)
            try validate(state)
            let data = try encode(state)
            // Stage and replace metadata first; no Keychain mutation is attempted
            // until every fallible metadata write has completed. A failed Keychain
            // operation atomically restores the label-only previous document.
            try workspace.replace(data, protectingExternalMutation: true) {
                do { try vault.save(value, account: Self.account(for: summary.id)) }
                catch { throw CommunityError.protectedValueUnavailable }
            }
            return summary
        }
    }

    public func deleteSecret(id: UUID) throws {
        try withWorkspace { workspace in
            var state = try load(workspace)
            guard state.secrets.contains(where: { $0.id == id }) else { throw CommunityError.notFound }
            state.secrets.removeAll { $0.id == id }
            for project in state.projects.indices {
                for environment in state.projects[project].environments.indices {
                    state.projects[project].environments[environment].bindings.removeAll { $0.secretID == id }
                }
            }
            try workspace.replace(try encode(state), protectingExternalMutation: true) {
                do { try vault.delete(account: Self.account(for: id)) }
                catch { throw CommunityError.protectedValueUnavailable }
            }
        }
    }

    /// Call only from an explicit human Reveal/Copy action. KeychainVault creates
    /// a fresh LAContext and preserves its .userPresence access control.
    public func readSecret(id: UUID, prompt: String) throws -> VaultSecret {
        let prompt = try Self.label(prompt, maximum: 300)
        return try withWorkspace { workspace in
            guard try load(workspace).secrets.contains(where: { $0.id == id }) else { throw CommunityError.notFound }
            do { return try vault.read(account: Self.account(for: id), prompt: prompt) }
            catch { throw CommunityError.protectedValueUnavailable }
        }
    }

    public func createProject(name: String) throws -> CommunityProject {
        let name = try Self.label(name)
        return try withWorkspace { workspace in
            var state = try load(workspace)
            guard !state.projects.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
                throw CommunityError.duplicateProject
            }
            let project = CommunityProject(name: name, environments: ["Development", "Staging", "Production"].map { ProjectEnvironment(name: $0) })
            state.projects.append(project)
            try validate(state)
            try workspace.replace(try encode(state))
            return project
        }
    }

    public func deleteProject(id: UUID) throws {
        try withWorkspace { workspace in
            var state = try load(workspace)
            guard state.projects.contains(where: { $0.id == id }) else { throw CommunityError.notFound }
            state.projects.removeAll { $0.id == id }
            try workspace.replace(try encode(state))
        }
    }

    public func setBinding(projectID: UUID, environmentID: UUID, key: String, secretID: UUID) throws {
        guard Self.isEnvironmentKey(key) else { throw CommunityError.invalidEnvironmentKey }
        try mutateEnvironment(projectID: projectID, environmentID: environmentID) { environment, state in
            guard state.secrets.contains(where: { $0.id == secretID }) else { throw CommunityError.notFound }
            if let index = environment.bindings.firstIndex(where: { $0.key == key }) {
                environment.bindings[index].secretID = secretID
            } else {
                environment.bindings.append(EnvironmentBinding(key: key, secretID: secretID))
            }
        }
    }

    public func removeBinding(projectID: UUID, environmentID: UUID, bindingID: UUID) throws {
        try mutateEnvironment(projectID: projectID, environmentID: environmentID) { environment, _ in
            guard environment.bindings.contains(where: { $0.id == bindingID }) else { throw CommunityError.notFound }
            environment.bindings.removeAll { $0.id == bindingID }
        }
    }

    /// Deliberate plaintext disclosure, not agent/runtime delivery. Exact human
    /// confirmation is required. The target must be new, owner-only and reached
    /// without symbolic links. One single-quoted assignment is emitted per
    /// binding, using the shared .env/POSIX-shell literal subset. Apostrophes,
    /// backslashes and control characters are refused instead of altered.
    public func exportEnvironment(projectID: UUID, environmentID: UUID, to target: URL, confirmation: String) throws {
        guard confirmation == "EXPORT" else { throw CommunityError.exportConfirmationRequired }
        try withWorkspace { workspace in
            let state = try load(workspace)
            let (projectIndex, environmentIndex) = try Self.location(projectID, environmentID, in: state)
            let bindings = state.projects[projectIndex].environments[environmentIndex].bindings.sorted { $0.key < $1.key }
            let output = ExportBuffer(capacity: Self.maximumMetadataBytes)
            try output.appendPublic("# Plaintext credentials exported by Vaultage Community. Keep this file private.\n")
            // Validate the destination before asking the human to disclose values.
            let destination = try NewExportFile(target, publicationCheck: exportPublicationCheck)
            for binding in bindings {
                let secret: VaultSecret
                do { secret = try vault.read(account: Self.account(for: binding.secretID), prompt: "Export a protected value to a plaintext environment file") }
                catch { throw CommunityError.protectedValueUnavailable }
                try output.appendAssignment(key: binding.key, secret: secret)
            }
            try destination.write(output)
        }
    }

    private func mutateEnvironment(projectID: UUID, environmentID: UUID,
                                   mutation: (inout ProjectEnvironment, CommunitySnapshot) throws -> Void) throws {
        try withWorkspace { workspace in
            var state = try load(workspace)
            let (projectIndex, environmentIndex) = try Self.location(projectID, environmentID, in: state)
            var environment = state.projects[projectIndex].environments[environmentIndex]
            try mutation(&environment, state)
            state.projects[projectIndex].environments[environmentIndex] = environment
            try validate(state)
            try workspace.replace(try encode(state))
        }
    }

    private func withWorkspace<T>(_ body: (MetadataDirectory) throws -> T) throws -> T {
        let workspace = try MetadataDirectory(directory, writeCheck: metadataWriteCheck)
        return try body(workspace)
    }

    private struct Document: Codable {
        let schemaVersion: Int
        let snapshot: CommunitySnapshot
    }

    private func load(_ workspace: MetadataDirectory) throws -> CommunitySnapshot {
        guard let data = try workspace.readMetadata() else { return CommunitySnapshot() }
        let document: Document
        do { document = try JSONDecoder().decode(Document.self, from: data) }
        catch { throw CommunityError.malformedMetadata }
        guard document.schemaVersion == 1 else { throw CommunityError.malformedMetadata }
        do { try validate(document.snapshot) }
        catch { throw CommunityError.malformedMetadata }
        return document.snapshot
    }

    private func encode(_ snapshot: CommunitySnapshot) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do { data = try encoder.encode(Document(schemaVersion: 1, snapshot: snapshot)) }
        catch { throw CommunityError.malformedMetadata }
        guard data.count <= Self.maximumMetadataBytes else { throw CommunityError.malformedMetadata }
        return data
    }

    private func validate(_ snapshot: CommunitySnapshot) throws {
        guard snapshot.secrets.count <= 10_000, snapshot.projects.count <= 10_000 else { throw CommunityError.malformedMetadata }
        var ids = Set<UUID>()
        let secretIDs = Set(snapshot.secrets.map(\.id))
        for secret in snapshot.secrets {
            guard ids.insert(secret.id).inserted, secret.createdAt.timeIntervalSince1970.isFinite,
                  try Self.label(secret.title) == secret.title,
                  try Self.label(secret.folder, emptyAllowed: true, maximum: 512) == secret.folder
            else { throw CommunityError.malformedMetadata }
        }
        var projectNames = Set<String>()
        for project in snapshot.projects {
            guard ids.insert(project.id).inserted, projectNames.insert(project.name.lowercased()).inserted,
                  try Self.label(project.name) == project.name,
                  !project.environments.isEmpty, project.environments.count <= 100
            else { throw CommunityError.malformedMetadata }
            var environmentNames = Set<String>()
            for environment in project.environments {
                guard ids.insert(environment.id).inserted,
                      environmentNames.insert(environment.name.lowercased()).inserted,
                      try Self.label(environment.name) == environment.name, environment.bindings.count <= 10_000
                else { throw CommunityError.malformedMetadata }
                var keys = Set<String>()
                for binding in environment.bindings {
                    guard ids.insert(binding.id).inserted, Self.isEnvironmentKey(binding.key),
                          keys.insert(binding.key).inserted, secretIDs.contains(binding.secretID)
                    else { throw CommunityError.malformedMetadata }
                }
            }
        }
    }

    private static func location(_ projectID: UUID, _ environmentID: UUID, in state: CommunitySnapshot) throws -> (Int, Int) {
        guard let project = state.projects.firstIndex(where: { $0.id == projectID }),
              let environment = state.projects[project].environments.firstIndex(where: { $0.id == environmentID })
        else { throw CommunityError.notFound }
        return (project, environment)
    }

    private static func label(_ value: String, emptyAllowed: Bool = false, maximum: Int = 200) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (emptyAllowed || !trimmed.isEmpty), trimmed.utf8.count <= maximum,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { throw CommunityError.invalidLabel }
        return trimmed
    }

    static func isEnvironmentKey(_ key: String) -> Bool {
        let bytes = Array(key.utf8)
        func letter(_ byte: UInt8) -> Bool { (65...90).contains(byte) || (97...122).contains(byte) || byte == 95 }
        guard let first = bytes.first, bytes.count <= 128, letter(first) else { return false }
        return bytes.dropFirst().allSatisfy { letter($0) || (48...57).contains($0) }
    }

    static func account(for id: UUID) -> String { accountPrefix + id.uuidString.lowercased() }
}
