import Foundation

public enum SecretKind: String, Codable, Sendable, Identifiable, CaseIterable {
    case apiKey, password, secureNote
    public var id: String { rawValue }
}

public struct SecretSummary: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var title: String
    public var kind: SecretKind
    public var folder: String
    public let createdAt: Date

    public init(id: UUID = UUID(), title: String, kind: SecretKind, folder: String, createdAt: Date = Date()) {
        self.id = id; self.title = title; self.kind = kind; self.folder = folder; self.createdAt = createdAt
    }
}

public struct EnvironmentBinding: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var key: String
    public var secretID: UUID

    public init(id: UUID = UUID(), key: String, secretID: UUID) {
        self.id = id; self.key = key; self.secretID = secretID
    }
}

public struct ProjectEnvironment: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var bindings: [EnvironmentBinding]

    public init(id: UUID = UUID(), name: String, bindings: [EnvironmentBinding] = []) {
        self.id = id; self.name = name; self.bindings = bindings
    }
}

public struct CommunityProject: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var environments: [ProjectEnvironment]

    public init(id: UUID = UUID(), name: String, environments: [ProjectEnvironment] = []) {
        self.id = id; self.name = name; self.environments = environments
    }
}

public struct CommunitySnapshot: Codable, Sendable, Identifiable, Equatable {
    public var id: String { "local-community-workspace" }
    public var secrets: [SecretSummary]
    public var projects: [CommunityProject]

    public init(secrets: [SecretSummary] = [], projects: [CommunityProject] = []) {
        self.secrets = secrets; self.projects = projects
    }
}

/// Error descriptions intentionally never interpolate labels, paths or credential data.
public enum CommunityError: Error, LocalizedError, Sendable, Equatable {
    case invalidLabel, invalidValue, invalidEnvironmentKey, notFound, duplicateProject
    case malformedMetadata, unsafeFile, storageUnavailable, protectedValueUnavailable
    case exportConfirmationRequired, exportValueUnsupported, exportTooLarge, recoveryRequired

    public var errorDescription: String? {
        switch self {
        case .invalidLabel: "Use a nonempty, reasonably sized name without control characters."
        case .invalidValue: "The protected value must be nonempty UTF-8 text of at most 64 KiB."
        case .invalidEnvironmentKey: "Use an environment key beginning with a letter or underscore, followed by letters, digits or underscores, up to 128 characters."
        case .notFound: "The selected local record no longer exists."
        case .duplicateProject: "A project with that name already exists."
        case .malformedMetadata: "Local workspace metadata is invalid or exceeds its safe parser bounds. It was not changed."
        case .unsafeFile: "Use a normal local folder and a new file. Symbolic links, shared metadata files and existing export targets are refused."
        case .storageUnavailable: "The local workspace could not be written. Existing records were preserved."
        case .protectedValueUnavailable: "The protected operation could not be completed. macOS may require authentication or a correctly signed Keychain-enabled build."
        case .exportConfirmationRequired: "Plaintext export requires the exact confirmation EXPORT."
        case .exportValueUnsupported: "This value cannot be exported unchanged in the supported .env format. Apostrophes, backslashes, control characters and non-text values are refused."
        case .exportTooLarge: "This export exceeds the safe file buffer bound."
        case .recoveryRequired: "An interrupted local transaction requires review. The workspace is locked to prevent further changes; no automatic credential deletion was attempted."
        }
    }
}
