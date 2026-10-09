import Foundation
import CryptoKit

/// BL-059 — local runtime credential delivery.
///
/// This is the one Vaultage path that puts a real credential value into another
/// process, and it gives up the product's no-secret-to-process property. It is
/// therefore a separate approval class with its own terminal decisions
/// (`runtimeDelivered` / `runtimeDenied`), it is reachable only from the
/// human-invoked `Vaultage --run` command line, and no MCP tool can request it.

// MARK: - Command line

/// The parsed `--run` command line. Every field is non-secret.
public struct RuntimeRunRequest: Sendable, Equatable {
    public struct Variable: Sendable, Equatable {
        public let name: String
        public let vaultItemID: UUID
        /// **CC-H6.** Which field of a composite vault item this variable
        /// carries. Written `NAME=<uuid>:<field>` on the command line.
        ///
        /// A composite item's Keychain record is the `VLTC1` envelope carrying
        /// every field, and it is valid UTF-8 for an ASCII credential — so
        /// `isValidUTF8` accepts it and the child would have been handed the
        /// envelope, magic and lengths and both fields, as the value of one
        /// environment variable. The same three rules the delivery path applies
        /// apply here, for the same reason and against the same record.
        public let sourceField: CompositeCredentialField?

        public init(name: String, vaultItemID: UUID, sourceField: CompositeCredentialField? = nil) {
            self.name = name
            self.vaultItemID = vaultItemID
            self.sourceField = sourceField
        }
    }

    public let projectID: UUID
    public let environmentID: UUID
    public let variables: [Variable]
    public let command: [String]

    public init(projectID: UUID, environmentID: UUID, variables: [Variable], command: [String]) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.variables = variables
        self.command = command
    }
}

public enum RuntimeRunArguments {
    public static let usage = """
    Vaultage --run: deliver approved credentials to one local command.

      Vaultage --run --project <uuid> --environment <uuid> \\
               --env NAME=<vault-item-uuid>[:<field>] [--env ...] \\
               -- <command> [args...]

    Each variable must already be authorized for that exact project, environment
    and variable name in Vaultage. The command receives the real credential
    values in its environment. Nothing is printed, logged, or written to disk.

    A vault item that holds several named fields — an account identifier and a
    secret, say — is delivered one field at a time: name it after a colon, as
    NAME=<uuid>:secret. One variable carries one field, the approval sheet says
    which, and an item that holds one value takes no field at all.
    """

    static let maximumVariables = 32
    static let maximumCommandArguments = 64
    static let maximumArgumentBytes = 4096

    /// Strict parsing: unknown flags, duplicate options, duplicate variable
    /// names, malformed identifiers, a missing `--`, and an empty command are
    /// all refused before any metadata is read.
    public static func parse(_ arguments: [String]) throws -> RuntimeRunRequest {
        var projectID: UUID?
        var environmentID: UUID?
        var variables: [RuntimeRunRequest.Variable] = []
        var command: [String] = []
        var sawSeparator = false
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--" {
                sawSeparator = true
                command = Array(arguments[(index + 1)...])
                break
            }
            switch argument {
            case "--run":
                index += 1
            case "--project", "--environment":
                guard index + 1 < arguments.count else {
                    throw VaultageError.invalidInput("\(argument) requires a value.")
                }
                guard let value = UUID(uuidString: arguments[index + 1]) else {
                    throw VaultageError.invalidInput("\(argument) requires a UUID.")
                }
                if argument == "--project" {
                    guard projectID == nil else { throw VaultageError.invalidInput("--project may be given only once.") }
                    projectID = value
                } else {
                    guard environmentID == nil else { throw VaultageError.invalidInput("--environment may be given only once.") }
                    environmentID = value
                }
                index += 2
            case "--env":
                guard index + 1 < arguments.count else {
                    throw VaultageError.invalidInput("--env requires NAME=<vault-item-uuid>.")
                }
                variables.append(try parseVariable(arguments[index + 1]))
                index += 2
            default:
                throw VaultageError.invalidInput("Unknown option \(argument). See Vaultage --run --help.")
            }
        }

        guard let projectID else { throw VaultageError.invalidInput("--project <uuid> is required.") }
        guard let environmentID else { throw VaultageError.invalidInput("--environment <uuid> is required.") }
        guard sawSeparator else { throw VaultageError.invalidInput("Put -- before the command to run.") }
        guard !command.isEmpty else { throw VaultageError.invalidInput("A command to run is required after --.") }
        guard command.count <= maximumCommandArguments else {
            throw VaultageError.invalidInput("A runtime delivery command may have at most \(maximumCommandArguments) arguments.")
        }
        for argument in command {
            guard argument.utf8.count <= maximumArgumentBytes, !argument.contains("\0") else {
                throw VaultageError.invalidInput("A command argument is too long or contains a null byte.")
            }
            // Audit M-04: a newline or another control character in an
            // argument could spoof a field on the approval sheet.
            guard !argument.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw VaultageError.invalidInput("A command argument contains a control character.")
            }
        }
        guard !variables.isEmpty else { throw VaultageError.invalidInput("At least one --env NAME=<vault-item-uuid> is required.") }
        guard variables.count <= maximumVariables else {
            throw VaultageError.invalidInput("A runtime delivery may carry at most \(maximumVariables) variables.")
        }
        let names = Set(variables.map(\.name))
        guard names.count == variables.count else {
            throw VaultageError.invalidInput("Each environment variable name may be given only once.")
        }
        return RuntimeRunRequest(projectID: projectID, environmentID: environmentID, variables: variables, command: command)
    }

    private static func parseVariable(_ value: String) throws -> RuntimeRunRequest.Variable {
        guard let separator = value.firstIndex(of: "=") else {
            throw VaultageError.invalidInput("--env expects NAME=<vault-item-uuid>[:<field>].")
        }
        let name = String(value[value.startIndex ..< separator])
        var rawID = String(value[value.index(after: separator)...])
        try validate(variableName: name)
        // CC-H6. A colon cannot appear in a UUID and cannot appear in an
        // environment variable name, so it is an unambiguous separator and the
        // shape without one keeps meaning exactly what it always meant.
        var field: CompositeCredentialField?
        if let fieldSeparator = rawID.firstIndex(of: ":") {
            let rawField = String(rawID[rawID.index(after: fieldSeparator)...])
            rawID = String(rawID[rawID.startIndex ..< fieldSeparator])
            guard let parsed = CompositeCredentialField.named(rawField), parsed != .token else {
                throw VaultageError.invalidInput("--env \(name) names the field \(rawField), which is not one field of a composite credential. Use one of: \(CompositeCredentialField.allCases.filter { $0 != .token }.map(\.wireName).sorted().joined(separator: ", ")).")
            }
            field = parsed
        }
        guard let id = UUID(uuidString: rawID) else {
            throw VaultageError.invalidInput("--env \(name) requires a vault item UUID.")
        }
        return RuntimeRunRequest.Variable(name: name, vaultItemID: id, sourceField: field)
    }

    /// Conservative POSIX environment name. This is the same shape the approval
    /// sheet displays and the digest covers.
    public static func validate(variableName: String) throws {
        guard variableName.utf8.count <= 128,
              variableName.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil else {
            throw VaultageError.invalidInput("An environment variable name must match [A-Za-z_][A-Za-z0-9_]* and be at most 128 bytes.")
        }
    }
}

// MARK: - Approval disclosure

/// Everything the runtime-delivery approval sheet must name. No value, and no
/// agent-supplied description, appears here: each field is derived from the
/// resolved local records or the resolved command line.
public struct RuntimeInjectionDisclosure: Sendable, Hashable {
    public let command: String
    public let arguments: [String]
    public let workingDirectory: String
    public let project: String
    public let environment: String
    public let variableNames: [String]
    /// **CC-H6.** One line per variable, naming the field where the source has
    /// one: `TWILIO_AUTH_TOKEN — Twilio account · Auth token`. The sheet has to
    /// say which field of a credential a process is about to be handed, for the
    /// same reason it says which variable.
    public let variableLines: [String]
    public let isProduction: Bool
    public let requestDigest: String

    public init(
        command: String,
        arguments: [String],
        workingDirectory: String,
        project: String,
        environment: String,
        variableNames: [String],
        variableLines: [String] = [],
        isProduction: Bool,
        requestDigest: String
    ) {
        self.command = command
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.project = project
        self.environment = environment
        self.variableNames = variableNames
        self.variableLines = variableLines.isEmpty ? variableNames : variableLines
        self.isProduction = isProduction
        self.requestDigest = requestDigest
    }

    /// The sentence BL-059 requires the sheet to show verbatim.
    public static let exposureSentence = "The process receives real credential values."
    /// The extra line a production environment requires.
    public static let productionWarning = "PRODUCTION ENVIRONMENT: these are production credentials, and the command you approve can use them for anything."
}

// MARK: - Child process

/// Audit H-09. What the owner approved is a file, not a string: its real
/// path with symlinks resolved, its device and inode, its size and
/// modification time, and a digest of its bytes — and the same for the first
/// argument when it names a file, which is the script an interpreter runs. A
/// same-user process that replaces the executable or retargets a symlink while
/// the sheet is up changes every one of these, and the approval no longer
/// matches; the identity is captured again immediately before the spawn.
/// The residual is the window between that last capture and `exec` itself.
public struct ExecutableIdentity: Sendable, Equatable {
    public struct File: Sendable, Equatable {
        public let realPath: String
        public let device: UInt64
        public let inode: UInt64
        public let size: UInt64
        public let modifiedNanoseconds: Int64
        public let sha256: String
        var canonicalFields: [String] { [realPath, "\(device)", "\(inode)", "\(size)", "\(modifiedNanoseconds)", sha256] }
    }
    public static let maximumHashedBytes = 64 * 1024 * 1024

    public let executable: File
    public let script: File?

    public var canonicalFields: [String] {
        var fields = ["executable"] + executable.canonicalFields
        fields.append(contentsOf: script.map { ["script"] + $0.canonicalFields } ?? ["script", "none"])
        return fields
    }

    /// The executable, and the first argument when it is a regular file.
    public static func capture(executable: URL, arguments: [String], workingDirectory: URL) throws -> ExecutableIdentity {
        let main = try File.capture(executable)
        var script: File?
        if let first = arguments.first, !first.isEmpty, !first.hasPrefix("-") {
            let candidate = URL(fileURLWithPath: first, relativeTo: workingDirectory).standardizedFileURL
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory), !isDirectory.boolValue {
                script = try File.capture(candidate)
            }
        }
        return ExecutableIdentity(executable: main, script: script)
    }
}

extension ExecutableIdentity.File {
    static func capture(_ url: URL) throws -> ExecutableIdentity.File {
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL
        var info = stat()
        guard stat(resolved.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw VaultageError.invalidInput("The command to run is not a regular file: \(resolved.path)")
        }
        let handle = try FileHandle(forReadingFrom: resolved)
        defer { try? handle.close() }
        var hasher = SHA256()
        var remaining = ExecutableIdentity.maximumHashedBytes
        while remaining > 0 {
            let chunk = try handle.read(upToCount: min(remaining, 1 << 20)) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return ExecutableIdentity.File(
            realPath: resolved.path,
            device: UInt64(info.st_dev),
            inode: UInt64(info.st_ino),
            size: UInt64(info.st_size),
            modifiedNanoseconds: Int64(info.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(info.st_mtimespec.tv_nsec),
            sha256: digest
        )
    }
}

public protocol RuntimeChildLauncher: Sendable {
    /// Runs the child to completion with exactly this environment and returns
    /// the status `Vaultage --run` should exit with.
    func run(executable: URL, arguments: [String], workingDirectory: URL, environment: [String: String]) throws -> Int32
}

/// **BL-096 slice 1 — the one macOS-only member of this file.**
///
/// `Foundation.Process` does not exist on iOS: a phone cannot spawn a child,
/// and `vaultage run` is a Mac command. The seam above (`RuntimeChildLauncher`)
/// is the protocol the rest of the module depends on, so guarding the concrete
/// launcher costs the iOS build nothing and changes no macOS behaviour —
/// `canImport(AppKit)` is this module's single spelling for "the Mac half",
/// the same one `HumanDisclosure.swift` already uses for `NSPasteboard`.
#if canImport(AppKit)
public struct ProcessRuntimeChildLauncher: RuntimeChildLauncher {
    public init() {}

    public func run(executable: URL, arguments: [String], workingDirectory: URL, environment: [String: String]) throws -> Int32 {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = workingDirectory
        process.environment = environment
        // Standard streams are inherited, so the child owns the terminal exactly
        // as it would without Vaultage. Vaultage writes nothing to them.
        do { try process.run() }
        catch { throw VaultageError.invalidInput("The command could not be started.") }
        process.waitUntilExit()
        if process.terminationReason == .uncaughtSignal { return 128 + process.terminationStatus }
        return process.terminationStatus
    }
}
#else
/// Fail-closed stand-in for a platform with no child processes, in the same
/// shape as `HumanDisclosure.swift`'s `UnavailablePasteboard`: running refuses
/// rather than silently succeeding.
public struct UnavailableRuntimeChildLauncher: RuntimeChildLauncher {
    public init() {}

    public func run(executable: URL, arguments: [String], workingDirectory: URL, environment: [String: String]) throws -> Int32 {
        throw VaultageError.unsupported("This platform cannot run a child process.")
    }
}
#endif

/// The launcher `RuntimeDelivery`'s initialiser defaults to. On macOS it is
/// `ProcessRuntimeChildLauncher()` — exactly what the default argument was
/// before — and on every other platform it is the refusal above.
public enum RuntimeChildLaunchers {
    public static var platformDefault: any RuntimeChildLauncher {
        #if canImport(AppKit)
        ProcessRuntimeChildLauncher()
        #else
        UnavailableRuntimeChildLauncher()
        #endif
    }
}

// MARK: - Service

public struct RuntimeDeliveryOutcome: Sendable, Equatable {
    public let exitStatus: Int32
    public let variableNames: [String]
    public let correlationID: UUID
}

/// Resolves, approves, unlocks and delivers. The re-validation discipline is the
/// same as the broker's: the request is canonicalized and hashed, metadata is
/// reloaded and re-compared after the approval sheet and again after every
/// Keychain prompt, the approval has a bounded lifetime, and any change denies.
public actor RuntimeDeliveryService {
    public static let operation = "runtime.env.deliver"
    public static let approvalLifetime: TimeInterval = 60

    private let metadata: MetadataStore
    private let vault: any SecretVault
    private let receipts: any ReceiptPersisting
    private let audit: any AuditPersisting
    private let launcher: any RuntimeChildLauncher
    private let authenticator: any OwnerAuthenticating
    private let environmentSource: @Sendable () -> [String: String]
    private let now: @Sendable () -> Date
    private let approve: @Sendable (ApprovalDetails) async -> Bool

    public init(
        metadata: MetadataStore,
        vault: any SecretVault,
        receipts: (any ReceiptPersisting)? = nil,
        audit: (any AuditPersisting)? = nil,
        launcher: any RuntimeChildLauncher = RuntimeChildLaunchers.platformDefault,
        authenticator: (any OwnerAuthenticating)? = nil,
        environmentSource: @escaping @Sendable () -> [String: String] = { ProcessInfo.processInfo.environment },
        now: @escaping @Sendable () -> Date = Date.init,
        approve: @escaping @Sendable (ApprovalDetails) async -> Bool
    ) {
        self.metadata = metadata
        self.vault = vault
        self.receipts = receipts ?? ReceiptStore(directory: metadata.directory)
        self.audit = audit ?? MetadataAuditStore(metadata: metadata)
        self.launcher = launcher
        self.authenticator = authenticator ?? LocalOwnerAuthentication()
        self.environmentSource = environmentSource
        self.now = now
        self.approve = approve
    }

    public func deliver(_ request: RuntimeRunRequest, workingDirectory: URL) async throws -> RuntimeDeliveryOutcome {
        let executable = try resolveExecutable(request.command[0], workingDirectory: workingDirectory)
        let arguments = Array(request.command.dropFirst())
        let invocationID = UUID()

        let resolution = try await resolve(request)
        // Audit H-09: the file's identity is a term of the approval, and the
        // sheet names the real path — symlinks resolved — rather than the
        // spelling the request used.
        let identity = try ExecutableIdentity.capture(executable: executable, arguments: arguments, workingDirectory: workingDirectory)
        let digest = self.digest(request, resolution: resolution, executable: executable, arguments: arguments, workingDirectory: workingDirectory, identity: identity)
        let disclosure = RuntimeInjectionDisclosure(
            command: identity.executable.realPath,
            arguments: arguments,
            workingDirectory: workingDirectory.path,
            project: resolution.project.name,
            environment: resolution.environment.name,
            variableNames: request.variables.map(\.name),
            variableLines: request.variables.map { variable in
                let item = resolution.items[variable.name]?.label ?? "the named vault item"
                let field = variable.sourceField.map { " \u{00B7} \($0.defaultLabel)" } ?? ""
                return "\(variable.name) \u{2014} \(item)\(field)"
            },
            isProduction: resolution.environment.isProduction,
            requestDigest: digest
        )
        let details = ApprovalDetails(
            project: resolution.project.name,
            environment: resolution.environment.name,
            provider: "Local process",
            connection: "No provider connection",
            operation: Self.operation,
            reason: "Local runtime delivery is a higher-exposure mode than a typed provider action. \(RuntimeInjectionDisclosure.exposureSentence) Vaultage cannot limit what the command does with them, and cannot revoke them once the process holds them.",
            runtimeInjection: disclosure
        )

        // The invocation is opened durably before the sheet is shown, so a
        // human denial of a runtime delivery is itself a durable record rather
        // than only a mutable Activity row.
        try await persist(request, resolution: resolution, digest: digest, correlationID: invocationID, .pending, "Runtime delivery awaiting approval for \(request.variables.count) variable(s): \(request.variables.map(\.name).joined(separator: ", ")).")
        try await project(request, decision: .pending, result: "Runtime delivery awaiting approval; request \(digest.prefix(16)).")

        guard await approve(details) else {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: .runtimeDenied, result: "The human denied local runtime delivery.")
            throw VaultageError.approvalDenied
        }
        let approvedAt = now()

        // Approval named an immutable selection; another process may have
        // changed local metadata while the sheet was visible.
        let verified: ExecutableIdentity
        do { verified = try await requireUnchanged(request, digest: digest, executable: executable, arguments: arguments, workingDirectory: workingDirectory, approvedAt: approvedAt) }
        catch {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: "The approved runtime delivery changed before the credentials were unlocked.")
            throw error
        }

        // BL-062 follow-up — one OS prompt per human action. Before this,
        // delivering N variables cost N user-presence prompts, none of which
        // named the command: the human approved one delivery in the sheet and
        // was then asked N times by the OS in its own words. Now the owner
        // authenticates **once**, in a prompt that names the command and the
        // variables, and that evaluated presence is carried into each read.
        //
        // It is bound to exactly the Keychain accounts the approved resolution
        // resolved to, so it cannot unlock an item outside the approval, and it
        // is invalidated the moment the reads finish.
        let approvedAccounts = Set(request.variables.compactMap { resolution.items[$0.name]?.keychainAccount })
        let authentication: OwnerAuthentication
        do {
            authentication = try await authenticator.authenticateOwner(
                reason: "Deliver \(request.variables.count) credential(s) to \(executable.lastPathComponent) for \(resolution.project.name) / \(resolution.environment.name): \(request.variables.map(\.name).joined(separator: ", "))",
                unlocking: approvedAccounts
            )
        } catch {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: "OS authentication failed or was cancelled before delivery.")
            throw error
        }
        defer { authentication.invalidate() }

        var secrets: [(name: String, secret: VaultSecret)] = []
        do {
            for variable in request.variables {
                guard let item = resolution.items[variable.name] else { throw VaultageError.policyDenied("The approved vault item is no longer resolvable.") }
                let stored = try vault.read(
                    account: item.keychainAccount,
                    prompt: "Deliver \(variable.name) to \(executable.lastPathComponent) for \(resolution.project.name) / \(resolution.environment.name)",
                    authentication: authentication
                )
                // CC-H6. The envelope is valid UTF-8 for an ASCII credential,
                // so the check below would have passed it straight into the
                // child's environment. One named field, or the whole of a
                // credential that has no fields.
                let secret = try CredentialDeliverySource.delivered(stored, field: variable.sourceField, sourceLabel: item.label)
                guard secret.isValidUTF8 else {
                    throw VaultageError.invalidInput("\(variable.name) is not valid UTF-8 and cannot be delivered as an environment value.")
                }
                secrets.append((variable.name, secret))
            }
        } catch {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: "OS authentication failed or was cancelled before delivery.")
            throw error
        }

        // A Keychain sheet can stay open while the graph changes. Re-resolve
        // everything once more, immediately before the child is spawned.
        do { try await requireUnchanged(request, digest: digest, executable: executable, arguments: arguments, workingDirectory: workingDirectory, approvedAt: approvedAt) }
        catch {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: "Runtime authorization changed or expired after OS authentication.")
            throw error
        }

        let status: Int32
        do { status = try spawn(secrets: secrets, executable: executable, arguments: arguments, workingDirectory: workingDirectory, expected: verified) }
        catch {
            try await complete(request, resolution: resolution, digest: digest, correlationID: invocationID, decision: .failed, result: Redactor.publicError(error))
            throw error
        }
        let names = request.variables.map(\.name).joined(separator: ", ")
        try await complete(
            request,
            resolution: resolution,
            digest: digest,
            correlationID: invocationID,
            decision: .runtimeDelivered,
            result: "Delivered \(request.variables.count) variable(s) (\(names)) to \(executable.lastPathComponent); the child exited with status \(status)."
        )
        return RuntimeDeliveryOutcome(exitStatus: status, variableNames: request.variables.map(\.name), correlationID: invocationID)
    }

    // MARK: Resolution

    private struct Resolution {
        let project: Project
        let environment: Environment
        /// Keyed by variable name.
        let items: [String: VaultItem]
        let authorizations: [String: RuntimeInjectionAuthorization]
    }

    private func resolve(_ request: RuntimeRunRequest) async throws -> Resolution {
        try resolve(request, in: try await metadata.load())
    }

    private func resolve(_ request: RuntimeRunRequest, in state: VaultageMetadata) throws -> Resolution {
        guard let project = state.projects.first(where: { $0.id == request.projectID }),
              let environment = state.environments.first(where: { $0.id == request.environmentID }),
              environment.projectID == project.id else {
            throw VaultageError.policyDenied("That project and environment are not a valid pair in this Vaultage.")
        }
        var items: [String: VaultItem] = [:]
        var authorizations: [String: RuntimeInjectionAuthorization] = [:]
        for variable in request.variables {
            try RuntimeRunArguments.validate(variableName: variable.name)
            // CC-H6, rule 3: `.token` is the whole of a credential with no
            // fields and is never a field selector.
            try CredentialDeliverySource.validate(variable.sourceField)
            guard let authorization = state.runtimeInjectionAuthorizations.first(where: {
                $0.vaultItemID == variable.vaultItemID
                    && $0.projectID == project.id
                    && $0.environmentID == environment.id
                    && $0.variableName == variable.name
            }) else {
                throw VaultageError.policyDenied("\(variable.name) is not authorized for runtime delivery from that vault item in this project and environment. Authorize it in Vaultage first.")
            }
            let item = try MetadataRemoval.requireUsableVaultItem(variable.vaultItemID, in: state)
            items[variable.name] = item
            authorizations[variable.name] = authorization
        }
        return Resolution(project: project, environment: environment, items: items, authorizations: authorizations)
    }

    private func requireUnchanged(
        _ request: RuntimeRunRequest,
        digest: String,
        executable: URL,
        arguments: [String],
        workingDirectory: URL,
        approvedAt: Date
    ) async throws -> ExecutableIdentity {
        guard now().timeIntervalSince(approvedAt) <= Self.approvalLifetime else { throw VaultageError.approvalDenied }
        let refreshed = try await resolve(request)
        // Audit H-09: captured again, so a file replaced or a symlink retargeted
        // under the sheet or the OS prompt no longer matches what was approved.
        let identity = try ExecutableIdentity.capture(executable: executable, arguments: arguments, workingDirectory: workingDirectory)
        let current = self.digest(request, resolution: refreshed, executable: executable, arguments: arguments, workingDirectory: workingDirectory, identity: identity)
        guard current == digest else {
            throw VaultageError.policyDenied("The approved runtime delivery changed before execution.")
        }
        return identity
    }

    private func digest(
        _ request: RuntimeRunRequest,
        resolution: Resolution,
        executable: URL,
        arguments: [String],
        workingDirectory: URL,
        identity: ExecutableIdentity
    ) -> String {
        var parts: [String] = [
            "vaultage.runtime.env.deliver.v2",
            request.projectID.uuidString,
            resolution.project.name,
            request.environmentID.uuidString,
            resolution.environment.name,
            resolution.environment.isProduction ? "production" : "standard",
            workingDirectory.path,
            executable.path,
            "\(arguments.count)"
        ]
        parts.append(contentsOf: identity.canonicalFields)
        parts.append(contentsOf: arguments)
        for variable in request.variables.sorted(by: { $0.name < $1.name }) {
            let item = resolution.items[variable.name]
            let authorization = resolution.authorizations[variable.name]
            parts.append(contentsOf: [
                variable.name,
                variable.vaultItemID.uuidString,
                item?.keychainAccount ?? "none",
                item?.credentialVersion?.uuidString ?? "none",
                // CC-H6. The approval is for one named field of this item, so
                // the field is a term of it.
                "sourceField",
                variable.sourceField?.wireName ?? "none",
                authorization?.id.uuidString ?? "none"
            ])
        }
        let canonical = parts.joined(separator: "|")
        return SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Spawning

    /// Resolves the command to one absolute executable path before the approval
    /// sheet names it, so the human approves the file that actually runs rather
    /// than a bare word whose meaning depends on `PATH`.
    private func resolveExecutable(_ command: String, workingDirectory: URL) throws -> URL {
        let candidates: [URL]
        if command.contains("/") {
            candidates = [URL(fileURLWithPath: command, relativeTo: workingDirectory).standardizedFileURL]
        } else {
            let path = environmentSource()["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
            candidates = path.split(separator: ":").map { URL(fileURLWithPath: String($0)).appendingPathComponent(command) }
        }
        for candidate in candidates {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
                  !isDirectory.boolValue,
                  FileManager.default.isExecutableFile(atPath: candidate.path) else { continue }
            return candidate.standardizedFileURL
        }
        throw VaultageError.invalidInput("No executable command was found for \(command).")
    }

    /// A deliberately small child environment. Vaultage's own variables, and
    /// anything else the parent shell happened to export, are not forwarded:
    /// only this allowlist plus the approved variables.
    private static let inheritedVariables = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ"]

    private func spawn(secrets: [(name: String, secret: VaultSecret)], executable: URL, arguments: [String], workingDirectory: URL, expected: ExecutableIdentity) throws -> Int32 {
        // Audit H-09: the last capture, immediately before the spawn — the
        // narrowest window this process can leave — and the spawn is of the
        // real path that was hashed, never of the pathname the request spelt.
        let identity = try ExecutableIdentity.capture(executable: executable, arguments: arguments, workingDirectory: workingDirectory)
        guard identity == expected else {
            throw VaultageError.policyDenied("The command to run changed after it was approved; nothing was started.")
        }
        let executable = URL(fileURLWithPath: identity.executable.realPath)
        var base: [String: String] = [:]
        let parent = environmentSource()
        for key in Self.inheritedVariables {
            if let value = parent[key] { base[key] = value }
        }
        if base["PATH"] == nil { base["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin" }
        var status: Int32 = 0
        try withDeliveredEnvironment(secrets, into: base) { environment in
            status = try launcher.run(executable: executable, arguments: arguments, workingDirectory: workingDirectory, environment: environment)
        }
        return status
    }

    /// Builds the child environment one credential at a time, each inside its
    /// own `VaultSecret` borrow, and releases the dictionary as soon as the
    /// child exits. The values are real credentials: this is the exposure this
    /// mode exists to make explicit.
    private func withDeliveredEnvironment(
        _ secrets: [(name: String, secret: VaultSecret)],
        into environment: [String: String],
        _ body: ([String: String]) throws -> Void
    ) throws {
        guard let first = secrets.first else { return try body(environment) }
        let rest = Array(secrets.dropFirst())
        var failure: Error?
        try first.secret.withRuntimeEnvironmentValue { value in
            var next = environment
            next[first.name] = value
            do { try withDeliveredEnvironment(rest, into: next, body) }
            catch { failure = error }
            next[first.name] = ""
        }
        if let failure { throw failure }
    }

    // MARK: Records

    private func persist(
        _ request: RuntimeRunRequest,
        resolution: Resolution,
        digest: String,
        correlationID: UUID,
        _ decision: AuditDecision,
        _ result: String
    ) async throws {
        let receipt = DurableReceipt(
            eventID: UUID(),
            correlationID: correlationID,
            at: now(),
            projectID: request.projectID,
            environmentID: request.environmentID,
            bindingID: nil,
            operation: Self.operation,
            requestDigest: digest,
            decision: decision,
            result: Redactor.safeError(result)
        )
        try await receipts.append(receipt)
    }

    private func project(_ request: RuntimeRunRequest, decision: AuditDecision, result: String) async throws {
        let event = AuditEvent(
            projectID: request.projectID,
            environmentID: request.environmentID,
            connectionID: nil,
            operation: Self.operation,
            decision: decision,
            result: Redactor.safeError(result)
        )
        try await audit.append(event)
    }

    /// The durable receipt is authoritative; a failure of the mutable Activity
    /// projection cannot change a recorded outcome.
    private func complete(
        _ request: RuntimeRunRequest,
        resolution: Resolution,
        digest: String,
        correlationID: UUID,
        decision: AuditDecision,
        result: String
    ) async throws {
        try await persist(request, resolution: resolution, digest: digest, correlationID: correlationID, decision, result)
        try? await project(request, decision: decision, result: result)
    }

    private func terminalDecision(for error: Error) -> AuditDecision {
        guard let error = error as? VaultageError else { return .failed }
        switch error {
        case .approvalDenied: return .runtimeDenied
        case .policyDenied: return .blocked
        default: return .failed
        }
    }
}
