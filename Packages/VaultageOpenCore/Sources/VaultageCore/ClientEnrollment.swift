import CryptoKit
import Foundation

/// BL-069 — per-client enrollment.
///
/// **Enrollment identifies; it never authorizes.** Nothing in this file grants
/// access to anything. A resolved enrolled name is a label the human is shown
/// on the approval sheet so that "allow for this agent" (BL-060) has something
/// durable to attach to, and so that a receipt can say *which* client asked.
/// Every approval gate, re-validation step and Keychain read in `VaultageBroker`
/// is unchanged by this ticket and runs identically for an enrolled client, an
/// unenrolled one, and one presenting a revoked credential.
///
/// The model is v1's accepted VS-009 remediation, narrowed to what v2 needs:
/// a distinct 32-byte secret per client, stored **only** as a SHA-256 hash
/// alongside a human-chosen display name, an install path hint and a status.
/// The plaintext is shown once, inside the MCP install snippet, and Vaultage
/// never writes it anywhere.

/// A client's enrollment authenticator.
///
/// This is deliberately **not** a `VaultSecret`: it is not a provider
/// credential, it is never read from the Keychain, it never reaches a provider,
/// and possessing it buys nothing but a name on a sheet. It is still treated as
/// a secret in every output path — `description` is redacted, it is not
/// `Codable`, and the one place its characters are handed out is `wireValue`,
/// which exists for exactly two callers: the install snippet that shows it once
/// and the client that presents it to the broker for verification.
public struct ClientCredential: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    /// Versioned so a future scheme (see `ClientEnrollment` notes on
    /// challenge–response) is distinguishable on sight rather than by length.
    public static let prefix = "vgc1_"
    public static let secretByteCount = 32
    /// base64url of 32 bytes, unpadded.
    public static let encodedLength = 43
    public static let textLength = prefix.count + encodedLength
    /// Nothing legitimate is longer. Anything larger is refused before it is
    /// examined, so a hostile environment value cannot be used to push work.
    public static let maximumAcceptedBytes = 256

    private let text: String

    private init(validated: String) { self.text = validated }

    /// Fails for anything that is not exactly the grammar below. There is no
    /// trimming, no normalization and no "close enough": a value that looks
    /// wrong is refused rather than repaired, and the value itself never
    /// appears in the resulting diagnosis.
    public init?(text: String) {
        guard text.utf8.count == Self.textLength,
              text.hasPrefix(Self.prefix),
              text.range(of: "^\(Self.prefix)[A-Za-z0-9_-]{\(Self.encodedLength)}$", options: .regularExpression) != nil
        else { return nil }
        self.text = text
    }

    public static func generate() -> ClientCredential {
        var bytes = [UInt8](repeating: 0, count: secretByteCount)
        // A failure here would otherwise yield a predictable credential, so it
        // is fatal rather than silently degraded.
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("Vaultage could not obtain secure random bytes for a client credential.")
        }
        return ClientCredential(validated: prefix + base64URL(Data(bytes)))
    }

    /// The only accessor that yields the characters. Call sites are auditable
    /// by grep and are limited to the one-time install snippet and the presented
    /// authentication wire.
    public var wireValue: String { text }

    /// What enrollment stores. The preimage is never persisted, so a reader of
    /// `metadata.json` learns that a client exists and nothing that lets them
    /// be it.
    public var storedHash: String { ClientEnrollment.hash(text) }

    public var description: String { "ClientCredential(redacted)" }
    public var debugDescription: String { "ClientCredential(redacted)" }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public enum EnrolledClientStatus: String, Codable, Hashable, Sendable, CaseIterable {
    case active, revoked
}

/// The durable record. It holds no credential material: `credentialHash` is a
/// SHA-256 digest of a 256-bit random value, which is why a plain digest is the
/// right primitive here and a password KDF is not — there is no low-entropy
/// preimage to grind.
/// How a client proved who it is (audit H-02). A **legacy bearer** is the
/// credential BL-069 issued into the MCP host's configuration: readable by
/// any same-user process, so replayable through the genuine `Vaultage --mcp`.
/// It still names the client on every sheet, but it is not an identity a
/// standing grant may rest on — a bearer-enrolled client is never auto-allowed.
/// A **paired instance** (BL-136 step 3) is one that proved itself with a key
/// that cannot leave the host instance; only that kind is grant-eligible.
public enum EnrolledClientKind: String, Codable, Hashable, Sendable {
    case legacyBearer = "legacy_bearer"
    case pairedInstance = "paired_instance"
}

public struct EnrolledClient: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    /// Chosen by the human in the app at install time. Never caller-supplied:
    /// an MCP client cannot name itself, which is the whole point of VS-009.
    public var displayName: String
    /// Informational only. It is recorded so the human can tell two "Claude
    /// Code" enrollments apart; it is never used as a path, a shell input, or
    /// any part of an authorization decision.
    public var installPathHint: String?
    /// Which MCP host the snippet was generated for, as a label.
    public var hostLabel: String?
    public var credentialHash: String
    public let createdAt: Date
    public var status: EnrolledClientStatus
    public var revokedAt: Date?
    public var rotatedAt: Date?
    /// Audit H-02. Nil on records written before the field existed: every one
    /// of those is a legacy bearer.
    public var kind: EnrolledClientKind?
    /// Audit H-03. Bumped by every rotation; a live session carries the
    /// generation it identified with and is cut the moment it differs. Nil
    /// on records written before the field existed, which is generation 1.
    public var credentialGeneration: Int?
    /// BL-136 step 3. How a paired agent was identified when it paired — said
    /// on every sheet. Nil for a legacy bearer.
    public var identificationStrength: AgentIdentificationStrength?
    /// BL-136 step 3. The origin digest the Keychain binding is filed under,
    /// kept here so a revoke can find the binding. It identifies nothing by
    /// itself: resolution goes through the binding, never through this field.
    public var pairingDigest: String?

    public init(id: UUID = UUID(), displayName: String, installPathHint: String? = nil, hostLabel: String? = nil, credentialHash: String, createdAt: Date = .now, status: EnrolledClientStatus = .active, revokedAt: Date? = nil, rotatedAt: Date? = nil, kind: EnrolledClientKind? = nil, credentialGeneration: Int? = nil, identificationStrength: AgentIdentificationStrength? = nil, pairingDigest: String? = nil) {
        self.identificationStrength = identificationStrength
        self.pairingDigest = pairingDigest
        self.id = id
        self.displayName = displayName
        self.installPathHint = installPathHint
        self.hostLabel = hostLabel
        self.credentialHash = credentialHash
        self.createdAt = createdAt
        self.status = status
        self.revokedAt = revokedAt
        self.rotatedAt = rotatedAt
        self.kind = kind
        self.credentialGeneration = credentialGeneration
    }

    public var isActive: Bool { status == .active && revokedAt == nil }
    /// Whether a standing grant may rest on this client's identity (audit
    /// H-02): only a paired instance. A legacy bearer is named, never trusted.
    public var isGrantEligible: Bool { kind == .pairedInstance }
    public var generation: Int { credentialGeneration ?? 1 }
}

/// Why a connection has no enrolled name. This is diagnostic: none of these
/// states differ in what they permit, because none of them permit anything.
public enum UnenrolledReason: String, Codable, Hashable, Sendable {
    /// The MCP host set no credential. The ordinary state for a client that
    /// was never enrolled.
    case notPresented
    /// Something was set but it is not a Vaultage client credential.
    case malformed
    /// Well-formed and matches no record.
    case unknown
    /// Matches a record whose credential has since been rotated: the session
    /// that identified with the old one is over (audit H-03).
    case rotated
    /// Matches a record that has been revoked.
    case revoked
}

/// What an approval sheet is allowed to say about the caller.
///
/// Modelled as a struct rather than an enum with payloads so that the wire
/// shape is flat and inspectable, and decoded defensively: an inconsistent
/// value (enrolled with no name) becomes unenrolled rather than a half-state,
/// and `approvalLine` refuses to print a name unless the state says enrolled.
public struct ClientIdentity: Codable, Hashable, Sendable {
    public enum State: String, Codable, Hashable, Sendable { case enrolled, unenrolled }

    public let state: State
    public let id: UUID?
    public let name: String?
    public let reason: UnenrolledReason?
    /// Audit H-03. The credential generation this session identified with;
    /// `current` refuses the session once the record's generation moves on.
    /// Nil for an identity that was never resolved from a credential.
    public let generation: Int?
    /// BL-136 step 3. How a paired agent was identified on this connection:
    /// by its code signature or by its file location. Nil for a legacy bearer,
    /// which was identified by a credential in the client's configuration.
    public let identification: AgentIdentificationStrength?

    private init(state: State, id: UUID?, name: String?, reason: UnenrolledReason?, generation: Int? = nil, identification: AgentIdentificationStrength? = nil) {
        self.state = state
        self.id = id
        self.name = name
        self.reason = reason
        self.generation = generation
        self.identification = identification
    }

    public static func enrolled(id: UUID, name: String, generation: Int? = nil, identification: AgentIdentificationStrength? = nil) -> ClientIdentity {
        let clean = ClientEnrollment.sanitizedDisplayName(name)
        guard let clean else { return .unenrolled(.unknown) }
        return ClientIdentity(state: .enrolled, id: id, name: clean, reason: nil, generation: generation, identification: identification)
    }

    public static func unenrolled(_ reason: UnenrolledReason) -> ClientIdentity {
        ClientIdentity(state: .unenrolled, id: nil, name: nil, reason: reason)
    }

    /// The exact line every approval sheet carries. It fails closed: without a
    /// coherent enrolled state and a non-empty name it says "unenrolled",
    /// whatever the other fields hold.
    public var approvalLine: String {
        guard state == .enrolled, let name, !name.isEmpty else { return "Client: unenrolled" }
        switch identification {
        case .codeSignature: return "Client: \(name) (paired; identified by its code signature)"
        case .fileLocation: return "Client: \(name) (paired; identified by its file location only)"
        case .none, .some(.none): return "Client: \(name)"
        }
    }

    public var isEnrolled: Bool { state == .enrolled && name?.isEmpty == false }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let state = try container.decode(State.self, forKey: .state)
        let id = try container.decodeIfPresent(UUID.self, forKey: .id)
        let name = try container.decodeIfPresent(String.self, forKey: .name).flatMap(ClientEnrollment.sanitizedDisplayName)
        let reason = try container.decodeIfPresent(UnenrolledReason.self, forKey: .reason)
        let generation = try container.decodeIfPresent(Int.self, forKey: .generation)
        let identification = try container.decodeIfPresent(AgentIdentificationStrength.self, forKey: .identification)
        guard state == .enrolled, let id, let name else {
            self = .unenrolled(reason ?? .unknown)
            return
        }
        self = ClientIdentity(state: .enrolled, id: id, name: name, reason: nil, generation: generation, identification: identification)
    }
}

/// The enrollment model: pure functions over metadata, plus the resolution rule.
///
/// Kept free of I/O so the whole model — issue, resolve, impersonate, revoke,
/// rotate — is exercised by the self-test suite with no Keychain, no file and
/// no approval sheet.
public enum ClientEnrollment {
    public static let maximumDisplayNameLength = 64
    public static let maximumInstallPathHintLength = 512
    /// A cap on how many records resolution will walk. Far above any real
    /// install and low enough that a corrupted store cannot turn a connect into
    /// unbounded work.
    public static let maximumEnrolledClients = 64

    public static func hash(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Human-chosen, so this normalizes rather than rejects on sight: control
    /// characters and newlines are stripped (an approval sheet is a single
    /// line per field), the result is trimmed and bounded, and an empty result
    /// is `nil` so no caller can display a nameless "enrolled" client.
    public static func sanitizedDisplayName(_ raw: String) -> String? {
        let stripped = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        let trimmed = stripped.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return String(trimmed.prefix(maximumDisplayNameLength))
    }

    public static func sanitizedInstallPathHint(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let stripped = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        let trimmed = stripped.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return String(trimmed.prefix(maximumInstallPathHintLength))
    }

    /// What `enroll` and `rotate` hand back. The plaintext exists only inside
    /// this value, for as long as the caller holds it, and is never persisted.
    public struct Issue: Sendable {
        public let client: EnrolledClient
        public let credential: ClientCredential
    }

    /// `kind` is what the client proved (audit H-02): the snippet flow issues
    /// a legacy bearer; only BL-136's pairing ceremony enrols a paired
    /// instance, and only that kind is grant-eligible.
    public static func enroll(displayName: String, installPathHint: String? = nil, hostLabel: String? = nil, now: Date = .now, kind: EnrolledClientKind = .legacyBearer, in state: inout VaultageMetadata) throws -> Issue {
        guard let name = sanitizedDisplayName(displayName) else {
            throw VaultageError.invalidInput("An enrolled client needs a display name.")
        }
        guard state.enrolledClients.count < maximumEnrolledClients else {
            throw VaultageError.policyDenied("This Vaultage install already has the maximum number of enrolled clients. Revoke one first.")
        }
        let credential = ClientCredential.generate()
        let client = EnrolledClient(
            displayName: name,
            installPathHint: sanitizedInstallPathHint(installPathHint),
            hostLabel: hostLabel,
            credentialHash: credential.storedHash,
            createdAt: now,
            kind: kind,
            credentialGeneration: 1
        )
        state.enrolledClients.append(client)
        return Issue(client: client, credential: credential)
    }

    /// BL-136 step 3. The paired record: named by the person on the sheet,
    /// labelled by the origin the broker derived, with no credential — the
    /// hash is of the digest, which no presented credential can equal, so the
    /// legacy resolution can never match a paired row. An active row for the
    /// same origin is refused; a revoked one is left as history and a new
    /// record is minted (S2: re-pairing mints a new id).
    public static func enrollPaired(displayName: String, origin: AgentOrigin, now: Date = .now, in state: inout VaultageMetadata) throws -> EnrolledClient {
        guard let name = sanitizedDisplayName(displayName) else {
            throw VaultageError.invalidInput("A paired agent needs a name.")
        }
        guard origin.canPair else { throw VaultageError.policyDenied(AgentIdentificationStrength.none.sentence) }
        guard state.enrolledClients.count < maximumEnrolledClients else {
            throw VaultageError.policyDenied("This Vaultage install already has the maximum number of enrolled clients. Revoke one first.")
        }
        guard !state.enrolledClients.contains(where: { $0.isActive && $0.pairingDigest == origin.digest }) else {
            throw VaultageError.policyDenied("This agent is already paired. Revoke it in the Vaultage app to pair it again.")
        }
        let client = EnrolledClient(
            displayName: name,
            installPathHint: sanitizedInstallPathHint(origin.folderLine),
            hostLabel: origin.clientLine,
            credentialHash: hash("pairing:" + origin.digest),
            createdAt: now,
            kind: .pairedInstance,
            credentialGeneration: 1,
            identificationStrength: origin.strength,
            pairingDigest: origin.digest
        )
        state.enrolledClients.append(client)
        return client
    }

    /// Rotation keeps the identity and replaces the authenticator. The previous
    /// credential stops resolving the instant this is committed, because the
    /// only thing that ever matched it was the hash being replaced here.
    public static func rotate(_ id: UUID, now: Date = .now, in state: inout VaultageMetadata) throws -> Issue {
        guard let index = state.enrolledClients.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That enrolled client no longer exists.")
        }
        guard state.enrolledClients[index].isActive else {
            throw VaultageError.policyDenied("A revoked client cannot be rotated. Enroll it again instead.")
        }
        let credential = ClientCredential.generate()
        state.enrolledClients[index].credentialHash = credential.storedHash
        state.enrolledClients[index].rotatedAt = now
        // Audit H-03: the generation moves, so a session that identified with
        // the old credential is refused on its next action, not only at its
        // next reconnect.
        state.enrolledClients[index].credentialGeneration = state.enrolledClients[index].generation + 1
        return Issue(client: state.enrolledClients[index], credential: credential)
    }

    /// Revocation is local and independent: it edits one record's status and
    /// touches nothing else, so no other client's credential is affected.
    @discardableResult
    public static func revoke(_ id: UUID, now: Date = .now, in state: inout VaultageMetadata) throws -> EnrolledClient {
        guard let index = state.enrolledClients.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That enrolled client no longer exists.")
        }
        state.enrolledClients[index].status = .revoked
        state.enrolledClients[index].revokedAt = state.enrolledClients[index].revokedAt ?? now
        return state.enrolledClients[index]
    }

    /// Resolution. A presented credential is hashed and compared against every
    /// record without early exit, so neither timing nor ordering reveals which
    /// records exist. A revoked record is matched deliberately — so the result
    /// can say `revoked` rather than `unknown` — and then refused all the same.
    public static func resolve(_ credential: ClientCredential?, in state: VaultageMetadata) -> ClientIdentity {
        guard let credential else { return .unenrolled(.notPresented) }
        let presented = Array(credential.storedHash.utf8)
        var matched: EnrolledClient?
        for client in state.enrolledClients.prefix(maximumEnrolledClients) {
            if constantTimeEquals(presented, Array(client.credentialHash.utf8)) { matched = client }
        }
        guard let matched else { return .unenrolled(.unknown) }
        guard matched.isActive else { return .unenrolled(.revoked) }
        return .enrolled(id: matched.id, name: matched.displayName, generation: matched.generation)
    }

    /// Audit H-02. What a bearer-enrolled client is told when it, or the owner
    /// on its behalf, asks for a standing grant.
    public static let legacyBearerGrantSentence = "Auto-allow is paused for this client: it is enrolled with a legacy credential that another process on this Mac could replay, so no standing grant may rest on it. Every action asks until the client is paired (BL-136)."

    /// Re-resolution during a live session. The broker calls this while
    /// composing each approval sheet, so revoking a client takes effect on the
    /// next approval rather than at the next reconnect.
    public static func current(_ identity: ClientIdentity, in state: VaultageMetadata) -> ClientIdentity {
        guard identity.state == .enrolled, let id = identity.id else { return identity }
        guard let client = state.enrolledClients.first(where: { $0.id == id }) else { return .unenrolled(.unknown) }
        guard client.isActive else { return .unenrolled(.revoked) }
        // Audit H-03: a session bound to a generation that has since moved is
        // over — the credential it presented no longer names anyone.
        if let generation = identity.generation, generation != client.generation { return .unenrolled(.rotated) }
        return .enrolled(id: client.id, name: client.displayName, generation: client.generation, identification: identity.identification)
    }

    private static func constantTimeEquals(_ left: [UInt8], _ right: [UInt8]) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

/// How the `--mcp` subprocess receives its credential.
///
/// **The chosen transport is one environment variable, set by the MCP host's
/// own configuration file, read once at startup and then removed from this
/// process's environment.**
///
/// Honest trade-off. An environment variable is not a strong channel:
///
/// * a process running as the same user can read another process's environment
///   on macOS, so this does not defend against a same-uid attacker — which is
///   precisely the attacker VS-009 describes;
/// * the value is at rest in the MCP host's configuration file, at whatever
///   permissions that host chose, and Vaultage does not control it;
/// * a host that logs its spawn environment will log the credential.
///
/// It is still the right choice for this ticket, because every alternative is
/// worse or unavailable:
///
/// * **process arguments** are visible to *every* user on the machine via `ps`,
///   and land in shell history — the repository rule is explicit that a
///   credential never reaches a process argument;
/// * **a shared file** is exactly v1's VS-009 failure: one secret readable by
///   every same-uid process, with no per-client attribution;
/// * **the Keychain** cannot help, because the MCP host has no identity with
///   which to authenticate as a distinct client;
/// * **a handshake over stdio** is not available: the MCP JSON-RPC framing owns
///   stdin and stdout for the life of the process.
///
/// What carried the real weight when this was written was elsewhere: the
/// credential authorized nothing, every action took a fresh human approval, and
/// BL-061's code-signing admission is what actually decides who may talk to the
/// broker.
///
/// **BL-060 changed the first two of those three.** A client-scoped auto-allow
/// grant keys on the enrolled client id this value resolves to, so for the life
/// of such a grant the bearer value in the MCP host's configuration file *is*
/// an authorization input, and the same-uid weakness above stops being a
/// weakness only in what a sheet says. The code-signing admission still holds.
/// The key-pair upgrade below is no longer only a tidiness argument.
/// Replacing the bearer value with a challenge–response over a key pair — where
/// nothing that crosses a boundary or sits in a file is replayable — is the
/// recorded follow-up, not something this ticket claims.
public enum ClientCredentialTransport {
    public static let environmentKey = "VAULTAGE_CLIENT_CREDENTIAL"

    /// Reads and immediately unsets the variable, so it is not inherited by any
    /// child, not visible to later introspection of this process, and not
    /// available to any code that runs after startup.
    public static func takeFromEnvironment(_ environment: [String: String] = ProcessInfo.processInfo.environment, unset: Bool = true) -> Result {
        let raw = environment[environmentKey]
        if unset { unsetenv(environmentKey) }
        guard let raw else { return Result(credential: nil, reason: .notPresented) }
        guard raw.utf8.count <= ClientCredential.maximumAcceptedBytes,
              let credential = ClientCredential(text: raw) else {
            // The rejected value is never echoed, logged or measured out loud.
            return Result(credential: nil, reason: .malformed)
        }
        return Result(credential: credential, reason: nil)
    }

    public struct Result: Sendable {
        public let credential: ClientCredential?
        /// Set when nothing usable was presented. `nil` means a well-formed
        /// credential was read — which is not yet a claim that it is enrolled.
        public let reason: UnenrolledReason?

        /// A one-line, value-free note for stderr. It never contains the
        /// presented value, its length, or any part of it.
        public var diagnostic: String {
            switch reason {
            case .none: return "Vaultage MCP: a client credential was presented."
            case .some(.notPresented): return "Vaultage MCP: no client credential was set; this client is unenrolled and gets per-action approval only."
            case .some(.malformed): return "Vaultage MCP: the value in \(environmentKey) is not a Vaultage client credential; it was ignored and this client is unenrolled."
            case .some(.unknown), .some(.revoked), .some(.rotated): return "Vaultage MCP: this client is unenrolled."
            }
        }
    }
}
