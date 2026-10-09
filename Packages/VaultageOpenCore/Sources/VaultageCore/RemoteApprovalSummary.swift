import Foundation

/// BL-099 / BL-095 — the value-free summary the Mac seals to a paired phone.
///
/// `12-REMOTE-APPROVALS-PROTOCOL.md` §3.1 (the field list and its two validator
/// classes) and §3.3 (the digest and the rendering contract), implemented from
/// the normative `12-APPENDIX-BUILDERS-CONTRACT.md` — **P4's field order is the
/// manifest**, and where the prose and the appendix differ the appendix wins.
///
/// **One list, two uses.** This type is simultaneously the object the Mac seals
/// and the render manifest the phone lays out, in the appendix's P4 order. There
/// is no field here that is digested and not shown, and no string shown that is
/// not digested, with exactly one carve-out the appendix names:
/// `offeredCoverageDigest`, which the phone cannot derive and which is
/// meaningless to render (§3.3 rule 1).
///
/// **Nothing here is agent-supplied.** Every string is drawn from a resolved
/// local record or a fixed enum (§7 A7, v1's VS-009 lesson). `agentLabel` is
/// `EnrolledClient.displayName` and nothing else.
///
/// **Optionals are sentinels, never omissions.** `agentLabel` encodes as `""`,
/// `agentClientId` / `resourceLabel` as `"none"`, `principalHint` as
/// `"unknown"`. Arity is therefore fixed and the encoding stays injective (Q2,
/// §3.3 rule 3).

public enum RemoteApprovalClass: String, Codable, Hashable, Sendable, CaseIterable {
    case action
    case grant
    case connect
    case provisioningSelection = "provisioning_selection"
}

/// §3.7's publication-time snapshot. The phone renders it in the past tense —
/// "your Mac was locked when this was raised" — because that is what it is.
///
/// **Presence is never consulted by an authorization check** (DB-H8, Q10). It is
/// a digested display field and a routing hint, nothing else.
public enum RemotePresence: String, Codable, Hashable, Sendable, CaseIterable {
    case active, idle, locked, asleep, unknown
}

/// §11.4 / §11.5 item 1. What the owner is approving about custody, as one enum,
/// digested so it is part of what they approve rather than a claim on a screen.
/// Release one's answer is §11.6's option (b), so every summary this build
/// composes carries `presenceRequired`.
public enum RemoteCustodyClass: String, Codable, Hashable, Sendable, CaseIterable {
    case presenceRequired = "presence_required"
    case standby
}

/// §3.3's `destination` block — five fields when a runtime destination exists,
/// and a `"0"` count when it does not. Present for completeness of the manifest;
/// `runtime_delivery` itself never mirrors (§3.6).
public struct RemoteSummaryDestination: Codable, Hashable, Sendable {
    public let accountId: String
    public let scriptName: String
    public let variableName: String
    public let deploymentMode: String
    public let destinationClass: String

    public init(accountId: String, scriptName: String, variableName: String, deploymentMode: String, destinationClass: String) {
        self.accountId = accountId
        self.scriptName = scriptName
        self.variableName = variableName
        self.deploymentMode = deploymentMode
        self.destinationClass = destinationClass
    }

    var canonicalFields: [String] { [accountId, scriptName, variableName, deploymentMode, destinationClass] }
}

/// One offered project: the id the decision may name and the name the owner
/// reads. Sorted by id in the digest.
public struct RemoteOfferedProject: Codable, Hashable, Sendable {
    public let id: String
    public let name: String
    public init(id: String, name: String) { self.id = id; self.name = name }
}

/// One `provisioning_selection` choice. Sorted by id in the digest.
public struct RemoteChoice: Codable, Hashable, Sendable {
    public let id: String
    public let label: String
    public let detail: String
    public init(id: String, label: String, detail: String) { self.id = id; self.label = label; self.detail = detail }
}

/// §3.3.1's `grant` section — every `GrantDisclosure` coverage field, so the
/// owner signs the coverage rather than being shown it (DB-C4).
///
/// `recipientDeviceId` and `recipientApvThumbprint` are why the retained field
/// lists are **per recipient** (residual 8, DB-M37): with the recipient digested,
/// a cross-recipient replay fails at §4.3 step 9a rather than only at the seal.
public struct RemoteGrantSection: Codable, Hashable, Sendable {
    public let scopeLabel: String
    public let durationLabel: String
    public let expiresAtEpoch: Int
    public let environments: [String]
    public let operations: [String]
    public let mutations: [String]
    public let mutationKinds: [String]
    public let productionEnvs: [String]
    public let includesProduction: Bool
    public let offeredMutations: [String]
    /// The one field that is digested and not rendered (§3.3 rule 1's carve-out).
    /// Fail-closed: a wrong value refuses at §4.3 step 9c and can never approve.
    public let offeredCoverageDigest: String
    public let recipientDeviceId: String
    public let recipientApvThumbprint: String

    public init(scopeLabel: String, durationLabel: String, expiresAtEpoch: Int, environments: [String], operations: [String], mutations: [String], mutationKinds: [String], productionEnvs: [String], includesProduction: Bool, offeredMutations: [String], offeredCoverageDigest: String, recipientDeviceId: String, recipientApvThumbprint: String) {
        self.scopeLabel = scopeLabel
        self.durationLabel = durationLabel
        self.expiresAtEpoch = expiresAtEpoch
        self.environments = environments
        self.operations = operations
        self.mutations = mutations
        self.mutationKinds = mutationKinds
        self.productionEnvs = productionEnvs
        self.includesProduction = includesProduction
        self.offeredMutations = offeredMutations
        self.offeredCoverageDigest = offeredCoverageDigest
        self.recipientDeviceId = recipientDeviceId
        self.recipientApvThumbprint = recipientApvThumbprint
    }

    /// The four sentence **identifiers** §3.3.1 requires — not the text. A
    /// sentence the relay can choose is a sentence the relay can drop; the
    /// identifier's presence in the digest is what stops that, and the phone
    /// carries the words in its own `Localizable.strings`.
    ///
    /// Four, not three (checklist 11, DB-M24): version 4 omitted
    /// `production.v1`, the one that says production actions will run without a
    /// prompt, on the class D38 aimed at production.
    public static let sentenceIdentifiers = ["autoAllow.v1", "production.v1", "mutation.v1", "verificationCeiling.v1"]
}

/// §3.3.1's `connect` section. `capability` is digested because it fixes *what
/// the owner is told to put in the fields* (checklist 6, DB-H25); the compiled
/// contract fixes which fields they are.
public struct RemoteConnectSection: Codable, Hashable, Sendable {
    public let providerSlug: String
    public let connectionLabel: String
    public let capability: String
    public let fieldSchemaId: String

    public init(providerSlug: String, connectionLabel: String, capability: String, fieldSchemaId: String) {
        self.providerSlug = providerSlug
        self.connectionLabel = connectionLabel
        self.capability = capability
        self.fieldSchemaId = fieldSchemaId
    }
}

/// The whole summary, in the appendix's P4 order.
///
/// `Codable` with explicit keys, because this object is also the §9.3 fixture's
/// wire shape: three suites in two languages decode the same bytes and must
/// agree on the number they produce from them.
public struct RemoteApprovalSummary: Codable, Hashable, Sendable {
    /// §3.1 Class A: const. The only cross-version discriminator two
    /// independently built implementations have (DB-M39).
    public static let schemaTag = "vaultage.remote.summary.v4"

    public let schema: String
    public let summaryClass: RemoteApprovalClass
    public let pendingId: String
    public let accountSubject: String
    public let macDeviceId: String
    public let agentState: String
    /// `nil` for an unenrolled client. Encodes as `""`; the phone renders the
    /// fixed string "Unenrolled client".
    public let agentLabel: String?
    /// `nil` for an unenrolled client. Encodes as `"none"`.
    public let agentClientId: String?
    public let provider: String
    public let connectionLabel: String
    /// Provider-supplied text, treated as untrusted (`Grant.swift:304` already
    /// does). Encodes as `"unknown"` when absent.
    public let principalHint: String?
    public let projectName: String
    public let environmentName: String
    /// **Display only** — the stored `EnvironmentSensitivity` raw value.
    public let sensitivity: String
    /// **The authority** (residual 1, DB-H30, checklist 2/DB-H21).
    /// `Environment.isProduction` is `sensitivity == .production || name.trimmed
    /// .lowercased() == "production"`, and it is what `GrantPolicy.prepare` and
    /// `authorizingGrant` already gate on. Digested, so the phone renders the
    /// production warning from a fact the relay cannot forge.
    public let isProduction: Bool
    public let operation: String
    public let verb: String
    public let effect: String
    /// **Display only** — `OperationTrustClass`'s four shipped raw values. The
    /// mirror decision is made against `ApprovalRequirement`, never against this
    /// (§3.6, DB-H13).
    public let trustClass: String
    public let resourceLabel: String?
    public let destination: RemoteSummaryDestination?
    public let offeredScopes: [String]
    public let offeredDurations: [String]
    public let offeredProjects: [RemoteOfferedProject]
    public let offeredProduction: Bool
    public let choices: [RemoteChoice]
    public let presence: RemotePresence
    public let openPendingCount: Int
    public let custodyClass: RemoteCustodyClass
    public let brokerDigestKind: String
    public let brokerRequestDigest: String
    public let issuedAt: Int
    public let expiresAt: Int
    public let grant: RemoteGrantSection?
    public let connect: RemoteConnectSection?

    public init(summaryClass: RemoteApprovalClass, pendingId: String, accountSubject: String, macDeviceId: String, agentState: String, agentLabel: String?, agentClientId: String?, provider: String, connectionLabel: String, principalHint: String?, projectName: String, environmentName: String, sensitivity: String, isProduction: Bool, operation: String, verb: String, effect: String, trustClass: String, resourceLabel: String?, destination: RemoteSummaryDestination? = nil, offeredScopes: [String] = [], offeredDurations: [String] = [], offeredProjects: [RemoteOfferedProject] = [], offeredProduction: Bool = false, choices: [RemoteChoice] = [], presence: RemotePresence, openPendingCount: Int, custodyClass: RemoteCustodyClass = .presenceRequired, brokerDigestKind: String, brokerRequestDigest: String, issuedAt: Int, expiresAt: Int, grant: RemoteGrantSection? = nil, connect: RemoteConnectSection? = nil) {
        self.schema = Self.schemaTag
        self.summaryClass = summaryClass
        self.pendingId = pendingId
        self.accountSubject = accountSubject
        self.macDeviceId = macDeviceId
        self.agentState = agentState
        self.agentLabel = agentLabel
        self.agentClientId = agentClientId
        self.provider = provider
        self.connectionLabel = connectionLabel
        self.principalHint = principalHint
        self.projectName = projectName
        self.environmentName = environmentName
        self.sensitivity = sensitivity
        self.isProduction = isProduction
        self.operation = operation
        self.verb = verb
        self.effect = effect
        self.trustClass = trustClass
        self.resourceLabel = resourceLabel
        self.destination = destination
        self.offeredScopes = offeredScopes
        self.offeredDurations = offeredDurations
        self.offeredProjects = offeredProjects
        self.offeredProduction = offeredProduction
        self.choices = choices
        self.presence = presence
        self.openPendingCount = openPendingCount
        self.custodyClass = custodyClass
        self.brokerDigestKind = brokerDigestKind
        self.brokerRequestDigest = brokerRequestDigest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.grant = grant
        self.connect = connect
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case summaryClass = "class"
        case pendingId, accountSubject, macDeviceId, agentState, agentLabel, agentClientId
        case provider, connectionLabel, principalHint, projectName, environmentName
        case sensitivity, isProduction, operation, verb, effect, trustClass, resourceLabel
        case destination, offeredScopes, offeredDurations, offeredProjects, offeredProduction
        case choices, presence, openPendingCount, custodyClass
        case brokerDigestKind, brokerRequestDigest, issuedAt, expiresAt
        case grant, connect
    }

    /// **Unknown keys are a refusal, not an ignore** (§3.3 rule 2). Swift's
    /// synthesized decoder ignores keys it does not know, which is exactly the
    /// hole rule 2 exists to close — a future relay adding displayed text
    /// outside the digest. So the container's key set is checked against the
    /// manifest before anything is read.
    ///
    /// **Missing keys are a refusal too** (rule 3): every optional here is a
    /// *sentinel-encoded* field, present in the JSON as `null` rather than
    /// absent, so arity is fixed on the wire as well as in the preimage.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: RawKey.self)
        let present = Set(container.allKeys.map(\.stringValue))
        let manifest = Set(CodingKeys.allCases.map(\.rawValue))
        let unknown = present.subtracting(manifest).sorted()
        guard unknown.isEmpty else {
            throw VaultageError.invalidInput("This summary carries \(unknown.count) field(s) outside the canonical manifest: \(unknown.joined(separator: ", ")).")
        }
        let missing = manifest.subtracting(present).sorted()
        guard missing.isEmpty else {
            throw VaultageError.invalidInput("This summary is missing \(missing.count) canonical field(s): \(missing.joined(separator: ", ")).")
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(String.self, forKey: .schema)
        guard schema == Self.schemaTag else {
            throw VaultageError.invalidInput("This summary declares schema \(schema); this build reads \(Self.schemaTag).")
        }
        summaryClass = try c.decode(RemoteApprovalClass.self, forKey: .summaryClass)
        pendingId = try c.decode(String.self, forKey: .pendingId)
        accountSubject = try c.decode(String.self, forKey: .accountSubject)
        macDeviceId = try c.decode(String.self, forKey: .macDeviceId)
        agentState = try c.decode(String.self, forKey: .agentState)
        agentLabel = try c.decode(String?.self, forKey: .agentLabel)
        agentClientId = try c.decode(String?.self, forKey: .agentClientId)
        provider = try c.decode(String.self, forKey: .provider)
        connectionLabel = try c.decode(String.self, forKey: .connectionLabel)
        principalHint = try c.decode(String?.self, forKey: .principalHint)
        projectName = try c.decode(String.self, forKey: .projectName)
        environmentName = try c.decode(String.self, forKey: .environmentName)
        sensitivity = try c.decode(String.self, forKey: .sensitivity)
        isProduction = try c.decode(Bool.self, forKey: .isProduction)
        operation = try c.decode(String.self, forKey: .operation)
        verb = try c.decode(String.self, forKey: .verb)
        effect = try c.decode(String.self, forKey: .effect)
        trustClass = try c.decode(String.self, forKey: .trustClass)
        resourceLabel = try c.decode(String?.self, forKey: .resourceLabel)
        destination = try c.decode(RemoteSummaryDestination?.self, forKey: .destination)
        offeredScopes = try c.decode([String].self, forKey: .offeredScopes)
        offeredDurations = try c.decode([String].self, forKey: .offeredDurations)
        offeredProjects = try c.decode([RemoteOfferedProject].self, forKey: .offeredProjects)
        offeredProduction = try c.decode(Bool.self, forKey: .offeredProduction)
        choices = try c.decode([RemoteChoice].self, forKey: .choices)
        presence = try c.decode(RemotePresence.self, forKey: .presence)
        openPendingCount = try c.decode(Int.self, forKey: .openPendingCount)
        custodyClass = try c.decode(RemoteCustodyClass.self, forKey: .custodyClass)
        brokerDigestKind = try c.decode(String.self, forKey: .brokerDigestKind)
        brokerRequestDigest = try c.decode(String.self, forKey: .brokerRequestDigest)
        issuedAt = try c.decode(Int.self, forKey: .issuedAt)
        expiresAt = try c.decode(Int.self, forKey: .expiresAt)
        grant = try c.decode(RemoteGrantSection?.self, forKey: .grant)
        connect = try c.decode(RemoteConnectSection?.self, forKey: .connect)
    }

    /// Every optional is encoded explicitly as `null`, so rule 3's "missing keys
    /// are a refusal" is decidable on the wire and not only in the preimage.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schema, forKey: .schema)
        try c.encode(summaryClass, forKey: .summaryClass)
        try c.encode(pendingId, forKey: .pendingId)
        try c.encode(accountSubject, forKey: .accountSubject)
        try c.encode(macDeviceId, forKey: .macDeviceId)
        try c.encode(agentState, forKey: .agentState)
        try c.encode(agentLabel, forKey: .agentLabel)
        try c.encode(agentClientId, forKey: .agentClientId)
        try c.encode(provider, forKey: .provider)
        try c.encode(connectionLabel, forKey: .connectionLabel)
        try c.encode(principalHint, forKey: .principalHint)
        try c.encode(projectName, forKey: .projectName)
        try c.encode(environmentName, forKey: .environmentName)
        try c.encode(sensitivity, forKey: .sensitivity)
        try c.encode(isProduction, forKey: .isProduction)
        try c.encode(operation, forKey: .operation)
        try c.encode(verb, forKey: .verb)
        try c.encode(effect, forKey: .effect)
        try c.encode(trustClass, forKey: .trustClass)
        try c.encode(resourceLabel, forKey: .resourceLabel)
        try c.encode(destination, forKey: .destination)
        try c.encode(offeredScopes, forKey: .offeredScopes)
        try c.encode(offeredDurations, forKey: .offeredDurations)
        try c.encode(offeredProjects, forKey: .offeredProjects)
        try c.encode(offeredProduction, forKey: .offeredProduction)
        try c.encode(choices, forKey: .choices)
        try c.encode(presence, forKey: .presence)
        try c.encode(openPendingCount, forKey: .openPendingCount)
        try c.encode(custodyClass, forKey: .custodyClass)
        try c.encode(brokerDigestKind, forKey: .brokerDigestKind)
        try c.encode(brokerRequestDigest, forKey: .brokerRequestDigest)
        try c.encode(issuedAt, forKey: .issuedAt)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encode(grant, forKey: .grant)
        try c.encode(connect, forKey: .connect)
    }

    /// A decoding container key that accepts anything, used only to see which
    /// keys the document actually carries before the typed read runs.
    private struct RawKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }
}
