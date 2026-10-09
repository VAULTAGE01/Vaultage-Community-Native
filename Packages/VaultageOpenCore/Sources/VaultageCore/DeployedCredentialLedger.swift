import Foundation

// BL-094 / owner decision D36 — the deployed-credential ledger.
//
// D36's fourth guarantee, in full: "For every environment, which credential
// (id, fingerprint, provider principal) is deployed where, when it was last
// delivered and last verified, and its expiry."
//
// Four rules shape every type here, and each explains why something is
// *missing* rather than present.
//
// 1. **A ledger row is never a value, and its fingerprint is not a hash of
//    one.** `fingerprint` is a digest of the vault item's id and its opaque
//    credential version — a *stable identifier*, exactly as the ticket says.
//    Hashing the value would make the ledger an offline oracle: anyone with
//    `metadata.json` could confirm a guessed credential. Hashing the identity
//    answers the question the product actually asks — "is production still
//    running the same key staging is?" — and answers nothing else.
//
// 2. **The ledger is a record of an act, not a cache.** The inventory
//    (BL-092) may degrade to "not cached" because a provider read can always
//    be repeated. A delivery cannot: forgetting that a secret is deployed at
//    a destination is worse than remembering it imprecisely, because the
//    secret is still *there*. So `normalize` repairs and drops far less than
//    the inventory's does, and a row whose source vault item has been deleted
//    is **kept** — with the projection saying so — rather than erased.
//
// 3. **Nothing here authorizes anything.** A row is not a capability and not
//    a binding. Delivering, verifying and rotating each resolve the binding,
//    the bound scope and the source authorization from scratch.
//
// 4. **Health is computed on demand and is advisory.** There is no timer, no
//    background task and no refresh-on-launch: D36 says health checks "are
//    advisory and never a dependency", and a product whose continuity story
//    is "nothing at runtime calls this Mac" must not quietly acquire a
//    process that has to be running.

// MARK: - The stores a delivery writes into

/// A provider's own secret store: the place a deployed runtime reads its
/// credentials from, so nothing at request time calls this Mac (D36).
///
/// Slice 1 is Cloudflare Worker secrets and Vercel environment variables.
/// Netlify, Railway, Supabase, GitHub Actions and Fly are the same shape and
/// join by being added here plus their operations — but see the value-returning
/// finding recorded on BL-094 and enforced in `BL-092 §3`: Vercel, Netlify,
/// Supabase, Railway and Render all return secret *values* on read, so a store
/// may only be listed through an adapter that provably drops them.
public enum SecretStore: String, Codable, Sendable, CaseIterable {
    case cloudflareWorkerSecret = "cloudflare.worker_secret"
    case vercelEnvironmentVariable = "vercel.environment_variable"
    /// BL-128 slice 3c (D65). A repository's Actions secrets — what a
    /// workflow reads as `${{ secrets.NAME }}`. The value is sealed on this Mac
    /// to the repository's own public key before it leaves, and GitHub
    /// documents that no route ever returns it.
    case githubActionsSecret = "github.actions_secret"

    public var provider: Provider {
        switch self {
        case .cloudflareWorkerSecret: .cloudflare
        case .vercelEnvironmentVariable: .vercel
        case .githubActionsSecret: .github
        }
    }

    /// What the environment card and the approval sheet call it.
    public var label: String {
        switch self {
        case .cloudflareWorkerSecret: "Worker secret"
        case .vercelEnvironmentVariable: "Environment variable"
        case .githubActionsSecret: "Actions secret"
        }
    }

    /// The label inside a sentence: lower-cased, except that "Actions" is
    /// GitHub's product name and keeps its capital.
    public var inlineLabel: String {
        switch self {
        case .githubActionsSecret: "Actions secret"
        default: label.lowercased()
        }
    }

    /// Whether one destination name exists once per deploy target. Vercel's
    /// `NEXT_PUBLIC_API` on production and on preview are two deployed
    /// credentials that can hold different values; a Cloudflare Worker secret
    /// has no such axis.
    public var usesTargets: Bool { self == .vercelEnvironmentVariable }

    /// The read that lists this store's entry **names and never their values**.
    /// It is the delivery's preflight and its post-write verification, and it
    /// is the only read the ledger's own "verify deployed" sweep ever issues.
    public var nameListOperation: Operation {
        switch self {
        case .cloudflareWorkerSecret: .cloudflareWorkerSecretNameList
        case .vercelEnvironmentVariable: .vercelEnvList
        case .githubActionsSecret: .githubActionsSecretNameList
        }
    }

    /// The deliveries that write into this store. Vercel has two because the
    /// provider documents a POST for a new variable and a PATCH for an
    /// existing one; which of the two runs is decided by the preflight, never
    /// by the caller.
    public var deliveryOperations: [Operation] {
        switch self {
        case .cloudflareWorkerSecret: [.cloudflareWorkerSecretPut]
        case .vercelEnvironmentVariable: [.vercelEnvCreate, .vercelEnvUpdate]
        // One PUT that creates or replaces by name, like Cloudflare's.
        case .githubActionsSecret: [.githubActionsSecretPut]
        }
    }

    /// The scope kind a binding must carry to deliver into this store.
    public var scopeKind: ProviderResourceScopeKind {
        switch self {
        case .cloudflareWorkerSecret: .cloudflareWorkerScript
        case .vercelEnvironmentVariable: .vercelProject
        case .githubActionsSecret: .githubRepository
        }
    }

    /// The store a delivery or a name list belongs to, read off the operation's
    /// own taxonomy rather than restated, so a new delivery cannot land here
    /// with the wrong store.
    public static func of(_ operation: Operation) -> SecretStore? {
        switch operation.taxonomy.resource {
        case .workerSecret: operation.provider == .cloudflare ? .cloudflareWorkerSecret : nil
        case .environmentVariable: operation.provider == .vercel ? .vercelEnvironmentVariable : nil
        case .actionsSecret: operation.provider == .github ? .githubActionsSecret : nil
        default: nil
        }
    }

    /// Whether the provider hands back its own identifier for a written entry.
    /// Vercel returns the variable's id; Cloudflare's Worker secret PUT is
    /// keyed by name and returns none, and a ledger row for it therefore has
    /// no `providerResourceID` — which is a fact about the provider, not a
    /// missing field.
    public var returnsIdentifier: Bool { self == .vercelEnvironmentVariable }

    /// The name shape this store accepts, restated from the operation's own
    /// field rules so a ledger row decoded from disk is validated on arrival.
    public func isCanonicalName(_ value: String) -> Bool {
        guard value.utf8.count <= 128, !value.isEmpty else { return false }
        switch self {
        // A conservative JavaScript identifier: the Worker's global binding.
        case .cloudflareWorkerSecret:
            return value.range(of: "^[A-Za-z_$][A-Za-z0-9_$]*$", options: .regularExpression) != nil
        // A conservative POSIX identifier, so it can never become a shell
        // surprise wherever the deployment later reads it.
        case .vercelEnvironmentVariable:
            return value.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil
        // The name exactly as GitHub stores it: upper case, no `GITHUB_`.
        case .githubActionsSecret:
            return ResourceFieldRules.isCanonicalGitHubSecretName(value)
        }
    }
}

/// Which deploy target one delivery writes to.
///
/// **One target per approved delivery.** Vercel's `target` is an array and the
/// provider would happily take all three in one call, so this is a deliberate
/// narrowing that BL-091 left in place and BL-094 keeps: see
/// `DeliveryDestination.oneTargetPerApprovalRationale`.
public enum DeliveryTarget: String, Codable, Sendable, CaseIterable {
    case production, preview, development

    public var label: String {
        switch self {
        case .production: "Production"
        case .preview: "Preview"
        case .development: "Development"
        }
    }

    /// True for the target that serves live traffic. Independent of the
    /// Vaultage environment's own `isProduction`: a human may deliver to
    /// Vercel's production target from an environment they called "staging",
    /// and the sheet has to warn about the target as well as the environment.
    public var isLiveTraffic: Bool { self == .production }
}

// MARK: - A destination

/// Exactly where one delivery puts a value: the store, the entry's name, the
/// deploy target where the store has one, and the bound container.
///
/// Every field is an identifier or a label the human chose. There is no URL,
/// no header, no credential and no free text from a provider.
public struct DeliveryDestination: Codable, Hashable, Sendable {
    public let store: SecretStore
    /// The entry's name at the provider — the Worker's binding name, the
    /// environment variable's key.
    public let name: String
    /// Nil for a store with no target axis.
    public let target: DeliveryTarget?
    /// The bound container's provider identifier: the Worker script name, the
    /// Vercel project id.
    public let scopeID: String
    /// What the human calls that container.
    public let scopeLabel: String

    public init(store: SecretStore, name: String, target: DeliveryTarget?, scopeID: String, scopeLabel: String) {
        self.store = store
        self.name = name
        self.target = target
        self.scopeID = scopeID
        self.scopeLabel = scopeLabel
    }

    /// The words the approval sheet names, and the words the ledger row shows.
    /// Built entirely from validated local records.
    public var sheetLine: String {
        let targetPart = target.map { " (\($0.label.lowercased()))" } ?? ""
        return "\(store.label) \(name)\(targetPart) on \(containerLine)"
    }

    /// The container, the way a sheet or a receipt names it. A GitHub
    /// repository is named by its `owner/name` — the identifier the write goes
    /// to — with the human's label beside it when the two differ, because the
    /// label is free text typed at bind time and could name a different
    /// repository (BL-128 slice 3c, security pass). Every other store is named
    /// by its label, as before.
    public var containerLine: String {
        guard store == .githubActionsSecret else { return scopeLabel }
        return scopeLabel == scopeID ? scopeID : "\(scopeID) (\(scopeLabel))"
    }

    /// The one-line rationale the sheet shows when a store has targets, so the
    /// human is told why three targets is three approvals rather than one.
    public static let oneTargetPerApprovalRationale = "This approval covers one deploy target. Delivering the same value to production, preview and development is three approvals, each naming its own target, because one approval covering every target would be a wider thing than the sentence above describes."

    /// A destination is well formed when its name fits the store's shape, its
    /// target axis matches the store, and its container identifier is the shape
    /// that store's routes accept.
    public var isWellFormed: Bool {
        guard store.isCanonicalName(name) else { return false }
        guard store.usesTargets == (target != nil) else { return false }
        guard !scopeLabel.isEmpty, scopeLabel.utf8.count <= 96,
              scopeLabel.range(of: "^[A-Za-z0-9 ._:/@()'-]+$", options: .regularExpression) != nil else { return false }
        switch store {
        case .cloudflareWorkerSecret: return ProviderResourceScope.isCanonicalScriptName(scopeID)
        case .vercelEnvironmentVariable: return ProviderResourceScope.isCanonicalVercelProjectID(scopeID)
        case .githubActionsSecret: return ProviderResourceScope.isCanonicalGitHubRepository(scopeID)
        }
    }

    /// Canonical, injective fields for a request digest (RP-07). The list
    /// states its own shape, so no name can impersonate a target.
    public var canonicalFields: [String] {
        ["destination", store.rawValue, name, target?.rawValue ?? "none", scopeID, scopeLabel]
    }

    /// The destination a binding's scope describes, for one entry name and
    /// target. Nil when the scope is not a store container — which is how a
    /// DNS-record binding is refused before anything else happens.
    public static func from(scope: ProviderResourceScope, name: String, target: DeliveryTarget?) -> DeliveryDestination? {
        switch scope.kind {
        case .cloudflareWorkerScript:
            guard let scriptName = scope.scriptName else { return nil }
            return DeliveryDestination(store: .cloudflareWorkerSecret, name: name, target: nil, scopeID: scriptName, scopeLabel: scope.label)
        case .vercelProject:
            guard let projectID = scope.projectID else { return nil }
            return DeliveryDestination(store: .vercelEnvironmentVariable, name: name, target: target, scopeID: projectID, scopeLabel: scope.label)
        case .cloudflareZone, .cloudflareAccount, .vercelAccount:
            return nil
        case .githubRepository:
            // BL-128 slice 3c (D65). The repository's Actions secrets; the
            // container id is the `owner/name` the human bound.
            guard let repository = scope.repository else { return nil }
            return DeliveryDestination(store: .githubActionsSecret, name: name, target: nil, scopeID: repository, scopeLabel: scope.label)
        }
    }
}

// MARK: - A ledger row

/// What one deployed credential's row can say about itself.
public enum DeployedCredentialStatus: String, Codable, Sendable, CaseIterable {
    /// Written, and the destination's name list reported it afterwards.
    case delivered
    /// Written, but a later name list did not report it — or could not be run.
    /// Advisory: the deployment may be perfectly fine and the read may simply
    /// have failed. It never blocks anything.
    case verifyFailed = "verify-failed"
    /// A rotation has delivered a newer credential to this destination. The
    /// row is kept because "what used to be here" is the question a partially
    /// finished rotation has to answer.
    case superseded
    /// The source credential has been revoked locally. What is at the provider
    /// is whatever was last delivered; Vaultage says so rather than claiming
    /// the destination is now empty.
    case revoked

    public var label: String {
        switch self {
        case .delivered: "Delivered"
        case .verifyFailed: "Not verified"
        case .superseded: "Superseded"
        case .revoked: "Revoked"
        }
    }

    /// Whether this row still describes a credential the environment is
    /// expected to be running on.
    public var isLive: Bool { self == .delivered || self == .verifyFailed }
}

/// One credential, deployed to one destination, for one environment.
public struct DeployedCredential: Codable, Identifiable, Hashable, Sendable {
    /// Derived from `(environmentID, destination)`, so re-delivering to the
    /// same destination updates the row instead of making a second one, and a
    /// row survives a rotation.
    public let id: UUID
    public let projectID: UUID
    public let environmentID: UUID
    /// The binding the delivery ran under. Kept so "verify deployed" can find
    /// the credential that is allowed to read this store's names.
    public let bindingID: UUID
    public let connectionID: UUID
    /// The vault item whose value was delivered. It may since have been
    /// deleted; the row is kept anyway, because the value is still at the
    /// provider.
    public var sourceVaultItemID: UUID
    /// **CC-H6.** Which field of that item was delivered here, or nil for an
    /// item that holds one value rather than named fields.
    ///
    /// It is a name, never a value — the same class of fact as the destination
    /// name — and it is the ledger's answer to "which half of this credential
    /// is production running?", which for a composite is a different question
    /// from "which credential". A rotation reads it so that the step replacing
    /// this row delivers **the same field** rather than guessing one.
    ///
    /// **Not part of `identityKey`.** One destination holds one value, so
    /// re-delivering the other field to the same name replaces what is there
    /// and is correctly the same row; a pair lives at two destination names and
    /// is already two rows.
    public var sourceField: CompositeCredentialField?
    /// A digest of the source item's **identity** — its id and its opaque
    /// credential version — never of its value. It changes when the value is
    /// replaced, which is exactly what a rotation needs, and it can never be
    /// used to confirm a guessed credential.
    public var fingerprint: String
    public let provider: Provider
    /// The provider principal the delivering connection was verified as, as
    /// recorded on the connection at delivery time. A hint for the card, never
    /// identity and never evidence.
    public var principal: String?
    public var destination: DeliveryDestination
    /// The operation that wrote it: `vercel.env.create`, `vercel.env.update`,
    /// `cloudflare.worker.secret.put`.
    public var operation: String
    /// The identifier the provider returned for the written entry, where the
    /// provider returns one. Nil for Cloudflare, always.
    public var providerResourceID: String?
    public var deliveredAt: Date
    public var lastVerifiedAt: Date?
    /// When the delivered credential itself expires, when that is known — a
    /// provider-stated token expiry carried over from BL-074's provisioning
    /// record. Nil means "not known", never "does not expire".
    public var expiresAt: Date?
    public var status: DeployedCredentialStatus
    public var supersededAt: Date?
    /// When the source credential was revoked locally. What is at the provider
    /// is still whatever was last delivered — this records Vaultage's own act,
    /// not the provider's.
    public var revokedAt: Date?
    /// The rotation that last touched this row, if any.
    public var rotationID: UUID?
    /// D71. Which door the delivery that last wrote this row came through,
    /// and — for the agent's — the enrolled client that asked, when it was
    /// enrolled. Nil on rows written before schema 28, when the owner's was
    /// the only door. The client's name is looked up from its enrolment at
    /// display time; the row carries no free text.
    public var requestedBy: DeliveryDoor?
    public var requestingClientID: UUID?
    public var door: DeliveryDoor { requestedBy ?? .owner }

    public init(
        id: UUID,
        projectID: UUID,
        environmentID: UUID,
        bindingID: UUID,
        connectionID: UUID,
        sourceVaultItemID: UUID,
        sourceField: CompositeCredentialField? = nil,
        fingerprint: String,
        provider: Provider,
        principal: String? = nil,
        destination: DeliveryDestination,
        operation: String,
        providerResourceID: String? = nil,
        deliveredAt: Date,
        lastVerifiedAt: Date? = nil,
        expiresAt: Date? = nil,
        status: DeployedCredentialStatus = .delivered,
        supersededAt: Date? = nil,
        revokedAt: Date? = nil,
        rotationID: UUID? = nil,
        requestedBy: DeliveryDoor? = nil,
        requestingClientID: UUID? = nil
    ) {
        self.id = id
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.connectionID = connectionID
        self.sourceVaultItemID = sourceVaultItemID
        self.sourceField = sourceField
        self.fingerprint = fingerprint
        self.provider = provider
        self.principal = principal
        self.destination = destination
        self.operation = operation
        self.providerResourceID = providerResourceID
        self.deliveredAt = deliveredAt
        self.lastVerifiedAt = lastVerifiedAt
        self.expiresAt = expiresAt
        self.status = status
        self.supersededAt = supersededAt
        self.revokedAt = revokedAt
        self.rotationID = rotationID
        self.requestedBy = requestedBy
        self.requestingClientID = requestingClientID
    }

    public static let maximumPrincipalBytes = 128
    public static let maximumIdentifierBytes = 128

    /// The identity a row is de-duplicated on: one environment, one
    /// destination. Two rows that agree on this are the same deployed
    /// credential observed twice.
    public var identityKey: String {
        ([environmentID.uuidString] + destination.canonicalFields).joined(separator: "\u{1F}")
    }

    /// A row repaired into a shape this build can show, or nil when it cannot
    /// be repaired at all. Only ever narrows.
    var repaired: DeployedCredential? {
        guard destination.isWellFormed else { return nil }
        guard SecretStore.of(Operation(rawValue: operation) ?? .githubRateLimit) == destination.store else { return nil }
        guard deliveredAt.timeIntervalSince1970.isFinite else { return nil }
        guard DeployedCredentialLedger.isCanonicalFingerprint(fingerprint) else { return nil }
        guard provider == destination.store.provider else { return nil }
        var copy = self
        // CC-H6. `.token` is the whole of a credential that has no fields, so
        // no delivery this build performs can have written it. Narrow it to
        // nil rather than dropping the row: the row's job is to remember that
        // something is deployed at this destination, and nil is the safe
        // reading — a rotation resuming from it delivers whole, which the
        // broker refuses outright for a composite rather than sending an
        // envelope.
        if copy.sourceField == .token { copy.sourceField = nil }
        // A verification that claims to predate the delivery is not a
        // verification of this delivery.
        if let verified = copy.lastVerifiedAt, !verified.timeIntervalSince1970.isFinite || verified < copy.deliveredAt {
            copy.lastVerifiedAt = nil
        }
        if let expiry = copy.expiresAt, !expiry.timeIntervalSince1970.isFinite { copy.expiresAt = nil }
        // Status and its timestamp have to agree, in both directions.
        if copy.status == .superseded {
            if copy.supersededAt == nil || copy.supersededAt?.timeIntervalSince1970.isFinite != true { copy.supersededAt = copy.deliveredAt }
        } else {
            copy.supersededAt = nil
        }
        if copy.status == .revoked {
            if copy.revokedAt == nil || copy.revokedAt?.timeIntervalSince1970.isFinite != true { copy.revokedAt = copy.deliveredAt }
        } else {
            copy.revokedAt = nil
        }
        if let identifier = copy.providerResourceID {
            copy.providerResourceID = DeployedCredentialLedger.identifier(identifier)
        }
        // A store that returns no identifier never has one, whatever the file
        // on disk says.
        if !destination.store.returnsIdentifier { copy.providerResourceID = nil }
        copy.principal = copy.principal.flatMap { DeployedCredentialLedger.principal($0) }
        return copy
    }

    /// Whether this row's last verification is older than the advisory window.
    public func verificationIsStale(at instant: Date, window: TimeInterval = DeployedCredentialLedger.verificationFreshness) -> Bool {
        guard let lastVerifiedAt else { return true }
        return instant.timeIntervalSince(lastVerifiedAt) > window
    }
}

/// A row decoded leniently: one unreadable entry is dropped, not the file.
struct DecodedDeployedCredential: Decodable {
    let value: DeployedCredential?
    init(from decoder: Decoder) throws {
        value = try? DeployedCredential(from: decoder)
    }
}

// MARK: - The ledger's rules

public enum DeployedCredentialLedger {
    /// How long a verification counts as current on the environment card.
    /// Display only: nothing refuses to act because a row has not been verified
    /// lately, because a delivered credential keeps working whether or not this
    /// Mac has looked at it (D36).
    public static let verificationFreshness: TimeInterval = 24 * 60 * 60

    /// How close to expiry a row starts warning. Advisory.
    public static let expiryWarningWindow: TimeInterval = 14 * 24 * 60 * 60

    public static let maximumRecordsPerEnvironment = 200
    public static let maximumRecords = 2_000

    private static let fingerprintNamespace = "vaultage.deployed.fingerprint.v1"
    private static let identityNamespace = "vaultage.deployed.row.v1"

    /// **A hash of a stable identifier, not of the value.**
    ///
    /// The inputs are the vault item's id and its opaque credential version —
    /// both already public inside `metadata.json`, both already changed by a
    /// replacement. Two ledger rows share a fingerprint exactly when they were
    /// fed by the same item at the same version, which is the question the
    /// environment card and a rotation both ask. It confirms nothing about the
    /// value, so a copy of `metadata.json` is not an offline oracle for a
    /// guessed credential.
    public static func fingerprint(vaultItemID: UUID, credentialVersion: UUID?) -> String {
        String(CanonicalDigest.hex([fingerprintNamespace, vaultItemID.uuidString, credentialVersion?.uuidString ?? "none"]).prefix(32))
    }

    public static func fingerprint(of item: VaultItem) -> String {
        fingerprint(vaultItemID: item.id, credentialVersion: item.credentialVersion)
    }

    public static func isCanonicalFingerprint(_ value: String) -> Bool {
        value.count == 32 && value.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil
    }

    /// One row id per (environment, destination), derived so that re-delivering
    /// to the same destination updates the row a card is already showing.
    public static func rowID(environmentID: UUID, destination: DeliveryDestination) -> UUID {
        let hex = CanonicalDigest.hex([identityNamespace, environmentID.uuidString] + destination.canonicalFields)
        return uuid(fromHex: hex) ?? UUID()
    }

    private static func uuid(fromHex hex: String) -> UUID? {
        let characters = Array(hex.prefix(32))
        guard characters.count == 32 else { return nil }
        let grouped = String(characters[0..<8]) + "-" + String(characters[8..<12]) + "-" + String(characters[12..<16]) + "-" + String(characters[16..<20]) + "-" + String(characters[20..<32])
        return UUID(uuidString: grouped)
    }

    static func identifier(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= DeployedCredential.maximumIdentifierBytes,
              trimmed.range(of: "^[A-Za-z0-9._:/@-]+$", options: .regularExpression) != nil else { return nil }
        return trimmed
    }

    static func principal(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= DeployedCredential.maximumPrincipalBytes,
              trimmed.range(of: "^[A-Za-z0-9 ._:/@()'-]+$", options: .regularExpression) != nil else { return nil }
        return trimmed
    }

    // MARK: The repair pass

    /// The schema-16 migration and the repair pass, in one function, run on
    /// every decode exactly as `VaultOrganization.normalize` and
    /// `ResourceInventory.normalize` are.
    ///
    /// It is idempotent and it only ever removes. A ledger that was
    /// hand-edited, written by a newer build, or left behind by a project that
    /// has since been deleted comes back as a smaller ledger, never as an
    /// unreadable file and never as a row that claims more than it did.
    ///
    /// What it deliberately does **not** drop: a row whose `sourceVaultItemID`
    /// names an item that has been deleted. The value is still at the provider,
    /// and a card that silently stopped mentioning it would be lying about the
    /// environment. The projection reports it instead.
    public static func normalize(_ state: inout VaultageMetadata) {
        let environments = Dictionary(uniqueKeysWithValues: state.environments.map { ($0.id, $0) })

        var deduplicated: [String: DeployedCredential] = [:]
        for record in state.deployedCredentials {
            // A row whose environment is gone has nothing to be shown on: the
            // project cascade that removed the environment removed the binding
            // and the card with it.
            guard let environment = environments[record.environmentID], environment.projectID == record.projectID else { continue }
            guard let repaired = record.repaired else { continue }
            if let existing = deduplicated[repaired.identityKey] {
                // The newest delivery wins; a tie breaks on the id so the
                // outcome does not depend on array order.
                let newer = existing.deliveredAt == repaired.deliveredAt
                    ? (existing.id.uuidString <= repaired.id.uuidString ? existing : repaired)
                    : (existing.deliveredAt > repaired.deliveredAt ? existing : repaired)
                deduplicated[repaired.identityKey] = newer
            } else {
                deduplicated[repaired.identityKey] = repaired
            }
        }

        var kept: [DeployedCredential] = []
        var perEnvironment: [UUID: Int] = [:]
        for record in deduplicated.values.sorted(by: newestFirst) {
            guard kept.count < maximumRecords else { break }
            let count = perEnvironment[record.environmentID, default: 0]
            guard count < maximumRecordsPerEnvironment else { continue }
            perEnvironment[record.environmentID] = count + 1
            kept.append(record)
        }
        state.deployedCredentials = kept.sorted(by: displayOrder)
    }

    private static func newestFirst(_ left: DeployedCredential, _ right: DeployedCredential) -> Bool {
        if left.deliveredAt != right.deliveredAt { return left.deliveredAt > right.deliveredAt }
        return left.id.uuidString < right.id.uuidString
    }

    /// Stable display order: environment, then store, then name, then target.
    private static func displayOrder(_ left: DeployedCredential, _ right: DeployedCredential) -> Bool {
        if left.environmentID != right.environmentID { return left.environmentID.uuidString < right.environmentID.uuidString }
        if left.destination.store != right.destination.store { return left.destination.store.rawValue < right.destination.store.rawValue }
        if left.destination.name != right.destination.name { return left.destination.name < right.destination.name }
        return (left.destination.target?.rawValue ?? "") < (right.destination.target?.rawValue ?? "")
    }

    // MARK: Writing

    /// Records one completed delivery, replacing whatever the same destination
    /// held. The previous row is not kept: one destination holds one value, and
    /// a ledger that accumulated every past delivery would be a history log
    /// pretending to be a state.
    ///
    /// Returns the row that was there before, so the caller can receipt the
    /// difference and a rotation can mark the right thing superseded.
    @discardableResult
    public static func record(_ entry: DeployedCredential, in state: inout VaultageMetadata) -> DeployedCredential? {
        let previous = state.deployedCredentials.first { $0.id == entry.id }
        state.deployedCredentials.removeAll { $0.id == entry.id }
        state.deployedCredentials.append(entry)
        normalize(&state)
        return previous
    }

    /// Applies one verification outcome. Nothing else about the row moves: a
    /// verification learns whether the *name* is present, and that is all it is
    /// allowed to change.
    public static func applyVerification(rowID: UUID, present: Bool, at instant: Date, in state: inout VaultageMetadata) {
        guard let index = state.deployedCredentials.firstIndex(where: { $0.id == rowID }) else { return }
        var row = state.deployedCredentials[index]
        // A superseded or revoked row is not re-promoted by a name still being
        // present: the name being there says nothing about which value it has.
        guard row.status.isLive else { return }
        if present {
            row.status = .delivered
            row.lastVerifiedAt = instant
        } else {
            row.status = .verifyFailed
        }
        state.deployedCredentials[index] = row
    }

    /// Marks a row superseded by a rotation. Only a live row can be superseded;
    /// a revoked one stays revoked.
    public static func markSuperseded(rowID: UUID, rotationID: UUID, at instant: Date, in state: inout VaultageMetadata) {
        guard let index = state.deployedCredentials.firstIndex(where: { $0.id == rowID }), state.deployedCredentials[index].status.isLive else { return }
        state.deployedCredentials[index].status = .superseded
        state.deployedCredentials[index].supersededAt = instant
        state.deployedCredentials[index].rotationID = rotationID
    }

    /// Marks every row fed by one vault item revoked. Called when the human
    /// revokes the old credential locally at the end of a rotation, and by
    /// nothing else.
    ///
    /// A row that a rotation already marked `superseded` is included: the
    /// rotation replaced the value at the destination, and revoking the old
    /// item is the last step. What is *not* included is the newly delivered
    /// row, because it is fed by the new item and has a different
    /// `sourceVaultItemID`.
    @discardableResult
    public static func markRevoked(sourceVaultItemID: UUID, at instant: Date, in state: inout VaultageMetadata) -> Int {
        var changed = 0
        for index in state.deployedCredentials.indices
        where state.deployedCredentials[index].sourceVaultItemID == sourceVaultItemID && state.deployedCredentials[index].status != .revoked {
            state.deployedCredentials[index].status = .revoked
            state.deployedCredentials[index].supersededAt = nil
            state.deployedCredentials[index].revokedAt = instant
            changed += 1
        }
        return changed
    }

    // MARK: Reading

    public static func entries(in state: VaultageMetadata, environmentID: UUID) -> [DeployedCredential] {
        state.deployedCredentials.filter { $0.environmentID == environmentID }
    }

    public static func entries(in state: VaultageMetadata, sourceVaultItemID: UUID) -> [DeployedCredential] {
        state.deployedCredentials.filter { $0.sourceVaultItemID == sourceVaultItemID }
    }
}

// MARK: - Health, computed on demand

/// The advisory health of one environment's deployed credentials.
///
/// Computed when something asks — an environment card being drawn, a
/// `vaultage_status` call, the Connection tab. **There is no timer.** D36 is
/// explicit that health checks are advisory and never a dependency, and a
/// product whose promise is "nothing at runtime calls this Mac" must not
/// acquire a background process that has to be running for the promise to
/// hold.
public struct DeliveryHealth: Codable, Hashable, Sendable {
    public let total: Int
    public let delivered: Int
    public let verifyFailed: Int
    public let superseded: Int
    public let revoked: Int
    public let neverVerified: Int
    public let staleVerification: Int
    public let expiringSoon: Int
    public let expired: Int
    /// The most recent verification across every live row, if any.
    public let lastVerifiedAt: Date?
    /// The oldest verification across every live row, which is what "all
    /// verified 2 h ago" has to be true of.
    public let oldestVerifiedAt: Date?
    /// Advisory sentences, in the order to show them. Empty when there is
    /// nothing to say.
    public let warnings: [String]
    /// Always true, and carried so a view cannot present this as a gate.
    public let isAdvisory: Bool

    public init(total: Int, delivered: Int, verifyFailed: Int, superseded: Int, revoked: Int, neverVerified: Int, staleVerification: Int, expiringSoon: Int, expired: Int, lastVerifiedAt: Date?, oldestVerifiedAt: Date?, warnings: [String]) {
        self.total = total
        self.delivered = delivered
        self.verifyFailed = verifyFailed
        self.superseded = superseded
        self.revoked = revoked
        self.neverVerified = neverVerified
        self.staleVerification = staleVerification
        self.expiringSoon = expiringSoon
        self.expired = expired
        self.lastVerifiedAt = lastVerifiedAt
        self.oldestVerifiedAt = oldestVerifiedAt
        self.warnings = warnings
        self.isAdvisory = true
    }

    /// The rows a runtime is expected to be using right now.
    public var live: Int { delivered + verifyFailed }
}

public extension DeployedCredentialLedger {
    /// The health of an arbitrary set of rows. Pure: it takes rows and an
    /// instant, so every count and every sentence is reachable in a self-test
    /// without a Keychain, a provider or a clock.
    static func health(of rows: [DeployedCredential], at instant: Date) -> DeliveryHealth {
        let live = rows.filter { $0.status.isLive }
        let verified = live.compactMap(\.lastVerifiedAt)
        var warnings: [String] = []

        let verifyFailed = rows.filter { $0.status == .verifyFailed }
        if !verifyFailed.isEmpty {
            warnings.append("\(verifyFailed.count) \(verifyFailed.count == 1 ? "entry was" : "entries were") delivered but the last check did not list \(verifyFailed.count == 1 ? "its name" : "their names"). The deployment may still be fine; run Verify deployed to look again.")
        }
        let neverVerified = live.filter { $0.lastVerifiedAt == nil && $0.status == .delivered }
        if !neverVerified.isEmpty {
            warnings.append("\(neverVerified.count) \(neverVerified.count == 1 ? "entry has" : "entries have") never been verified since delivery.")
        }
        let stale = live.filter { $0.status == .delivered && $0.lastVerifiedAt != nil && $0.verificationIsStale(at: instant) }
        if !stale.isEmpty {
            warnings.append("\(stale.count) \(stale.count == 1 ? "entry was" : "entries were") last verified more than a day ago.")
        }
        let expired = live.filter { ($0.expiresAt.map { $0 <= instant }) == true }
        if !expired.isEmpty {
            warnings.append("\(expired.count) delivered \(expired.count == 1 ? "credential has" : "credentials have") passed the expiry the provider stated. Rotate before the deployment starts failing.")
        }
        let expiringSoon = live.filter { row in
            guard let expiry = row.expiresAt else { return false }
            return expiry > instant && expiry.timeIntervalSince(instant) <= expiryWarningWindow
        }
        if !expiringSoon.isEmpty {
            warnings.append("\(expiringSoon.count) delivered \(expiringSoon.count == 1 ? "credential expires" : "credentials expire") within two weeks.")
        }
        let superseded = rows.filter { $0.status == .superseded }
        if !superseded.isEmpty {
            warnings.append("\(superseded.count) \(superseded.count == 1 ? "entry is" : "entries are") mid-rotation: a newer credential has been delivered and the old one has not been revoked yet.")
        }

        return DeliveryHealth(
            total: rows.count,
            delivered: rows.filter { $0.status == .delivered }.count,
            verifyFailed: verifyFailed.count,
            superseded: superseded.count,
            revoked: rows.filter { $0.status == .revoked }.count,
            neverVerified: neverVerified.count,
            staleVerification: stale.count,
            expiringSoon: expiringSoon.count,
            expired: expired.count,
            lastVerifiedAt: verified.max(),
            oldestVerifiedAt: live.count == verified.count ? verified.min() : nil,
            warnings: warnings
        )
    }

    static func health(in state: VaultageMetadata, environmentID: UUID, at instant: Date) -> DeliveryHealth {
        health(of: entries(in: state, environmentID: environmentID), at: instant)
    }
}
