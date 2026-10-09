import Foundation

/// BL-074 / BL-073 — provider resource creation and the MCP provisioning
/// conversation.
///
/// Two rules shape every type in this file, and both come from D17 read against
/// the security boundaries in `03-SECURITY-RESEARCH.md` §4 and §5:
///
/// 1. **A created credential is a vault item, not a result.** The value a
///    provider returns once at creation is written straight into the Keychain
///    and linked to a connection, a project and an environment. It is never a
///    field on anything `Codable`, never a receipt field, and never crosses MCP.
/// 2. **Creating authority is its own approval class.** `Operation` is the set
///    of actions an *agent* may ask a binding to run; resource creation and
///    revocation are deliberately **not** members of it. They live in
///    `ProviderResourceOperation`, which no MCP tool schema names and no
///    binding can allow, so no auto-allow grant and no `vaultage_execute`
///    argument can reach them. The only path in is a native approval.

// MARK: - Resource operations (deliberately not `Operation`)

/// The typed provider-resource lifecycle actions. Compare `Operation`: that
/// enum is enumerated into the `vaultage_execute` tool schema and stored in
/// `Binding.allowedOperations`. This one is in neither, by construction.
public enum ProviderResourceOperation: String, Codable, CaseIterable, Sendable {
    case cloudflareTokenCreate = "cloudflare.token.create"
    case cloudflareTokenRevoke = "cloudflare.token.revoke"

    public var provider: Provider { .cloudflare }

    /// Human wording for the approval sheet's `Action:` line.
    public var title: String {
        switch self {
        case .cloudflareTokenCreate: "Create a scoped Cloudflare API token"
        case .cloudflareTokenRevoke: "Revoke a Cloudflare API token Vaultage created"
        }
    }
}

/// What kind of thing was created. One case today; the enum exists so a receipt
/// and a stored record name the resource class rather than implying "token"
/// everywhere.
public enum ProviderResourceKind: String, Codable, CaseIterable, Sendable {
    case cloudflareAPIToken = "cloudflare.api_token"

    public var title: String {
        switch self { case .cloudflareAPIToken: "API token" }
    }
}

// MARK: - Capabilities

/// What the human wants the environment to be able to do. This is the
/// `capability` an agent names in `vaultage_provision`.
///
/// A capability is **intent**, and it decides exactly two things: which
/// reviewed policy template a newly created token is given, and which
/// `Operation`s the resulting binding allows. Those are not the same set and
/// must not be conflated — see `bindingOperations`.
public enum ProvisioningCapability: String, Codable, CaseIterable, Sendable {
    /// Deploy and update Workers scripts in one Cloudflare account.
    case cloudflareWorkersDeploy = "cloudflare.workers.deploy"
    /// Edit DNS records in one Cloudflare zone.
    case cloudflareDNSEdit = "cloudflare.dns.edit"

    public var provider: Provider { .cloudflare }

    public var title: String {
        switch self {
        case .cloudflareWorkersDeploy: "Deploy Workers scripts"
        case .cloudflareDNSEdit: "Edit DNS records"
        }
    }

    /// The reviewed policy template a token created for this capability gets.
    public var policyTemplate: CloudflareTokenPolicyTemplate {
        switch self {
        case .cloudflareWorkersDeploy: .workersScriptsEditForOneAccount
        case .cloudflareDNSEdit: .dnsEditForOneZone
        }
    }

    /// The operations the binding created by provisioning allows.
    ///
    /// This is deliberately **narrower than the token's own policy**, and the
    /// asymmetry is the point. The token is scoped so the *human's* tooling can
    /// deploy a Worker or edit DNS. What Vaultage itself may do with that token
    /// on an agent's behalf is a separate question, and today the only
    /// Cloudflare operation it can answer without a destination the human has
    /// not yet named is the fixed verification probe.
    ///
    /// `cloudflare.worker.secret.put` is specifically excluded. It needs an
    /// immutable bound account, Worker and variable name, and its own approval
    /// sheet discloses immediate deployment (BL-059, contracts §7). A
    /// provisioning conversation that has not asked for any of that must not
    /// hand out a binding that allows it; the human adds that destination
    /// deliberately, in the app, which is where those three values are chosen.
    public var bindingOperations: Set<Operation> {
        switch self {
        case .cloudflareWorkersDeploy, .cloudflareDNSEdit: [.cloudflareVerifyToken]
        }
    }

    /// BL-091. The operations this capability's binding may allow **once the
    /// human has attached a resource scope to it** — the zone, or the account
    /// and Worker script, that the paragraph above says provisioning has not
    /// asked for.
    ///
    /// Nothing here is granted by `vaultage_provision`: `bindingOperations`
    /// above is still what a provisioning-created binding allows, and it is
    /// still only the verification probe. This set is the ceiling that
    /// `VaultageBroker.bindProviderResource` — desktop-only, its own approval
    /// sheet — may widen a binding to when the human names the resource. So the
    /// conversation's shape is unchanged and the answer to "can provisioning
    /// bind a resource created this way?" is: the conversation produces the
    /// binding, and the human attaches the resource to it in one more approved
    /// step that names exactly which zone or Worker it is.
    ///
    /// `cloudflare.worker.secret.put` stays excluded for the reason above: it
    /// needs a *variable name* as well, which is a third thing nobody has
    /// named, and its own sheet discloses immediate deployment.
    public var resourceOperations: Set<Operation> {
        switch self {
        case .cloudflareWorkersDeploy: [.cloudflareVerifyToken, .cloudflareWorkerScriptList, .cloudflareWorkerSecretNameList]
        case .cloudflareDNSEdit: [.cloudflareVerifyToken, .cloudflareDNSRecordList, .cloudflareDNSRecordCreate, .cloudflareDNSRecordUpdate, .cloudflareDNSRecordDelete]
        }
    }

    /// BL-092. The scope kinds this capability's operations run against, and
    /// therefore the kinds of cached resource that could satisfy the request
    /// instead of creating something new. Derived from `resourceOperations`, so
    /// a capability added later checks the inventory by construction.
    public var inventoryScopeKinds: Set<ProviderResourceScopeKind> {
        Set(resourceOperations.flatMap { ProviderResourceScope.kinds(for: $0) })
    }

    /// The capabilities a provider offers, for `capability_unsupported`
    /// messages and for the Services screen.
    public static func supported(for provider: Provider) -> [ProvisioningCapability] {
        allCases.filter { $0.provider == provider }
    }

    /// Whether an existing binding already covers this capability.
    public func isCovered(by binding: Binding) -> Bool {
        bindingOperations.isSubset(of: binding.allowedOperations)
    }
}

/// The providers `vaultage_provision` can currently run a conversation for.
/// A provider outside this set is `provider_unsupported`, not an error.
public enum ProvisioningSupport {
    public static let providers: Set<Provider> = [.cloudflare]

    public static func isSupported(_ provider: Provider) -> Bool {
        providers.contains(provider) && !ProvisioningCapability.supported(for: provider).isEmpty
    }
}

// MARK: - The reviewed Cloudflare policy template list

/// The scope string a Cloudflare permission group declares.
///
/// Cloudflare's permission groups carry a `scopes` array naming the resource
/// class they may be applied to. A template pins the one it expects, so a
/// permission group whose name matches but whose scope does not is refused
/// rather than silently applied to the wrong resource.
public enum CloudflarePermissionScope: String, Codable, Sendable {
    case account = "com.cloudflare.api.account"
    case zone = "com.cloudflare.api.account.zone"
}

/// One reviewed, minimal token policy.
///
/// The template list is the security review surface named by BL-074: adding a
/// template means adding a new minimum permission to a signed release, and a
/// remote catalogue update cannot introduce one (`03-SECURITY-RESEARCH.md` §4).
/// Two templates ship in the first slice.
///
/// `permissionGroupNames` is an ordered, exact-match allowlist rather than a
/// hardcoded permission-group ID. Cloudflare documents that IDs are looked up
/// via `GET /user/tokens/permission_groups`, and the adapter does exactly that;
/// hardcoding an ID would bake a value the docs tell callers to resolve. More
/// than one name is listed because Cloudflare's own documentation is not
/// self-consistent about the Workers group's API name ("Workers Scripts Edit"
/// in the permissions reference, "Workers Scripts Write" in older material).
/// Resolution still fails closed: the adapter requires **exactly one** live
/// permission group matching any listed name *and* declaring `requiredScope`,
/// and refuses to create a token otherwise.
public struct CloudflareTokenPolicyTemplate: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    /// The exact words the approval sheet shows. BL-074 requires the sheet to
    /// name "the exact policy template", so this string is a contract.
    public let displayName: String
    public let permissionGroupNames: [String]
    public let requiredScope: CloudflarePermissionScope
    /// What the human must have chosen for the policy's `resources` map: an
    /// account on its own, or an account and one of its zones.
    public let targetKind: CloudflareTokenTargetKind
    /// One sentence naming what the token will be able to do, for the sheet.
    public let effect: String

    public static let workersScriptsEditForOneAccount = CloudflareTokenPolicyTemplate(
        id: "cloudflare.workers_scripts_edit.account.v1",
        displayName: "Workers Scripts Edit for one account",
        permissionGroupNames: ["Workers Scripts Edit", "Workers Scripts Write"],
        requiredScope: .account,
        targetKind: .account,
        effect: "Create, update and delete Workers scripts in this one account. It grants no DNS, zone, billing or account-settings access."
    )

    public static let dnsEditForOneZone = CloudflareTokenPolicyTemplate(
        id: "cloudflare.dns_edit.zone.v1",
        displayName: "Zone DNS Edit for one zone",
        permissionGroupNames: ["DNS Write", "Zone DNS Edit", "DNS Records Write"],
        requiredScope: .zone,
        targetKind: .zone,
        effect: "Read and change DNS records in this one zone. It grants no access to other zones, to Workers, to billing or to account settings."
    )

    /// The whole reviewed list, in one place so a self-test can assert its size
    /// and a security review can read it without searching.
    public static let all: [CloudflareTokenPolicyTemplate] = [
        .workersScriptsEditForOneAccount,
        .dnsEditForOneZone
    ]

    public static func template(id: String) -> CloudflareTokenPolicyTemplate? {
        all.first { $0.id == id }
    }
}

public enum CloudflareTokenTargetKind: String, Codable, Sendable {
    case account, zone
}

/// The exact Cloudflare resource a created token is scoped to.
///
/// Both identifiers are validated as Cloudflare's canonical 32-character
/// lowercase hexadecimal IDs before they are ever interpolated into a policy
/// body. They are non-secret identifiers and appear on the approval sheet.
public struct CloudflareTokenTarget: Codable, Hashable, Sendable {
    public let accountID: String
    /// Required for a zone-scoped template, refused for an account-scoped one.
    public let zoneID: String?

    public init(accountID: String, zoneID: String? = nil) {
        self.accountID = accountID
        self.zoneID = zoneID
    }

    public static func isCanonicalID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil
    }

    /// Fails closed against the template: an account template carrying a zone,
    /// or a zone template missing one, is refused rather than normalized.
    public func validated(for template: CloudflareTokenPolicyTemplate) throws -> CloudflareTokenTarget {
        guard Self.isCanonicalID(accountID) else {
            throw VaultageError.invalidInput("A Cloudflare account ID must be 32 lowercase hexadecimal characters.")
        }
        switch template.targetKind {
        case .account:
            guard zoneID == nil else {
                throw VaultageError.invalidInput("The \(template.displayName) template is scoped to an account and takes no zone.")
            }
        case .zone:
            guard let zoneID, Self.isCanonicalID(zoneID) else {
                throw VaultageError.invalidInput("The \(template.displayName) template needs a zone ID of 32 lowercase hexadecimal characters.")
            }
        }
        return self
    }

    /// The policy `resources` map Cloudflare documents.
    ///
    /// Account scope keys on `com.cloudflare.api.account.<id>`; zone scope keys
    /// on `com.cloudflare.api.account.zone.<id>`. Both IDs are already
    /// constrained to `[0-9a-f]{32}`, so no caller-supplied text can reshape
    /// the key.
    public func resourceMap(for template: CloudflareTokenPolicyTemplate) throws -> [String: String] {
        let checked = try validated(for: template)
        switch template.targetKind {
        case .account:
            return ["com.cloudflare.api.account.\(checked.accountID)": "*"]
        case .zone:
            return ["com.cloudflare.api.account.zone.\(checked.zoneID!)": "*"]
        }
    }

    /// The line the approval sheet shows under `Account:`.
    public var sheetDescription: String {
        zoneID.map { "account \(accountID), zone \($0)" } ?? "account \(accountID)"
    }
}

// MARK: - Creation request and disclosure

/// The label a created vault item is given. It is human-entered display text on
/// the same footing as a connection label, and it is bounded the same way: it
/// reaches the approval sheet, the vault list and the receipt's *name* fields.
public enum ProvisionedResourceLabel {
    public static let maximumLength = 80

    public static func validated(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultageError.invalidInput("A label is required for the new vault item.") }
        guard trimmed.utf8.count <= maximumLength else {
            throw VaultageError.invalidInput("That label is too long; use at most \(maximumLength) characters.")
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("A label cannot contain control characters or line breaks.")
        }
        return trimmed
    }

    /// The `name` Cloudflare records for the token. Cloudflare bounds it to 120
    /// characters; this derives it from the validated label plus a fixed prefix
    /// so the owner can recognize it in the Cloudflare dashboard.
    public static func providerTokenName(for label: String) -> String {
        let cleaned = label.unicodeScalars.filter {
            CharacterSet.alphanumerics.contains($0) || $0 == " " || $0 == "-" || $0 == "_" || $0 == "."
        }
        let compact = String(String.UnicodeScalarView(cleaned)).trimmingCharacters(in: .whitespaces)
        let body = compact.isEmpty ? "token" : String(compact.prefix(90))
        return "Vaultage: \(body)"
    }
}

/// Everything the broker needs to create one provider resource.
public struct ProviderResourceCreationRequest: Hashable, Sendable {
    public let projectID: UUID
    public let environmentID: UUID
    public let connectionID: UUID
    public let capability: ProvisioningCapability
    public let target: CloudflareTokenTarget
    public let label: String

    public init(projectID: UUID, environmentID: UUID, connectionID: UUID, capability: ProvisioningCapability, target: CloudflareTokenTarget, label: String) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.connectionID = connectionID
        self.capability = capability
        self.target = target
        self.label = label
    }
}

/// The sheet's contract for BL-074: provider, account, resource kind, the exact
/// policy template, and the project/environment. Every field is non-secret.
public struct ProviderResourceCreationDisclosure: Sendable, Hashable, Codable {
    public let provider: String
    public let accountDescription: String
    public let resourceKind: String
    public let templateDisplayName: String
    public let templateEffect: String
    public let permissionGroupNames: [String]
    public let project: String
    public let environment: String
    public let isProduction: Bool
    public let vaultLabel: String
    public let requestDigest: String

    public init(provider: String, accountDescription: String, resourceKind: String, templateDisplayName: String, templateEffect: String, permissionGroupNames: [String], project: String, environment: String, isProduction: Bool, vaultLabel: String, requestDigest: String) {
        self.provider = provider
        self.accountDescription = accountDescription
        self.resourceKind = resourceKind
        self.templateDisplayName = templateDisplayName
        self.templateEffect = templateEffect
        self.permissionGroupNames = permissionGroupNames
        self.project = project
        self.environment = environment
        self.isProduction = isProduction
        self.vaultLabel = vaultLabel
        self.requestDigest = requestDigest
    }

    /// The sentence that must appear on every creation sheet. It is the one
    /// promise BL-074 makes about where the value goes.
    public static let custodySentence = "The new token's value is shown to Cloudflare once and written straight into your Keychain as a protected vault item. Vaultage never returns it to the MCP client, never writes it to a receipt, and never puts it in a log."

    public static let productionWarning = "This is a PRODUCTION environment. The token created here will be able to change production resources."
}

/// The sheet's contract for a revocation.
public struct ProviderResourceRevocationDisclosure: Sendable, Hashable, Codable {
    public let provider: String
    public let resourceKind: String
    public let providerResourceID: String
    public let vaultLabel: String
    public let project: String
    public let environment: String
    public let requestDigest: String

    public init(provider: String, resourceKind: String, providerResourceID: String, vaultLabel: String, project: String, environment: String, requestDigest: String) {
        self.provider = provider
        self.resourceKind = resourceKind
        self.providerResourceID = providerResourceID
        self.vaultLabel = vaultLabel
        self.project = project
        self.environment = environment
        self.requestDigest = requestDigest
    }

    /// **D44c (owner decision D44, `blueprint/backlog/bl-074-…md` §2), corrected
    /// 2026-09-13.** This sentence predated D44c's sweep and kept saying the
    /// old, pre-D44c behaviour after the broker changed under it —
    /// `blueprint/evidence/ui-lane-d44-wordlist-walk-2026-09-13.md`, "One thing
    /// to know from the merge". It must describe `VaultageBroker
    /// .revokeProviderResource`'s real order (§2.2 there): Cloudflare is asked
    /// first; **only if it confirms** is the protected value deleted from this
    /// Mac, with the value-free record kept, marked revoked, for audit; if it
    /// does not confirm, **nothing local is deleted** and the token may still
    /// be live. The old sentence claimed the opposite of the confirmed case —
    /// "stays in your vault until you delete it separately" — which stopped
    /// being true the moment D44c shipped the sweep.
    public static let effectSentence = "Vaultage asks Cloudflare to revoke this token first. If Cloudflare confirms, anything still using it stops working and the protected value is deleted from this Mac; the value-free record is kept, marked revoked, for audit. If Cloudflare does not confirm, nothing is deleted here and the token may still be live."
}

// MARK: - Adapter boundary

/// What the adapter needs in order to build the one approved POST body. The
/// broker assembles this only after the human has approved the template.
public struct CloudflareTokenCreationPlan: Sendable {
    public let template: CloudflareTokenPolicyTemplate
    public let target: CloudflareTokenTarget
    public let tokenName: String

    public init(template: CloudflareTokenPolicyTemplate, target: CloudflareTokenTarget, tokenName: String) {
        self.template = template
        self.target = target
        self.tokenName = tokenName
    }
}

/// A created provider resource: bounded non-secret projection plus the value.
///
/// This type is deliberately **not** `Codable` and its `description` is
/// redacted, so it cannot be encoded into a receipt, an MCP result or a log by
/// accident. The `value` is a `VaultSecret`, which has no printable form and
/// zeroes its allocation on release.
public struct CreatedProviderResource: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let kind: ProviderResourceKind
    /// Cloudflare's token ID. Bounded to `[0-9a-f]{32}` by the adapter before
    /// it is accepted, so provider text cannot reshape metadata or a sheet.
    public let providerResourceID: String
    public let name: String
    public let status: String
    public let expiresAt: Date?
    public let value: VaultSecret

    public init(kind: ProviderResourceKind, providerResourceID: String, name: String, status: String, expiresAt: Date? = nil, value: VaultSecret) {
        self.kind = kind
        self.providerResourceID = providerResourceID
        self.name = name
        self.status = status
        self.expiresAt = expiresAt
        self.value = value
    }

    /// The value-free projection that is safe to put in a receipt.
    public var receiptFields: [String: String] {
        var fields = [
            "provider": "cloudflare",
            "resource_kind": kind.rawValue,
            "resource_id": providerResourceID,
            "resource_name": name,
            "status": status,
            "value_returned_to_mcp": "false",
            "value_stored": "keychain"
        ]
        if let expiresAt { fields["expires_on"] = ISO8601DateFormatter().string(from: expiresAt) }
        return fields
    }

    public var description: String { "CreatedProviderResource(\(providerResourceID), value: redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// The value-free result of a revocation.
public struct ProviderResourceRevocation: Codable, Hashable, Sendable {
    public let providerResourceID: String
    public let revoked: Bool

    public init(providerResourceID: String, revoked: Bool) {
        self.providerResourceID = providerResourceID
        self.revoked = revoked
    }
}

/// The compiled-adapter seam for BL-074.
///
/// It is a separate protocol from `ProviderExecutor` and
/// `RuntimeProviderExecutor` for the same reason `HumanDisclosure` is separate
/// from `BrokerFacade`: a composition that has not been given a resource
/// creator cannot create a resource, and there is no runtime flag that changes
/// that.
public protocol ProviderResourceCreating: Sendable {
    /// Resolves the template's permission group, then creates the token.
    ///
    /// - Parameter managingToken: the connection's own Cloudflare token, which
    ///   must itself carry token-creation permission. Vaultage cannot attest
    ///   that it does — `/user/tokens/verify` does not report policies — so the
    ///   provider enforces it on the POST and a 403 surfaces as
    ///   `permissionMissing`.
    func createCloudflareToken(managingToken: VaultSecret, plan: CloudflareTokenCreationPlan) async throws -> CreatedProviderResource
    func revokeCloudflareToken(managingToken: VaultSecret, tokenID: String) async throws -> ProviderResourceRevocation
}

// MARK: - The durable record of what was created

/// A value-free record that Vaultage created one provider resource for one
/// project environment. It is the link BL-074 requires between the created
/// item, the connection that created it, and the target project/environment,
/// and it is what makes `cloudflare.token.revoke` possible later: the provider
/// resource ID lives here, never in the Keychain payload.
public struct ProvisionedResource: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public let provider: Provider
    public let kind: ProviderResourceKind
    /// Cloudflare's token ID, `[0-9a-f]{32}`.
    public let providerResourceID: String
    /// The vault item holding the created value.
    public let vaultItemID: UUID
    /// The connection whose token created it.
    public let connectionID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    /// The binding the created item was authorized as a runtime source for.
    public let bindingID: UUID
    public let capability: ProvisioningCapability
    public let templateID: String
    public let createdAt: Date
    /// BL-094. The expiry the provider stated when it created this credential,
    /// when it stated one. It is the only place in this product that knows a
    /// deployed credential's expiry, and the deployed-credential ledger copies
    /// it onto a row at delivery time so the environment card can warn. Nil
    /// means "the provider did not say", never "it does not expire" — and
    /// Cloudflare's scoped tokens are commonly created without one.
    public var expiresAt: Date?
    public var revokedAt: Date?
    /// Set when a revocation was attempted and the provider did not confirm it.
    /// BL-074: "failure to revoke is reported honestly."
    public var revocationFailedAt: Date?
    /// D44c (owner decision **D44**). When the protected Keychain value behind
    /// `vaultItemID` was deleted, after — and only after — the provider
    /// confirmed the token was revoked.
    ///
    /// Three states, and the difference between the last two is the whole point
    /// of the field:
    ///
    /// - `revokedAt == nil` — live. The value is there because the token is.
    /// - `revokedAt != nil, valueSweptAt != nil` — revoked and swept. The
    ///   provider confirmed, and the dead value is gone from this Mac. This is
    ///   the normal outcome.
    /// - `revokedAt != nil, valueSweptAt == nil` — revoked at the provider, but
    ///   the local protected value could **not** be deleted. The token is dead,
    ///   so nothing can be done with the value; but a Keychain record still
    ///   exists, and saying it does not would be the false state BL-074 spends
    ///   most of its text avoiding. The receipt says so too.
    ///
    /// It is never set without `revokedAt`, and nothing sets it on a failed
    /// revocation: D44c's rule is "never delete before the provider confirms",
    /// and this stamp is the record that the order was kept.
    public var valueSweptAt: Date?

    public init(id: UUID = UUID(), provider: Provider, kind: ProviderResourceKind, providerResourceID: String, vaultItemID: UUID, connectionID: UUID, projectID: UUID, environmentID: UUID, bindingID: UUID, capability: ProvisioningCapability, templateID: String, createdAt: Date = .now, expiresAt: Date? = nil, revokedAt: Date? = nil, revocationFailedAt: Date? = nil, valueSweptAt: Date? = nil) {
        self.id = id
        self.provider = provider
        self.kind = kind
        self.providerResourceID = providerResourceID
        self.vaultItemID = vaultItemID
        self.connectionID = connectionID
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.capability = capability
        self.templateID = templateID
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.revocationFailedAt = revocationFailedAt
        self.valueSweptAt = valueSweptAt
    }

    public var isLive: Bool { revokedAt == nil }

    /// D44c. A revoked record whose protected value is still on this Mac. The
    /// UI's third row state — "Revoked — the local value could not be deleted"
    /// — reads this, and it is the only state in which a revoked record still
    /// has something to clean up.
    public var hasUnsweptValue: Bool { revokedAt != nil && valueSweptAt == nil }
}

/// The value-free result of a successful creation. It is what
/// `createProviderResource` returns and what BL-073 turns into a `bound`
/// outcome: identifiers, a human label and operation names. No value, no
/// Keychain account, no provider policy body.
public struct ProviderResourceSummary: Codable, Hashable, Sendable {
    public let provisionedResourceID: UUID
    public let vaultItemID: UUID
    public let bindingID: UUID
    public let connectionID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let providerResourceID: String
    public let label: String
    public let capability: ProvisioningCapability
    public let operations: [String]

    public init(provisionedResourceID: UUID, vaultItemID: UUID, bindingID: UUID, connectionID: UUID, projectID: UUID, environmentID: UUID, providerResourceID: String, label: String, capability: ProvisioningCapability, operations: [String]) {
        self.provisionedResourceID = provisionedResourceID
        self.vaultItemID = vaultItemID
        self.bindingID = bindingID
        self.connectionID = connectionID
        self.projectID = projectID
        self.environmentID = environmentID
        self.providerResourceID = providerResourceID
        self.label = label
        self.capability = capability
        self.operations = operations
    }
}
