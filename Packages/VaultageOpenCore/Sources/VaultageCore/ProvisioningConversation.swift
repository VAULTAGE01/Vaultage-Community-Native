import Foundation

/// BL-073 — the MCP provisioning conversation.
///
/// D17, in the owner's words: an agent asked to "add provider X to staging"
/// should have the desktop check the connection, ask the human to pick or
/// create the resource, and end with a usable binding.
///
/// The conversation is **structured outcomes, never invented success**. Each
/// call returns one of the codes below; the two that need a human return
/// immediately with a pending-provisioning ID, the human acts in a native
/// approval, and the agent re-calls with that ID to learn the result. Nothing
/// blocks an MCP request on a modal sheet, and no secret value crosses MCP in
/// any outcome — the richest thing an outcome ever carries is a binding ID, a
/// vault item ID and a label.

/// The stable outcome codes. `connection_required`, `resource_selection_required`,
/// `creation_authorization_required` and `bound` are the four D17 names;
/// `provider_unsupported`, `capability_unsupported` and `request_invalid` are
/// already stable codes in `09-ENGINEERING-CONTRACTS.md` §1, and `pending`,
/// `denied`, `expired` and `failed` report the state of a human step the agent
/// is polling.
public enum ProvisioningStatus: String, Codable, CaseIterable, Sendable {
    case bound
    case connectionRequired = "connection_required"
    case resourceSelectionRequired = "resource_selection_required"
    case creationAuthorizationRequired = "creation_authorization_required"
    case providerUnsupported = "provider_unsupported"
    case capabilityUnsupported = "capability_unsupported"
    case requestInvalid = "request_invalid"
    case pending
    case denied
    case expired
    case failed
}

/// What the agent asks for.
public struct ProvisioningRequest: Hashable, Sendable {
    public let projectID: UUID
    public let environmentID: UUID
    /// Kept as the raw string the agent sent, so an unknown provider can be
    /// answered with `provider_unsupported` rather than rejected as malformed.
    public let provider: String
    public let capability: String
    /// Set when the agent is re-calling to learn the result of a human step.
    public let provisioningID: UUID?

    public init(projectID: UUID, environmentID: UUID, provider: String, capability: String, provisioningID: UUID? = nil) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.provider = provider
        self.capability = capability
        self.provisioningID = provisioningID
    }
}

/// One existing resource the human may pick, as the agent sees it: an opaque
/// identifier and the label the human gave it. Never a value, never a Keychain
/// account, never a provider token ID.
public struct ProvisioningResourceChoice: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let label: String
    public init(id: UUID, label: String) { self.id = id; self.label = label }
}

/// The reply. Every field is non-secret and most are absent for most outcomes.
public struct ProvisioningOutcome: Codable, Hashable, Sendable {
    public let status: ProvisioningStatus
    public let provider: String
    public let capability: String
    public let projectID: UUID?
    public let environmentID: UUID?
    /// Set on `bound`.
    public let bindingID: UUID?
    /// Set on `bound`: the operations that binding allows, sorted.
    public let operations: [String]
    /// Set on `resource_selection_required`, `creation_authorization_required`
    /// and `pending`. The agent re-calls with it.
    public let provisioningID: UUID?
    /// Set on `resource_selection_required`, so the agent can tell the human
    /// what is on the picker. The picker itself is native; this is a label list.
    public let choices: [ProvisioningResourceChoice]
    /// Set on `provider_unsupported` / `capability_unsupported`.
    public let supported: [String]
    /// BL-092. Cached resources that could satisfy this request without
    /// creating a second thing. Set on `creation_authorization_required` and on
    /// the `pending` that follows it — the two outcomes that are about to bring
    /// something new into existence. It is information, not a decision: the
    /// human still approves in Vaultage, and binding one of these is its own
    /// approved step.
    public let inventoryMatches: [ProvisioningInventoryMatch]
    /// The exact next step, in words a human can act on.
    public let nextStep: String

    public init(status: ProvisioningStatus, provider: String, capability: String, projectID: UUID? = nil, environmentID: UUID? = nil, bindingID: UUID? = nil, operations: [String] = [], provisioningID: UUID? = nil, choices: [ProvisioningResourceChoice] = [], supported: [String] = [], inventoryMatches: [ProvisioningInventoryMatch] = [], nextStep: String) {
        self.status = status
        self.provider = provider
        self.capability = capability
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.operations = operations
        self.provisioningID = provisioningID
        self.choices = choices
        self.supported = supported
        self.inventoryMatches = inventoryMatches
        self.nextStep = nextStep
    }

    /// The exact words `connection_required` carries. Contracts §1 already
    /// fixes this shape for `vaultage_execute`; provisioning reuses it so an
    /// agent sees one consistent instruction.
    public static func connectionRequiredNextStep(_ provider: Provider) -> String {
        "Open Services in Vaultage, connect a scoped \(provider.title) API token, and press Verify. Then call vaultage_provision again."
    }

    /// BL-099 slice 3 step (b) — the same outcome when a §5.3a connect request
    /// is open on a paired phone.
    ///
    /// **It names both places, and it names them in the same sentence.** The
    /// owner may be at the Mac or away from it, and an agent that tells them to
    /// "open Vaultage" while their phone is buzzing has sent them to the wrong
    /// room. Nothing about this sentence is value-bearing and nothing in it
    /// comes from the phone: the provider's title is compiled, and the rest is
    /// fixed copy.
    public static let remoteConnectWaitingSentence = "Connecting is waiting for you on your Mac or phone."

    public static func connectionRequiredNextStep(_ provider: Provider, waitingOnAPhone: Bool) -> String {
        guard waitingOnAPhone else { return connectionRequiredNextStep(provider) }
        return "\(provider.title) is waiting for you on your Mac or phone: approve it on your phone, or open Services in Vaultage, connect a scoped \(provider.title) API token and press Verify. Then call vaultage_provision again."
    }
}

/// What the human still has to do, persisted so it survives the MCP call that
/// created it, an app restart, and the gap before the agent re-calls.
///
/// It authorizes nothing. It is a note that a human was asked something, plus
/// the answer once they give it. Every field is an identifier or an enum; there
/// is no credential here and no policy decision is read from it — the broker
/// re-resolves and re-checks everything when it acts on the answer.
public struct PendingProvisioning: Codable, Identifiable, Hashable, Sendable {
    /// The window a human has to answer. A request the human ignores expires
    /// rather than sitting open forever, and an expired one is never acted on.
    public static let lifetime: TimeInterval = 15 * 60

    public let id: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let provider: Provider
    public let capability: ProvisioningCapability
    /// The verified connection the conversation resolved. Re-checked before use.
    public let connectionID: UUID
    /// Which human step this is: selection or creation authorization.
    public let step: Step
    /// The vault items offered on the native picker, for a selection step.
    public let choiceVaultItemIDs: [UUID]
    public let createdAt: Date
    public let expiresAt: Date
    /// Nil while the human has not answered.
    public var resolution: Resolution?

    public enum Step: String, Codable, Sendable {
        case resourceSelection, creationAuthorization

        public var status: ProvisioningStatus {
            switch self {
            case .resourceSelection: .resourceSelectionRequired
            case .creationAuthorization: .creationAuthorizationRequired
            }
        }
    }

    /// What the human decided, and nothing more.
    public enum Resolution: Codable, Hashable, Sendable {
        case bound(bindingID: UUID)
        case denied
        case failed(message: String)
    }

    public init(id: UUID = UUID(), projectID: UUID, environmentID: UUID, provider: Provider, capability: ProvisioningCapability, connectionID: UUID, step: Step, choiceVaultItemIDs: [UUID] = [], createdAt: Date = .now, expiresAt: Date? = nil, resolution: Resolution? = nil) {
        self.id = id
        self.projectID = projectID
        self.environmentID = environmentID
        self.provider = provider
        self.capability = capability
        self.connectionID = connectionID
        self.step = step
        self.choiceVaultItemIDs = choiceVaultItemIDs
        self.createdAt = createdAt
        self.expiresAt = expiresAt ?? createdAt.addingTimeInterval(Self.lifetime)
        self.resolution = resolution
    }

    public func isOpen(at instant: Date) -> Bool { resolution == nil && expiresAt > instant }
    public func isExpired(at instant: Date) -> Bool { resolution == nil && expiresAt <= instant }

    /// Whether this record answers the same question as `request`. Idempotency
    /// per (project, environment, provider, capability) is built on this: a
    /// repeated ask reuses the open request instead of stacking a second sheet.
    public func matches(projectID: UUID, environmentID: UUID, provider: Provider, capability: ProvisioningCapability) -> Bool {
        self.projectID == projectID && self.environmentID == environmentID && self.provider == provider && self.capability == capability
    }
}

/// The pure decision function behind `vaultage_provision`.
///
/// It is deliberately separate from the broker and takes metadata by value, so
/// every outcome is reachable in a self-test without a Keychain, a network or a
/// modal sheet — and so the ordering of the checks is reviewable in one place.
public enum ProvisioningPolicy {
    /// The outcome of inspecting state, before anything is persisted.
    public enum Decision: Hashable, Sendable {
        case bound(binding: Binding)
        case connectionRequired(Provider)
        case resourceSelection(connectionID: UUID, vaultItemIDs: [UUID])
        case creationAuthorization(connectionID: UUID)
    }

    /// Resolves the request against current metadata.
    ///
    /// Order matters and is the D17 order: connection first, then an existing
    /// binding, then existing resources, then creation.
    public static func decide(
        projectID: UUID,
        environmentID: UUID,
        provider: Provider,
        capability: ProvisioningCapability,
        in state: VaultageMetadata,
        now: Date
    ) throws -> Decision {
        guard let project = state.projects.first(where: { $0.id == projectID }),
              let environment = state.environments.first(where: { $0.id == environmentID }),
              environment.projectID == project.id else {
            throw VaultageError.invalidInput("That project and environment do not exist, or the environment is not in that project.")
        }

        // 1. Is there a verified connection for this provider at all?
        //
        // Unverified and failed connections do not count. A connection whose
        // credential is being deleted does not count either. This is the same
        // standard every execution path applies, so provisioning cannot produce
        // a binding that the next `vaultage_execute` would refuse.
        let usableConnections = state.connections.filter { connection in
            guard connection.provider == provider, connection.state == .verified, connection.pauseReason == nil,
                  let item = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
                  item.provider == provider,
                  MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil,
                  let evidence = connection.verification,
                  evidence.providerExpiresAt.map({ $0 > now }) ?? true else { return false }
            return true
        }
        guard let connection = usableConnections.first else {
            return .connectionRequired(provider)
        }

        // 2. Does a binding already cover the capability? Idempotency: a second
        //    identical ask returns the same binding rather than making another.
        let connectionIDs = Set(usableConnections.map(\.id))
        if let existing = state.bindings.first(where: { binding in
            binding.projectID == projectID && binding.environmentID == environmentID
                && connectionIDs.contains(binding.connectionID)
                && capability.isCovered(by: binding)
        }) {
            return .bound(binding: existing)
        }

        // 3. Are there existing resources usable for the capability?
        //
        // For Cloudflare: vault items of this provider already authorized for
        // this environment — that is, named by a runtime-source authorization
        // in this exact project and environment, or created here by a previous
        // provisioning. A connection's own managing credential is excluded: it
        // is the token that creates others, not a resource to bind.
        let managingItemIDs = Set(state.connections.map(\.vaultItemID))
        var candidateIDs: [UUID] = []
        var seen: Set<UUID> = []
        for authorization in state.runtimeSourceAuthorizations
        where authorization.projectID == projectID && authorization.environmentID == environmentID {
            guard let item = state.vaultItems.first(where: { $0.id == authorization.sourceVaultItemID }),
                  item.provider == provider,
                  !managingItemIDs.contains(item.id),
                  MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil,
                  seen.insert(item.id).inserted else { continue }
            candidateIDs.append(item.id)
        }
        for record in state.provisionedResources
        where record.projectID == projectID && record.environmentID == environmentID && record.provider == provider && record.isLive {
            guard let item = state.vaultItems.first(where: { $0.id == record.vaultItemID }),
                  !managingItemIDs.contains(item.id),
                  MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil,
                  seen.insert(item.id).inserted else { continue }
            candidateIDs.append(item.id)
        }
        if !candidateIDs.isEmpty {
            return .resourceSelection(connectionID: connection.id, vaultItemIDs: candidateIDs)
        }

        // 4. Nothing exists. The human must authorize creating one.
        return .creationAuthorization(connectionID: connection.id)
    }

    /// Drops expired, unanswered requests and answered ones past their window.
    /// Housekeeping only: it is called inside the same locked update that reads
    /// them, so a stale record can never be acted on.
    public static func purge(_ state: inout VaultageMetadata, now: Date) {
        state.pendingProvisionings.removeAll { record in
            // An unanswered request dies at its expiry. An answered one is kept
            // for one further lifetime so a slow agent can still collect the
            // result, then dropped.
            record.resolution == nil
                ? record.expiresAt <= now
                : record.expiresAt.addingTimeInterval(PendingProvisioning.lifetime) <= now
        }
    }

    /// The label list for a selection outcome.
    public static func choices(for record: PendingProvisioning, in state: VaultageMetadata) -> [ProvisioningResourceChoice] {
        record.choiceVaultItemIDs.compactMap { id in
            state.vaultItems.first(where: { $0.id == id }).map { ProvisioningResourceChoice(id: $0.id, label: $0.label) }
        }
    }
}
