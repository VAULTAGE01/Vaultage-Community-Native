import Foundation
import CryptoKit

public struct ApprovalDetails: Sendable, Hashable {
    public let project: String
    public let environment: String
    public let provider: String
    public let connection: String
    public let operation: String
    public let reason: String
    /// BL-069. Who the broker resolved the caller to be, for the "Client:" line
    /// every sheet carries. It is a label: no value of this field widens,
    /// narrows or skips any approval.
    public let client: ClientIdentity
    /// Set for local `--run` credential delivery into a child process — its
    /// own approval class, never on a sheet with any other disclosure here.
    public let runtimeInjection: RuntimeInjectionDisclosure?
    /// BL-060. Set only on the sheet that creates an auto-allow grant. It is
    /// never set on an action sheet: a grant is approved on its own, once, and
    /// an action is never quietly turned into one.
    public let grant: GrantDisclosure?
    /// BL-074. Set only on the sheet that creates a provider resource. Like the
    /// grant sheet, this one authorizes something the other sheets do not: it
    /// brings a *new* credential into existence.
    public let providerResourceCreation: ProviderResourceCreationDisclosure?
    /// BL-074. Set only on the separate revocation sheet.
    public let providerResourceRevocation: ProviderResourceRevocationDisclosure?
    /// BL-091. Set on every provider resource operation sheet: the three lines
    /// D34's copy rule requires, in order — resource, action, safety — plus the
    /// exact resource id for an update or a delete.
    public let resourceOperation: ResourceOperationDisclosure?
    /// BL-094. Set on the orchestrated delivery sheet: the exact destination a
    /// vault value is about to be written into, and the continuity promise.
    /// Never set on the same sheet as `runtimeInjection`, BL-059's local
    /// `--run`: two approval classes, two sheets. (D71: BL-051's single Worker
    /// PUT is this delivery now, and has no sheet of its own.)
    public let credentialDelivery: CredentialDeliveryDisclosure?
    /// BL-094. Set on the "verify deployed" sheet, which lists destination
    /// names and changes nothing.
    public let deployedVerification: DeployedVerificationDisclosure?

    public init(
        project: String,
        environment: String,
        provider: String,
        connection: String,
        operation: String,
        reason: String,
        client: ClientIdentity = .unenrolled(.notPresented),
        runtimeInjection: RuntimeInjectionDisclosure? = nil,
        grant: GrantDisclosure? = nil,
        providerResourceCreation: ProviderResourceCreationDisclosure? = nil,
        providerResourceRevocation: ProviderResourceRevocationDisclosure? = nil,
        resourceOperation: ResourceOperationDisclosure? = nil,
        credentialDelivery: CredentialDeliveryDisclosure? = nil,
        deployedVerification: DeployedVerificationDisclosure? = nil
    ) {
        self.credentialDelivery = credentialDelivery
        self.deployedVerification = deployedVerification
        self.providerResourceCreation = providerResourceCreation
        self.providerResourceRevocation = providerResourceRevocation
        self.resourceOperation = resourceOperation
        self.project = project
        self.environment = environment
        self.provider = provider
        self.connection = connection
        self.operation = operation
        self.reason = reason
        self.client = client
        self.runtimeInjection = runtimeInjection
        self.grant = grant
    }
}

/// BL-094. The sheet for "verify deployed": one native approval per store, and
/// it discloses that Vaultage is about to ask the provider which names exist.
/// It writes nothing and reads no value.
public struct DeployedVerificationDisclosure: Codable, Sendable, Hashable {
    public let store: SecretStore
    public let scopeLabel: String
    public let project: String
    public let environment: String
    /// How many ledger rows this check covers.
    public let entryCount: Int
    public let requestDigest: String

    public init(store: SecretStore, scopeLabel: String, project: String, environment: String, entryCount: Int, requestDigest: String) {
        self.store = store
        self.scopeLabel = scopeLabel
        self.project = project
        self.environment = environment
        self.entryCount = entryCount
        self.requestDigest = requestDigest
    }

    /// The one sentence the sheet must carry. It is the read's whole contract:
    /// names, never values, and nothing is changed.
    public static let safetySentence = "Vaultage will ask the provider which entry names exist at this destination and compare them with what it recorded. It lists names only, never values, it changes nothing, and it is advisory: a delivered credential keeps working whether or not this check runs."

    public var actionLine: String {
        "List the \(store.inlineLabel) names on \(scopeLabel) and compare them with the \(entryCount) \(entryCount == 1 ? "entry" : "entries") Vaultage recorded for \(environment)."
    }
}

/// BL-117 (D51) §7.2 and §2.3. What the **connection** and the **approved
/// action** contribute to one provider call, as opposed to what the operation
/// contributes.
///
/// D44a's `region` was the first of these and travelled as a bare `String?`.
/// The Azure slot adds three more — the tenant that fills one compiled path
/// segment, and the two ids Rule C's cache is keyed on — and four positional
/// parameters on an executor method is how a call site ends up passing the
/// connection id where the action id belongs. So they travel together, in the
/// order they are read.
public struct ProviderConnectionContext: Sendable, Hashable {
    /// Rule C's first key half.
    public let connectionID: UUID
    /// Rule C's second key half: the broker's own invocation id for the
    /// approved action this call runs inside. Minted per approved request, so a
    /// cached token is never reachable from a second action.
    public let approvedActionID: UUID
    /// D44a. Which documented region this connection reaches.
    public let region: String?
    /// BL-117 §7.2. Which tenant this connection operates against.
    public let tenant: String?
    /// Rule C clause (c). The expiry or revocation instant of the D6/D19 grant
    /// this action ran under, or nil when it ran under a sheet.
    public let grantExpiry: Date?

    public init(connectionID: UUID, approvedActionID: UUID, region: String? = nil, tenant: String? = nil, grantExpiry: Date? = nil) {
        self.connectionID = connectionID
        self.approvedActionID = approvedActionID
        self.region = region
        self.tenant = tenant
        self.grantExpiry = grantExpiry
    }
}

public protocol ProviderExecutor: Sendable {
    /// Audit M-07. Called by the broker when an approved action has answered,
    /// whichever way, so anything the executor cached under that action's id
    /// — Rule C's minted token — dies with it. Defaults to nothing.
    func actionSettled(_ approvedActionID: UUID) async
    func execute(operation: Operation, credential: VaultSecret) async throws -> ActionResult
    /// D44a. The same execution, told which of the provider's documented
    /// regions the *connection* selected, so the adapter resolves the route
    /// through `ProviderRegionRouting.route(for:region:)` instead of always
    /// reaching the primary host.
    ///
    /// It is a second method rather than a changed signature because `region`
    /// belongs to the connection, not to the operation, and every executor that
    /// has no notion of regions — every fake in the self-tests, the XPC client,
    /// any future adapter set — should keep working unchanged. The default
    /// implementation below is what makes that true, and it is deliberately
    /// **not** "ignore the region": an executor that cannot honour a region
    /// refuses the request rather than silently sending it to another host,
    /// which is the same refusal `ProviderRegionRouting` makes for an
    /// undocumented id.
    func execute(operation: Operation, region: String?, credential: VaultSecret) async throws -> ActionResult
    /// BL-117 (D51) §7.2 and §2.3. The same execution again, told everything the
    /// **connection and the approved action** contribute rather than only the
    /// region.
    ///
    /// A third method rather than a changed signature, for D44a's own reason
    /// repeated: an executor that has no notion of tenants or of a token cache —
    /// every fake in the self-tests, the XPC client, any future adapter set —
    /// keeps working unchanged. And, as with the region, the default
    /// implementation below is deliberately **not** "ignore the context": an
    /// executor that cannot honour a tenant refuses rather than silently
    /// sending the request to whatever host the template would resolve to
    /// without one.
    func execute(operation: Operation, context: ProviderConnectionContext, credential: VaultSecret) async throws -> ActionResult
}

public extension ProviderExecutor {
    func actionSettled(_ approvedActionID: UUID) async {}
}

extension ProviderExecutor {
    public func execute(operation: Operation, region: String?, credential: VaultSecret) async throws -> ActionResult {
        guard region == nil else {
            throw VaultageError.unsupported("This Vaultage composition cannot reach a provider's non-primary region.")
        }
        return try await execute(operation: operation, credential: credential)
    }

    public func execute(operation: Operation, context: ProviderConnectionContext, credential: VaultSecret) async throws -> ActionResult {
        guard context.tenant == nil else {
            throw VaultageError.unsupported("This Vaultage composition cannot reach a provider that operates against a tenant.")
        }
        return try await execute(operation: operation, region: context.region, credential: credential)
    }
}
public protocol RuntimeProviderExecutor: Sendable {
    func putCloudflareWorkerSecret(destinationToken: VaultSecret, sourceValue: VaultSecret, destination: CloudflareWorkerDestination, variableName: String) async throws -> ProviderReceipt
}
public protocol ConnectionVerifier: Sendable {
    func verify(connection: Connection, item: VaultItem, credential: VaultSecret) async throws -> ConnectionVerification
}

/// BL-091. The one seam every provider resource operation runs through.
///
/// It takes the bound scope the *human* chose, the typed arguments the agent
/// supplied and, for the two operations that write a value into a provider's
/// secret store, the value the broker read from the Keychain. It returns a
/// value-free projection. Like every other executor seam here, it has no way
/// to be handed a URL, a header or a method: the adapter resolves the route
/// from the operation and the scope.
public protocol ProviderResourceExecuting: Sendable {
    func performResourceOperation(
        _ operation: Operation,
        credential: VaultSecret,
        scope: ProviderResourceScope,
        arguments: ResourceMutationArguments,
        sourceValue: VaultSecret?
    ) async throws -> ResourceOperationResult

    /// BL-128 slice 3c. Whether one named entry exists in a delivery store,
    /// asked of that entry directly — for a store whose name list is a single
    /// page that may not report it. Nil when the store has no such read, which
    /// leaves the answer to the name list, as before.
    func deliveredEntryExists(
        _ destination: DeliveryDestination,
        credential: VaultSecret,
        scope: ProviderResourceScope
    ) async throws -> Bool?
}

public extension ProviderResourceExecuting {
    func deliveredEntryExists(
        _ destination: DeliveryDestination,
        credential: VaultSecret,
        scope: ProviderResourceScope
    ) async throws -> Bool? { nil }
}

/// Mutable Activity UI history is intentionally secondary to durable receipts.
/// This seam keeps that projection testable without weakening receipt writes.
public protocol AuditPersisting: Sendable {
    func append(_ event: AuditEvent) async throws
}

public actor MetadataAuditStore: AuditPersisting {
    private let metadata: MetadataStore
    public init(metadata: MetadataStore) { self.metadata = metadata }
    public func append(_ event: AuditEvent) async throws {
        _ = try await metadata.update { state in
            state.audit.append(event)
            if state.audit.count > 500 { state.audit.removeFirst(state.audit.count - 500) }
        }
    }
}

public actor VaultageBroker {
    /// `internal` rather than `private` so BL-099's remote-approval surface can live in its own file (`BrokerRemoteApprovals.swift`) instead of growing this one by another three hundred lines.
    let metadata: MetadataStore
    private let vault: any SecretVault
    private let executor: any ProviderExecutor
    private let runtimeExecutor: (any RuntimeProviderExecutor)?
    /// BL-074. Nil in a composition that was not given one, and a composition
    /// without one cannot create or revoke a provider resource at all.
    private let resourceCreator: (any ProviderResourceCreating)?
    /// BL-091. Nil in a composition that was not given one, and a composition
    /// without one refuses every resource operation rather than pretending the
    /// operation does not exist.
    private let resourceExecutor: (any ProviderResourceExecuting)?
    private let receipts: any ReceiptPersisting
    /// `internal` rather than `private` so BL-099's remote-approval surface can live in its own file (`BrokerRemoteApprovals.swift`) instead of growing this one by another three hundred lines.
    let audit: any AuditPersisting
    private let accountClient: any AccountClient
    private let connectionPolicy: ManagedConnectionPolicy
    /// `internal` rather than `private` so BL-099's remote-approval surface can live in its own file (`BrokerRemoteApprovals.swift`) instead of growing this one by another three hundred lines.
    let now: @Sendable () -> Date
    private let approve: @Sendable (ApprovalDetails) async -> Bool
    /// BL-060. Owner authentication for grant creation. A grant is the only
    /// thing in Vaultage that is created by an approval rather than consumed by
    /// one, so it takes its own OS authentication instead of borrowing the
    /// Keychain's.
    /// `internal` rather than `private` so BL-099's remote-approval surface can live in its own file (`BrokerRemoteApprovals.swift`) instead of growing this one by another three hundred lines.
    let authenticator: any OwnerAuthenticating
    /// BL-062 follow-up. The presence proved during `createGrant`, held for the
    /// single arming read that follows it. Single-use, account-bound and
    /// 60-second-bounded by `OwnerAuthentication` itself; cleared on every
    /// read attempt whether or not it matched, so it can never accumulate.
    private var armingAuthentication: OwnerAuthentication?
    private var armingGrantID: UUID?
    /// BL-136 steps 2–5. The pairing binding store (the broker-only Keychain
    /// group in the shipping composition), the sheet presenter the client
    /// process supplies, the connection's OS-derived origin, and at most one
    /// pending pairing for this connection.
    let agentBindings: any AgentBindingStoring
    let pairingSheet: PairingSheetPresenter?
    var connectionOrigin: AgentConnectionOrigin?
    var pendingPairing: PendingPairing?
    /// BL-060. The auto-allow window's secret cache. It lives here, in the
    /// broker, so its lifetime is the broker process's lifetime and nothing
    /// about it is ever written to disk.
    /// `internal` rather than `private` so BL-099's remote-approval surface can live in its own file (`BrokerRemoteApprovals.swift`) instead of growing this one by another three hundred lines.
    let grantCache: GrantSecretCache
    /// BL-136 step 1. What stamps and checks a grant's MAC. The shipping
    /// composition supplies the Keychain key; a broker composed without one
    /// gets this process's ephemeral key, so its grants die with the process.
    let grantSigner: any GrantSigning
    /// BL-069. The identity this connection presented, if any. It is set once,
    /// at connect, and is re-checked against metadata every time a sheet is
    /// composed, so revoking a client takes effect at the next approval rather
    /// than at the next reconnect. It is never consulted by a policy decision.
    var presentedClient: ClientIdentity = .unenrolled(.notPresented)
    /// BL-099. The remote-approval surface's network half, or `nil` on a Mac
    /// with no paired phone — which is every Mac until the §2.4 ceremony runs,
    /// and every existing test.
    var remoteApprovals: (any RemoteApprovalCoordinating)?
    /// BL-099 slice 3. §6.2's four connect routes, or `nil` on a Mac that
    /// cannot ask a phone to connect a provider — which is every Mac with no
    /// pin, and every existing test.
    var remoteConnect: (any RemoteConnectTransport)?
    /// BL-100 slice A. §3.2's twelve app-facing rows, or `nil` on a broker with
    /// vault sync off — which is every existing test and every build that has
    /// not run §5.1's ceremony. **A composition without one refuses every one
    /// of the twelve** rather than pretending it worked, which is the same
    /// fail-closed rule the mirroring methods and the grant methods apply.
    var vaultCustody: VaultCustodyComposition?
    /// BL-100 slice A. The **network** half — BL-102's sixteen routes and the
    /// `sig` signer the acknowledgement takes — or `nil` on a Mac that has no
    /// relay session, which is every existing test and every offline-by-design
    /// Mac. `syncVault` refuses rather than pretending, exactly as the twelve
    /// selectors do without a custody composition.
    var vaultSync: VaultSyncComposition?

    /// Installs the custody composition. It is a separate call rather than an
    /// init parameter for the reason `remoteApprovals` is: a Mac acquires it
    /// when the ceremony runs, not when the process starts.
    public func installVaultCustody(_ custody: VaultCustodyComposition) {
        vaultCustody = custody
    }

    public init(metadata: MetadataStore, vault: any SecretVault, executor: any ProviderExecutor, runtimeExecutor: (any RuntimeProviderExecutor)? = nil, resourceCreator: (any ProviderResourceCreating)? = nil, resourceExecutor: (any ProviderResourceExecuting)? = nil, receipts: (any ReceiptPersisting)? = nil, audit: (any AuditPersisting)? = nil, accountClient: any AccountClient = StaticAccountClient(), connectionPolicy: ManagedConnectionPolicy = ManagedConnectionPolicy(), now: @escaping @Sendable () -> Date = Date.init, authenticator: (any OwnerAuthenticating)? = nil, grantCache: GrantSecretCache? = nil, grantSigner: (any GrantSigning)? = nil, agentBindings: (any AgentBindingStoring)? = nil, pairingSheet: PairingSheetPresenter? = nil, approve: @escaping @Sendable (ApprovalDetails) async -> Bool) {
        self.agentBindings = agentBindings ?? InMemoryAgentBindings(); self.pairingSheet = pairingSheet; self.metadata = metadata; self.vault = vault; self.executor = executor; self.runtimeExecutor = runtimeExecutor; self.resourceCreator = resourceCreator; self.resourceExecutor = resourceExecutor; self.receipts = receipts ?? ReceiptStore(directory: metadata.directory); self.audit = audit ?? MetadataAuditStore(metadata: metadata); self.accountClient = accountClient; self.connectionPolicy = connectionPolicy; self.now = now; self.authenticator = authenticator ?? LocalOwnerAuthentication(); self.grantCache = grantCache ?? GrantSecretCache(); self.grantSigner = grantSigner ?? GrantSigner.processEphemeral; self.approve = approve
    }

    /// BL-069. Resolves a presented enrollment credential to an enrolled record
    /// and remembers the result for this connection's approval sheets.
    ///
    /// This grants nothing. An unknown or revoked credential is recorded as an
    /// audit event and the connection continues as unenrolled — it is not
    /// refused, because refusing would make the enrollment credential an access
    /// control, which is exactly what this ticket must not build. Every action
    /// from an unenrolled connection still takes the same fresh human approval
    /// it took before enrollment existed.
    @discardableResult
    public func identify(presenting credential: ClientCredential?) async -> ClientIdentity {
        let state = (try? await metadata.load()) ?? VaultageMetadata()
        let identity = ClientEnrollment.resolve(credential, in: state)
        presentedClient = identity
        if let reason = identity.reason, reason == .unknown || reason == .revoked {
            try? await audit.append(AuditEvent(
                operation: "client.identify",
                decision: .blocked,
                result: reason == .revoked
                    ? "A revoked client credential was presented. The connection continues as unenrolled."
                    : "An unrecognized client credential was presented. The connection continues as unenrolled."
            ))
        }
        return identity
    }

    /// The identity as of right now. An enrolled record that has since been
    /// revoked or deleted resolves to unenrolled here, so a long-lived MCP
    /// session cannot keep displaying a name the human has withdrawn.
    private func currentClient(_ state: VaultageMetadata) -> ClientIdentity {
        ClientEnrollment.current(presentedClient, in: state)
    }

    /// Runs durable-receipt recovery once at process start, then mirrors each
    /// invocation that never reached a terminal decision into the mutable
    /// Activity projection as unknown. A crashed or interrupted invocation is
    /// therefore surfaced, never silently dropped and never shown as success.
    @discardableResult
    public func recoverDurableReceipts() async -> ReceiptRecovery {
        let recovery: ReceiptRecovery
        do { recovery = try await receipts.recover() }
        catch {
            // RP-04. A failed repair used to be swallowed by `try?`, so a
            // crashed invocation disappeared from both records it was meant to
            // appear in: the durable log kept a dangling pending, and Activity
            // was told nothing at all. The repair is retryable at the next
            // start; what must not happen is that it fails silently.
            try? await audit.append(AuditEvent(
                operation: "receipts.recover",
                decision: .failed,
                result: "Vaultage could not repair the durable receipt log: \(Redactor.publicError(error)) Any interrupted action is still unresolved; the next start retries the repair."
            ))
            return ReceiptRecovery()
        }
        for invocation in recovery.pendingClosedAsUnknown {
            let event = AuditEvent(
                projectID: invocation.projectID,
                environmentID: invocation.environmentID,
                connectionID: nil,
                operation: invocation.operation,
                decision: .resultUnknown,
                result: "Vaultage restarted while this action was pending. The result is unknown; do not retry automatically."
            )
            try? await audit.append(event)
        }
        return recovery
    }

    public func status(includeBindings: Bool) async throws -> VaultageStatus {
        guard includeBindings else { return VaultageStatus(projects: [], environments: [], bindings: [], message: "Metadata is concealed until the human approves vaultage_status(include_bindings: true).") }
        let state = try await metadata.load()
        // BL-094 widened what this one approval discloses, so the sentence
        // widened with it: an agent that is told what is deployed where can
        // tell a human, and a human approving disclosure should know that is
        // part of it.
        guard await approve(ApprovalDetails(project: "Local metadata", environment: "No environment", provider: "Vaultage", connection: "No credential", operation: "Expose binding metadata", reason: "An MCP client asked to list opaque project, environment, binding, approved runtime-source, and bound Worker destination metadata, and which credentials Vaultage has delivered into each environment's provider secret stores — destination names, identity fingerprints, and when each was delivered and last verified. No credential value is returned. An agent can ask to deliver a credential (vaultage_deliver), which you approve here each time; it cannot verify or rotate.", client: currentClient(state))) else { throw VaultageError.approvalDenied }
        let projects = state.projects.map { ProjectStatus(id: $0.id, name: $0.name) }
        let environments = state.environments.map { EnvironmentStatus(id: $0.id, projectID: $0.projectID, name: $0.name) }
        let bindings = state.bindings.compactMap { binding -> BindingStatus? in
            guard let connection = state.connections.first(where: { $0.id == binding.connectionID }) else { return nil }
            let sources = state.runtimeSourceAuthorizations.filter { $0.bindingID == binding.id && $0.projectID == binding.projectID && $0.environmentID == binding.environmentID }.compactMap { authorization -> RuntimeSourceStatus? in guard let item = state.vaultItems.first(where: { $0.id == authorization.sourceVaultItemID }) else { return nil }; return RuntimeSourceStatus(id: item.id, label: item.label) }
            let destination = binding.cloudflareWorkerDestination.map { WorkerDestinationStatus(accountID: $0.accountID, scriptName: $0.scriptName, destinationClass: $0.destinationClass.rawValue) }
            // BL-091. The bound resource scope, so an agent can discover which
            // zone or project a resource operation would act on before it asks
            // for one. Identifiers and a human label; nothing else.
            let scope = binding.resourceScope.map { ResourceScopeStatus(kind: $0.kind.rawValue, label: $0.label, accountID: $0.accountID, zoneID: $0.zoneID, scriptName: $0.scriptName, projectID: $0.projectID, repository: $0.repository) }
            return BindingStatus(id: binding.id, projectID: binding.projectID, environmentID: binding.environmentID, provider: connection.provider.rawValue, connection: connection.label, operations: binding.allowedOperations.map(\.rawValue).sorted(), runtimeSources: sources, workerDestination: destination, resourceScope: scope)
        }
        // BL-094. What is deployed where, value-free. A fingerprint is a digest
        // of the source item's id and credential version, so an agent can say
        // "production and staging are running the same key" and can confirm
        // nothing about the key itself.
        let deployments = state.deployedCredentials.map { row in
            DeploymentStatus(
                projectID: row.projectID,
                environmentID: row.environmentID,
                provider: row.provider.rawValue,
                store: row.destination.store.rawValue,
                destinationName: row.destination.name,
                target: row.destination.target?.rawValue,
                scopeLabel: row.destination.scopeLabel,
                sourceVaultItemID: row.sourceVaultItemID,
                sourceField: row.sourceField?.wireName,
                fingerprint: row.fingerprint,
                status: row.status.rawValue,
                deliveredAt: row.deliveredAt,
                lastVerifiedAt: row.lastVerifiedAt,
                expiresAt: row.expiresAt,
                requestedBy: row.door.rawValue,
                requestingClientID: row.requestingClientID
            )
        }
        var message: String
        if bindings.isEmpty {
            message = "No bindings yet. Create a project and environment, save a provider credential in Vault, connect and Verify it in Services, then bind an operation. Initial providers are GitHub, OpenAI, and Cloudflare; request other providers on the website Account page. Only opaque IDs and labels are returned. Credentials are never returned."
        } else {
            message = "Only opaque IDs and labels are returned. Credentials are never returned."
        }
        if deployments.isEmpty {
            message += " Nothing has been delivered into a provider secret store yet."
        } else {
            let live = deployments.filter { $0.status == DeployedCredentialStatus.delivered.rawValue || $0.status == DeployedCredentialStatus.verifyFailed.rawValue }.count
            message += " \(live) of \(deployments.count) recorded deployments are live. To deliver a credential, use vaultage_deliver: the owner approves it on this Mac, the destination is checked before and after the write, and the delivery is recorded here with your name. Verifying what is deployed and rotating with overlap are done by the owner in the Vaultage app; there is no tool for them here. Credential values never leave this Mac, and once delivered the environment keeps running with Vaultage quit."
        }
        return VaultageStatus(projects: projects, environments: environments, bindings: bindings, deployments: deployments, message: message)
    }

    public func execute(_ request: ActionRequest) async throws -> ActionResult {
        // BL-128 slice 3c (D65). Before anything is resolved, read or shown: a
        // delivery that goes through the ledger is not an agent operation.
        guard request.operation.isAgentReachable else {
            try? await append(request, connectionID: nil, .blocked, "\(request.operation.rawValue) is a delivery and is not an action.")
            throw VaultageError.policyDenied("\(request.operation.rawValue) is a delivery. Ask for it with vaultage_deliver, which checks the destination before and after the write and records it in the deployed-credential ledger; the owner approves it on this Mac.")
        }
        // BL-091. The resource path. Everything with a bound scope and typed
        // arguments goes through it, including the two reads whose URL needs a
        // resource identifier and which therefore cannot live in the read table.
        if request.operation.isResourceOperation { return try await executeResourceOperation(request).actionResult }
        guard request.resourceMutation == nil else {
            throw VaultageError.invalidInput("\(request.operation.rawValue) does not take resource arguments.")
        }
        let state = try await metadata.load()
        let resolution: ReadResolution
        do { resolution = try readResolution(state, request: request) }
        catch {
            try? await append(request, connectionID: nil, .blocked, "No permitted connected capability.")
            throw error
        }
        try await requireActiveManagedConnection(resolution.connection.id)
        // BL-060. The single branch a grant can change. Everything before it and
        // everything after it is identical for an approved and an auto-allowed
        // action; `authorizingGrant` returns nil for an unenrolled client, an
        // operation outside the grant, a production environment the grant does
        // not include, an expired or revoked grant, and any change to the
        // records the grant covers.
        //
        // D19 moved this ahead of the verification check, because a covering
        // grant now decides how long verification counts as current. It is the
        // same call, over the same state, deciding the same thing; resolving it
        // first only means the verification check can ask it for a ceiling.
        let decisionInstant = now()
        await grantCache.purge(now: decisionInstant)
        let autoAllow = GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: state, now: decisionInstant, signer: grantSigner)
        try requireCurrentVerification(connection: resolution.connection, item: resolution.item, operation: request.operation, grant: autoAllow)
        let approvedReadDigest = readDigest(request: request, resolution: resolution)
        if let autoAllow {
            try? await append(request, connectionID: resolution.connection.id, .approved, "Auto-allowed without a prompt by grant \(autoAllow.id.uuidString), which expires \(ISO8601DateFormatter().string(from: autoAllow.expiresAt)).")
        } else {
            let details = ApprovalDetails(project: resolution.project.name, environment: resolution.environment.name, provider: resolution.connection.provider.title, connection: resolution.connection.label, operation: request.operation.rawValue, reason: "MCP actions require fresh approval and the protected credential will be used only for this fixed provider operation. \(providerEvidenceDescription(resolution.connection))", client: currentClient(state))
            guard await approve(details) else {
                try? await append(request, connectionID: resolution.connection.id, .denied, "Human denied approval.")
                throw VaultageError.approvalDenied
            }
        }
        let approvedAt = now()
        // Approval names an immutable selection, but another process may have
        // changed local metadata while the native sheet was visible. Reload and
        // re-check every relationship before asking Keychain for a secret.
        let refreshedState: VaultageMetadata
        let refreshed: ReadResolution
        do {
            refreshedState = try await metadata.load()
            refreshed = try readResolution(refreshedState, request: request)
        }
        catch {
            try? await append(request, connectionID: nil, .blocked, "Binding changed while approval was pending.")
            throw VaultageError.policyDenied("The approved binding changed before execution.")
        }
        let currentReadDigest = readDigest(request: request, resolution: refreshed)
        guard currentReadDigest == approvedReadDigest else {
            try? await append(request, connectionID: nil, .blocked, "Read binding changed while approval was pending.")
            throw VaultageError.policyDenied("The approved binding changed before execution.")
        }
        // An auto-allowed action re-proves its grant against freshly loaded
        // metadata, so a revocation or a covered-record change between the
        // decision and the Keychain read denies rather than proceeding.
        if let autoAllow {
            guard GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: refreshedState, now: now(), signer: grantSigner)?.id == autoAllow.id else {
                try? await append(request, connectionID: nil, .blocked, "The auto-allow grant was revoked or invalidated before execution.")
                throw VaultageError.policyDenied("The auto-allow grant no longer covers this action.")
            }
        }
        try await requireActiveManagedConnection(refreshed.connection.id)
        try requireCurrentVerification(connection: refreshed.connection, item: refreshed.item, operation: request.operation, grant: autoAllow)
        let invocationID = UUID()
        try await persistReceipt(request, digest: currentReadDigest, correlationID: invocationID, .pending, autoAllow == nil ? "Approved read operation pending." : "Auto-allowed read operation pending.", grantID: autoAllow?.id)
        let secret: VaultSecret
        do { secret = try await readCredential(refreshed, request: request, grant: autoAllow) }
        catch {
            try await completeKnown(request, digest: currentReadDigest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: "OS authentication failed or was cancelled.", grantID: autoAllow?.id)
            throw error
        }
        // A Keychain sheet can remain open while the graph or entitlement is
        // changed by another process.  Re-resolve every immutable record and
        // impose the same bounded approval lifetime as a runtime delivery.
        var egressRegion = refreshed.connection.region
        do {
            // The 60-second approval lifetime bounds a human staring at a sheet.
            // An auto-allowed action never showed one, so its bound is the grant
            // window itself, re-proved here against freshly loaded metadata.
            let finalState = try await metadata.load()
            if let autoAllow {
                guard GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: finalState, now: now(), signer: grantSigner)?.id == autoAllow.id else {
                    throw VaultageError.policyDenied("The auto-allow grant no longer covers this action.")
                }
            } else {
                guard now().timeIntervalSince(approvedAt) <= 60 else { throw VaultageError.approvalDenied }
            }
            let final = try readResolution(finalState, request: request)
            guard readDigest(request: request, resolution: final) == approvedReadDigest else {
                throw VaultageError.policyDenied("The approved binding changed before egress.")
            }
            try await requireActiveManagedConnection(final.connection.id)
            try requireCurrentVerification(connection: final.connection, item: final.item, operation: request.operation, grant: autoAllow)
            // D44a. The region that goes to the adapter is the one on the
            // record that was just re-resolved and digest-matched, not the one
            // read before the Keychain sheet opened. A region cannot change
            // without `Connection.reconnect`, which clears the verification and
            // changes the vault item, so both the digest above and
            // `requireCurrentVerification` would already have refused — this
            // simply makes the value that reaches egress the same one those two
            // checks passed on.
            egressRegion = final.connection.region
        } catch {
            try await completeKnown(request, digest: currentReadDigest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: "Read authorization changed or expired after OS authentication.", grantID: autoAllow?.id)
            throw error
        }
        let result: ActionResult
        // BL-117 §7.2 and §2.3. The connection and the approved action travel
        // together now: the region D44a needed, the tenant Azure's compiled path
        // needs, and the two ids Rule C's cache is keyed on. `invocationID` is
        // the approved action's own id, which is exactly what "no cache entry is
        // reachable from an action other than the one whose id keys it" means.
        let egressContext = ProviderConnectionContext(
            connectionID: refreshed.connection.id,
            approvedActionID: invocationID,
            region: egressRegion,
            tenant: refreshed.connection.tenant,
            grantExpiry: autoAllow?.expiresAt
        )
        do { result = try await executor.execute(operation: request.operation, context: egressContext, credential: secret) }
        catch {
            // Audit M-07: the action has answered; its minted token goes.
            await executor.actionSettled(invocationID)
            try await completeKnown(request, digest: currentReadDigest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: .failed, result: Redactor.publicError(error), grantID: autoAllow?.id)
            throw error
        }
        // Audit M-07: the action has answered; its minted token goes.
        await executor.actionSettled(invocationID)
        try await persistReceipt(request, digest: currentReadDigest, correlationID: invocationID, .executed, result.summary, grantID: autoAllow?.id)
        // The durable receipt is authoritative. A UI activity projection
        // failure must not turn a durably recorded execution into unknown.
        try? await append(request, connectionID: refreshed.connection.id, .executed, result.summary)
        return result
    }

    /// The one place a grant changes what a Keychain read costs.
    ///
    /// Without a grant this is exactly the call it has always been: one
    /// user-presence prompt per action. With one, a value cached under the same
    /// grant, the same Keychain account and the same credential version is
    /// reused for the window; anything else reads the Keychain again and re-arms
    /// the cache. The cache is memory in this process and nothing else.
    private func readCredential(_ resolution: ReadResolution, request: ActionRequest, grant: Grant?) async throws -> VaultSecret {
        let prompt = "Approve \(request.operation.rawValue) for \(resolution.project.name) / \(resolution.environment.name)"
        guard let grant else {
            // No grant: the Keychain prompt is the only gate on this path, and
            // it stays exactly one prompt. BL-062's follow-up deliberately does
            // not touch agent-facing reads.
            return try vault.read(account: resolution.item.keychainAccount, prompt: prompt)
        }
        // BL-136 step 4 (S1): the arming is keyed to the host instance that made it; a cache that outlived the host is dropped.
        if !hostInstanceStillRunning() { await grantCache.clear() }

        if let cached = await grantCache.secret(account: resolution.item.keychainAccount, grantID: grant.id, credentialVersion: resolution.item.credentialVersion, now: now()) {
            return cached
        }
        let secret = try vault.read(
            account: resolution.item.keychainAccount,
            prompt: "\(prompt) (arming auto-allow until \(ISO8601DateFormatter().string(from: grant.expiresAt)))",
            // BL-062 follow-up: "grant creation followed by a read". The owner
            // authenticated seconds ago to create this grant, in a prompt that
            // named the scope, and the arming read that immediately follows
            // would otherwise raise a second prompt. `takeArmingAuthentication`
            // returns that presence only once, only for this grant, only for a
            // Keychain account the grant's own coverage resolved to, and only
            // inside 60 seconds. Everything else reads with a fresh prompt.
            authentication: takeArmingAuthentication(grantID: grant.id, account: resolution.item.keychainAccount)
        )
        // BL-136 step 4. A cached secret lives at most one session — twelve
        // hours from this arming — however long the grant runs; the next
        // action after that re-arms with one Touch ID.
        await grantCache.store(secret, account: resolution.item.keychainAccount, grantID: grant.id, credentialVersion: resolution.item.credentialVersion, expiresAt: min(grant.expiresAt, now().addingTimeInterval(GrantSecretCache.sessionCeiling)), now: now())
        return secret
    }

    /// The Keychain accounts a grant draft's coverage resolves to, via its
    /// bindings and their connections. Used only to bind the grant-creation
    /// presence; a binding whose connection or item cannot be resolved simply
    /// contributes nothing, so an unresolvable graph narrows the binding rather
    /// than widening it.
    private static func coveredKeychainAccounts(_ draft: GrantDraft, in state: VaultageMetadata) -> Set<String> {
        var accounts: Set<String> = []
        for covered in draft.bindings {
            guard let binding = state.bindings.first(where: { $0.id == covered.bindingID }),
                  let connection = state.connections.first(where: { $0.id == binding.connectionID }),
                  let item = state.vaultItems.first(where: { $0.id == connection.vaultItemID }) else { continue }
            accounts.insert(item.keychainAccount)
        }
        return accounts
    }

    // MARK: - BL-060 grants

    /// Creates a grant. Two gates, in this order and both required: the native
    /// approval sheet that states scope, duration, environments, the operations
    /// covered and the sentence about running without a prompt; and OS
    /// authentication. Neither is skippable and neither alone is sufficient.
    ///
    /// Between them the coverage is re-resolved and its digest re-compared, so a
    /// binding, connection, credential version, plan state or policy revision
    /// that moved while the human was deciding denies instead of being granted.
    @discardableResult
    public func createGrant(_ request: GrantRequest) async throws -> GrantSummary {
        let state = try await metadata.load()
        // Audit H-02. A client-scoped grant for a bearer-enrolled client would
        // authorize nothing (`authorizingGrant` refuses the client), so it is
        // refused here, before a sheet, in the words the owner needs.
        if let clientID = request.scope.clientID, state.enrolledClients.first(where: { $0.id == clientID })?.isGrantEligible != true {
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .blocked, result: ClientEnrollment.legacyBearerGrantSentence))
            throw VaultageError.policyDenied(ClientEnrollment.legacyBearerGrantSentence)
        }
        let draft: GrantDraft
        do { draft = try GrantPolicy.prepare(request, in: state, now: now()) }
        catch {
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .blocked, result: Redactor.publicError(error)))
            throw error
        }
        let details = ApprovalDetails(
            project: draft.disclosure.scopeLabel,
            environment: draft.disclosure.environmentLabels.joined(separator: ", "),
            provider: "Vaultage",
            connection: "Auto-allow grant",
            operation: "grant.create",
            reason: "This creates a standing auto-allow grant. \(GrantDisclosure.autoAllowSentence) Actions outside this scope, and every action from a client that is not enrolled, still take a per-action approval. \(GrantDisclosure.verificationCeilingSentence)",
            client: currentClient(state),
            grant: draft.disclosure
        )
        guard await approve(details) else {
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .denied, result: "The owner denied a \(request.duration.label) auto-allow grant."))
            throw VaultageError.approvalDenied
        }
        let approvedAt = now()
        let authentication: OwnerAuthentication
        do {
            // Bound to the Keychain accounts this grant's own coverage
            // resolves to — the items the human was shown in the sheet — and
            // to nothing else. When coverage resolves to no item the set is
            // empty, which makes the presence unbound and therefore unusable
            // for any read at all.
            authentication = try await authenticator.authenticateOwner(
                reason: "Authorize a \(request.duration.label) Vaultage auto-allow grant for \(draft.disclosure.scopeLabel)",
                unlocking: Self.coveredKeychainAccounts(draft, in: state)
            )
        } catch {
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .denied, result: "Owner authentication failed or was cancelled; no grant was created."))
            throw error
        }
        guard now().timeIntervalSince(approvedAt) <= 60 else {
            authentication.invalidate()
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .blocked, result: "The grant approval expired before it was committed."))
            throw VaultageError.approvalDenied
        }
        // Re-resolve and re-compare after authentication. Approving a sheet and
        // authenticating do not authorize a changed set of records.
        let grant: Grant
        do {
            grant = try await metadata.updateResult { fresh in
                let confirmed = try GrantPolicy.prepare(request, in: fresh, now: self.now())
                guard confirmed.digest == draft.digest else {
                    throw VaultageError.policyDenied("The records this grant would cover changed before it was created.")
                }
                return try GrantPolicy.commit(confirmed, now: self.now(), in: &fresh, signer: self.grantSigner)
            }
        } catch {
            authentication.invalidate()
            try? await audit.append(AuditEvent(operation: "grant.create", decision: .blocked, result: Redactor.publicError(error)))
            throw error
        }
        armingAuthentication?.invalidate()
        armingAuthentication = authentication
        armingGrantID = grant.id
        try? await audit.append(AuditEvent(operation: "grant.create", decision: .approved, result: "Auto-allow grant \(grant.id.uuidString) created for \(draft.disclosure.scopeLabel), \(request.duration.label), \(draft.disclosure.environmentLabels.count) environment(s), production \(grant.includesProduction ? "included" : "excluded")."))
        let summary = try await grantSummaries().first { $0.id == grant.id }
        guard let summary else { throw VaultageError.storage("The grant was created but could not be projected.") }
        return summary
    }

    /// Takes the grant-creation presence if it is still good for exactly this
    /// grant and this Keychain account. It is consumed either way: a presence
    /// that did not match the first read it was offered to is a presence the
    /// human's action has already moved past.
    private func takeArmingAuthentication(grantID: UUID, account: String) -> OwnerAuthentication? {
        guard let held = armingAuthentication else { return nil }
        armingAuthentication = nil
        guard held.isValid(for: account, at: now()), armingGrantID == grantID else {
            held.invalidate()
            return nil
        }
        armingGrantID = nil
        return held
    }

    /// Revocation. The durable record is marked first and the cached secrets for
    /// that grant are dropped — which zeroes them — immediately afterwards, so a
    /// revoked grant can neither authorize an action nor leave a usable value
    /// behind in this process.
    @discardableResult
    public func revokeGrant(_ id: UUID) async throws -> GrantSummary {
        let (grant, generation) = try await metadata.updateResult { state -> (Grant, Int) in
            let revoked = try GrantPolicy.revoke(id, now: self.now(), in: &state, signer: self.grantSigner)
            return (revoked, state.revocationGeneration)
        }
        // Audit H-08: the anchor rises with the file, so a copy of the file
        // from before this revocation is below it from now on.
        try grantSigner.raiseRevocationWatermark(to: generation)
        await grantCache.invalidate(grantID: id)
        if armingGrantID == id { armingAuthentication?.invalidate(); armingAuthentication = nil; armingGrantID = nil }
        try? await audit.append(AuditEvent(operation: "grant.revoke", decision: .blocked, result: "Auto-allow grant \(grant.id.uuidString) was revoked. Matching actions take a per-action approval again."))
        let summary = try await grantSummaries().first { $0.id == id }
        guard let summary else { throw VaultageError.storage("The grant was revoked but could not be projected.") }
        return summary
    }

    /// Every grant, verified under this Mac's key and its revocation anchor
    /// (audit H-08): a rolled-back file shows every grant as not honoured.
    private func grantSummaries() async throws -> [GrantSummary] {
        let state = try await metadata.load()
        let current = grantSigner.isCurrent(state)
        return GrantPolicy.summaries(in: state, now: now(), verify: { current && self.grantSigner.verifies($0) })
    }

    /// The Activity projection: every grant with its scope, coverage and
    /// remaining time. Labels and counts only; no digest and no credential.
    public func listGrants() async throws -> [GrantSummary] {
        try await grantSummaries()
    }

    /// Lock. Forgets every cached secret without touching a grant record, so the
    /// windows stay armed as metadata and the next matching action re-arms with
    /// one Touch ID.
    /// Lock (audit H-04/H-05): the cache **and** the presence carried from the
    /// last grant creation, which would otherwise let one covered action read
    /// the Keychain without a prompt for about a minute after the owner
    /// locked. Returns what is left in the cache, which is zero or the lock
    /// did not happen — a caller that cannot see zero must not say "locked".
    @discardableResult
    public func lockGrantSecrets() async throws -> Int {
        armingAuthentication?.invalidate()
        armingAuthentication = nil
        armingGrantID = nil
        await grantCache.clear()
        return await grantCache.entryCount()
    }

    /// Test-visible: whether a presence carried from the last grant creation
    /// is still held for its first covered action. A fact, never a value.
    public func carriesArmingPresence() -> Bool { armingAuthentication != nil }

    /// Test-visible cache size. It returns a count, never a value.
    public func cachedGrantSecretCount() async -> Int {
        await grantCache.entryCount()
    }

    // MARK: - BL-073 the provisioning conversation

    /// `vaultage_provision`. Returns a structured outcome and never blocks on a
    /// human: the two outcomes that need one persist a `PendingProvisioning`
    /// and return its ID immediately, and the agent re-calls with that ID.
    ///
    /// No secret value crosses this method in any direction. The richest thing
    /// it ever returns is a binding ID, a vault item ID and a human label.
    public func provision(_ request: ProvisioningRequest) async throws -> ProvisioningOutcome {
        // An unknown provider or capability is an *outcome*, not an error: the
        // agent needs to be told what is supported, not handed a refusal.
        guard let provider = Provider(rawValue: request.provider), ProvisioningSupport.isSupported(provider) else {
            return ProvisioningOutcome(
                status: .providerUnsupported,
                provider: request.provider,
                capability: request.capability,
                projectID: request.projectID,
                environmentID: request.environmentID,
                supported: ProvisioningSupport.providers.map(\.rawValue).sorted(),
                nextStep: "Vaultage can provision for \(ProvisioningSupport.providers.map(\.title).sorted().joined(separator: ", ")) today. Request another provider from the Account page on the website."
            )
        }
        guard let capability = ProvisioningCapability(rawValue: request.capability), capability.provider == provider else {
            return ProvisioningOutcome(
                status: .capabilityUnsupported,
                provider: provider.rawValue,
                capability: request.capability,
                projectID: request.projectID,
                environmentID: request.environmentID,
                supported: ProvisioningCapability.supported(for: provider).map(\.rawValue).sorted(),
                nextStep: "Choose one of the capabilities this provider supports and call vaultage_provision again."
            )
        }

        let instant = now()
        // Housekeeping and reads happen in one locked update, so an expired
        // record can never be read as open.
        let state = try await metadata.update { ProvisioningPolicy.purge(&$0, now: instant) }

        // A re-call naming a pending request reports that request's state, and
        // nothing else: it never starts new work and never re-asks the human.
        if let provisioningID = request.provisioningID {
            guard let record = state.pendingProvisionings.first(where: { $0.id == provisioningID }),
                  record.matches(projectID: request.projectID, environmentID: request.environmentID, provider: provider, capability: capability) else {
                return ProvisioningOutcome(status: .expired, provider: provider.rawValue, capability: capability.rawValue, projectID: request.projectID, environmentID: request.environmentID, nextStep: "That provisioning request is unknown, expired, or belongs to a different project, environment, provider or capability. Call vaultage_provision again without a provisioning_id to start over.")
            }
            return outcome(for: record, in: state, at: instant)
        }

        let decision: ProvisioningPolicy.Decision
        do { decision = try ProvisioningPolicy.decide(projectID: request.projectID, environmentID: request.environmentID, provider: provider, capability: capability, in: state, now: instant) }
        catch {
            return ProvisioningOutcome(status: .requestInvalid, provider: provider.rawValue, capability: capability.rawValue, projectID: request.projectID, environmentID: request.environmentID, nextStep: Redactor.publicError(error))
        }

        switch decision {
        case let .bound(binding):
            return boundOutcome(binding, provider: provider, capability: capability)
        case let .connectionRequired(provider):
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, operation: "provision.\(capability.rawValue)", decision: .blocked, result: "No verified \(provider.title) connection; the agent was told to connect one in Services."))
            return ProvisioningOutcome(status: .connectionRequired, provider: provider.rawValue, capability: capability.rawValue, projectID: request.projectID, environmentID: request.environmentID, nextStep: ProvisioningOutcome.connectionRequiredNextStep(provider))
        case let .resourceSelection(connectionID, vaultItemIDs):
            let record = try await openPendingRequest(projectID: request.projectID, environmentID: request.environmentID, provider: provider, capability: capability, connectionID: connectionID, step: .resourceSelection, choiceVaultItemIDs: vaultItemIDs, at: instant)
            let fresh = try await metadata.load()
            return outcome(for: record, in: fresh, at: instant)
        case let .creationAuthorization(connectionID):
            let record = try await openPendingRequest(projectID: request.projectID, environmentID: request.environmentID, provider: provider, capability: capability, connectionID: connectionID, step: .creationAuthorization, choiceVaultItemIDs: [], at: instant)
            let fresh = try await metadata.load()
            return outcome(for: record, in: fresh, at: instant)
        }
    }

    /// Opens a human step, or reuses the one already open for the same
    /// (project, environment, provider, capability). This is what makes the
    /// tool idempotent: an agent that calls three times gets one pending
    /// request and the human sees one sheet.
    private func openPendingRequest(projectID: UUID, environmentID: UUID, provider: Provider, capability: ProvisioningCapability, connectionID: UUID, step: PendingProvisioning.Step, choiceVaultItemIDs: [UUID], at instant: Date) async throws -> PendingProvisioning {
        try await metadata.updateResult { fresh in
            ProvisioningPolicy.purge(&fresh, now: instant)
            if let existing = fresh.pendingProvisionings.first(where: { $0.matches(projectID: projectID, environmentID: environmentID, provider: provider, capability: capability) && $0.isOpen(at: instant) }) {
                return existing
            }
            let record = PendingProvisioning(projectID: projectID, environmentID: environmentID, provider: provider, capability: capability, connectionID: connectionID, step: step, choiceVaultItemIDs: choiceVaultItemIDs, createdAt: instant)
            fresh.pendingProvisionings.append(record)
            return record
        }
    }

    /// Projects a pending record — answered or not — into the agent's outcome.
    private func outcome(for record: PendingProvisioning, in state: VaultageMetadata, at instant: Date) -> ProvisioningOutcome {
        let provider = record.provider.rawValue
        let capability = record.capability.rawValue
        switch record.resolution {
        case let .bound(bindingID):
            guard let binding = state.bindings.first(where: { $0.id == bindingID }) else {
                // The binding was removed after the human created it. Say so
                // rather than reporting a binding the agent cannot use.
                return ProvisioningOutcome(status: .failed, provider: provider, capability: capability, projectID: record.projectID, environmentID: record.environmentID, nextStep: "The binding created for this request no longer exists. Call vaultage_provision again without a provisioning_id.")
            }
            return boundOutcome(binding, provider: record.provider, capability: record.capability)
        case .denied:
            return ProvisioningOutcome(status: .denied, provider: provider, capability: capability, projectID: record.projectID, environmentID: record.environmentID, nextStep: "The owner declined this request in Vaultage. Do not retry automatically; ask them what they would prefer.")
        case let .failed(message):
            return ProvisioningOutcome(status: .failed, provider: provider, capability: capability, projectID: record.projectID, environmentID: record.environmentID, nextStep: Redactor.safeError(message))
        case nil:
            guard record.isOpen(at: instant) else {
                return ProvisioningOutcome(status: .expired, provider: provider, capability: capability, projectID: record.projectID, environmentID: record.environmentID, nextStep: "This provisioning request expired before the owner answered it. Call vaultage_provision again without a provisioning_id.")
            }
            let choices = ProvisioningPolicy.choices(for: record, in: state)
            let step: String
            // BL-092. Before anything is created, say what already exists. The
            // check runs only on the creation step — the one outcome that is
            // about to bring a second thing into being — and it changes no
            // decision: the owner's sheet is unchanged, and binding one of
            // these is its own approved step.
            var matches: [ProvisioningInventoryMatch] = []
            switch record.step {
            case .resourceSelection:
                step = "Vaultage is showing the owner a picker of \(choices.count) existing \(record.provider.title) resource(s) for this environment. Call vaultage_provision again with this provisioning_id to learn what they chose."
            case .creationAuthorization:
                matches = ResourceInventory.provisioningMatches(
                    provider: record.provider,
                    scopeKinds: record.capability.inventoryScopeKinds,
                    projectID: record.projectID,
                    environmentID: record.environmentID,
                    in: state,
                    at: instant
                )
                var sentence = "Vaultage is asking the owner to authorize creating a new scoped \(record.provider.title) \(ProviderResourceKind.cloudflareAPIToken.title) for this project and environment. Call vaultage_provision again with this provisioning_id to learn the result."
                if !matches.isEmpty {
                    sentence += " Before that: \(matches.count) cached \(record.provider.title) resource(s) already match this request — \(matches.map(\.name).joined(separator: ", ")). Ask the owner whether they would rather bind one of those than create a new resource."
                }
                step = sentence
            }
            return ProvisioningOutcome(
                status: record.step.status,
                provider: provider,
                capability: capability,
                projectID: record.projectID,
                environmentID: record.environmentID,
                provisioningID: record.id,
                choices: choices,
                inventoryMatches: matches,
                nextStep: step
            )
        }
    }

    private func boundOutcome(_ binding: Binding, provider: Provider, capability: ProvisioningCapability) -> ProvisioningOutcome {
        ProvisioningOutcome(
            status: .bound,
            provider: provider.rawValue,
            capability: capability.rawValue,
            projectID: binding.projectID,
            environmentID: binding.environmentID,
            bindingID: binding.id,
            operations: binding.allowedOperations.map(\.rawValue).sorted(),
            nextStep: "Call vaultage_execute with this binding_id and one of the listed operations. Credentials are never returned."
        )
    }

    /// Value-free projection of the open requests, for the desktop to render.
    public func openProvisioningRequests() async throws -> [PendingProvisioning] {
        let instant = now()
        let state = try await metadata.update { ProvisioningPolicy.purge(&$0, now: instant) }
        return state.pendingProvisionings.filter { $0.isOpen(at: instant) }
    }

    /// The human picked an existing resource. Called by the desktop from its
    /// native picker, never by an agent.
    ///
    /// Everything is re-resolved here: the pending record must still be open,
    /// the chosen item must still be one of the ones offered, and the
    /// connection must still be usable. A binding created this way is created
    /// by exactly the code a UI binding is, so it behaves identically.
    @discardableResult
    public func resolveProvisioningSelection(_ provisioningID: UUID, vaultItemID: UUID) async throws -> ProvisioningOutcome {
        let instant = now()
        let state = try await metadata.update { ProvisioningPolicy.purge(&$0, now: instant) }
        guard let record = state.pendingProvisionings.first(where: { $0.id == provisioningID }), record.isOpen(at: instant), record.step == .resourceSelection else {
            throw VaultageError.policyDenied("That provisioning request is no longer open.")
        }
        guard record.choiceVaultItemIDs.contains(vaultItemID) else {
            throw VaultageError.policyDenied("That vault item was not one of the resources offered for this request.")
        }
        guard let project = state.projects.first(where: { $0.id == record.projectID }),
              let environment = state.environments.first(where: { $0.id == record.environmentID }),
              let connection = state.connections.first(where: { $0.id == record.connectionID }),
              let item = state.vaultItems.first(where: { $0.id == vaultItemID }) else {
            throw VaultageError.policyDenied("The project, environment, connection or vault item for this request is unavailable.")
        }
        try await requireActiveManagedConnection(connection.id)
        let details = ApprovalDetails(
            project: project.name,
            environment: environment.name,
            provider: record.provider.title,
            connection: connection.label,
            operation: "provision.select.\(record.capability.rawValue)",
            reason: "An MCP client asked to give \(project.name) / \(environment.name) the ability to \(record.capability.title.lowercased()). This binds the existing vault item \"\(item.label)\" to that environment. It creates no new credential, moves no value anywhere, and returns nothing to the client but identifiers.",
            client: currentClient(state)
        )
        guard await approve(details) else {
            try await recordProvisioningResolution(provisioningID, .denied)
            try? await audit.append(AuditEvent(projectID: record.projectID, environmentID: record.environmentID, connectionID: connection.id, operation: "provision.select.\(record.capability.rawValue)", decision: .denied, result: "The owner declined to bind \(item.label) to \(project.name) / \(environment.name)."))
            throw VaultageError.approvalDenied
        }
        let binding = try await metadata.updateResult { fresh in
            ProvisioningPolicy.purge(&fresh, now: instant)
            guard let current = fresh.pendingProvisionings.first(where: { $0.id == provisioningID }), current.isOpen(at: instant),
                  current.choiceVaultItemIDs.contains(vaultItemID),
                  fresh.projects.contains(where: { $0.id == record.projectID }),
                  fresh.environments.contains(where: { $0.id == record.environmentID }),
                  fresh.connections.contains(where: { $0.id == record.connectionID }),
                  let freshItem = fresh.vaultItems.first(where: { $0.id == vaultItemID }),
                  MetadataRemoval.deletionReservation(forVaultItem: freshItem.id, in: fresh) == nil else {
                throw VaultageError.policyDenied("The records this selection named changed while the approval was open.")
            }
            // Idempotency once more, under the lock: if a covering binding
            // appeared while the sheet was up, reuse it.
            let existing = fresh.bindings.first {
                $0.projectID == record.projectID && $0.environmentID == record.environmentID
                    && $0.connectionID == record.connectionID && record.capability.isCovered(by: $0)
            }
            let binding = existing ?? Binding(projectID: record.projectID, environmentID: record.environmentID, connectionID: record.connectionID, allowedOperations: record.capability.bindingOperations)
            if existing == nil { fresh.bindings.append(binding) }
            // D71: no source record. Since schema 28 that record says "an
            // agent may deliver this item from this binding", which the owner
            // did not say here — the sheet promised this selection moves no
            // value anywhere. The owner allows a source in the binding's own
            // control, if they ever want an agent to deliver it.
            if let index = fresh.pendingProvisionings.firstIndex(where: { $0.id == provisioningID }) {
                fresh.pendingProvisionings[index].resolution = .bound(bindingID: binding.id)
            }
            return binding
        }
        try? await audit.append(AuditEvent(projectID: record.projectID, environmentID: record.environmentID, connectionID: connection.id, operation: "provision.select.\(record.capability.rawValue)", decision: .executed, result: "Bound the existing vault item \(item.label) to \(project.name) / \(environment.name) for \(record.capability.rawValue)."))
        return boundOutcome(binding, provider: record.provider, capability: record.capability)
    }

    /// The human authorized creating a new resource. This runs the full BL-074
    /// creation — its own approval sheet, its own OS authentication, its own
    /// receipts — and records the resulting binding as this request's answer.
    @discardableResult
    public func resolveProvisioningCreation(_ provisioningID: UUID, target: CloudflareTokenTarget, label: String) async throws -> ProvisioningOutcome {
        let instant = now()
        let state = try await metadata.update { ProvisioningPolicy.purge(&$0, now: instant) }
        guard let record = state.pendingProvisionings.first(where: { $0.id == provisioningID }), record.isOpen(at: instant), record.step == .creationAuthorization else {
            throw VaultageError.policyDenied("That provisioning request is no longer open.")
        }
        do {
            let summary = try await createProviderResource(ProviderResourceCreationRequest(
                projectID: record.projectID,
                environmentID: record.environmentID,
                connectionID: record.connectionID,
                capability: record.capability,
                target: target,
                label: label
            ))
            try await recordProvisioningResolution(provisioningID, .bound(bindingID: summary.bindingID))
            let fresh = try await metadata.load()
            guard let binding = fresh.bindings.first(where: { $0.id == summary.bindingID }) else {
                throw VaultageError.storage("The binding was created but could not be projected.")
            }
            return boundOutcome(binding, provider: record.provider, capability: record.capability)
        } catch let error as VaultageError where error == .approvalDenied {
            try await recordProvisioningResolution(provisioningID, .denied)
            throw error
        } catch {
            // The agent is told the request failed and why, in redacted words.
            // It is not told to retry: a `result_unknown` creation may have
            // made a token.
            try await recordProvisioningResolution(provisioningID, .failed(message: Redactor.publicError(error)))
            throw error
        }
    }

    /// The human declined without picking or creating anything.
    public func denyProvisioning(_ provisioningID: UUID) async throws {
        try await recordProvisioningResolution(provisioningID, .denied)
    }

    private func recordProvisioningResolution(_ provisioningID: UUID, _ resolution: PendingProvisioning.Resolution) async throws {
        _ = try await metadata.update { fresh in
            guard let index = fresh.pendingProvisionings.firstIndex(where: { $0.id == provisioningID }) else { return }
            // An answered request is never re-answered.
            if fresh.pendingProvisionings[index].resolution == nil {
                fresh.pendingProvisionings[index].resolution = resolution
            }
        }
    }

    // MARK: - BL-074 provider resource creation and revocation

    /// Creates one provider resource, stores its value as a new protected vault
    /// item, and links that item to the connection and to the target project
    /// environment as a runtime-source authorization on a new binding.
    ///
    /// This is a third approval class, alongside the action sheet and the grant
    /// sheet. It is reachable only from the desktop — `ProviderResourceOperation`
    /// is not a member of `Operation`, so it is not in any MCP tool schema, not
    /// storable in `Binding.allowedOperations`, and not coverable by an
    /// auto-allow grant.
    ///
    /// The created value never becomes a return value: this method's result is
    /// a value-free summary of identifiers and labels.
    @discardableResult
    public func createProviderResource(_ request: ProviderResourceCreationRequest) async throws -> ProviderResourceSummary {
        guard let resourceCreator else {
            throw VaultageError.unsupported("This Vaultage composition cannot create provider resources.")
        }
        let label = try ProvisionedResourceLabel.validated(request.label)
        let template = request.capability.policyTemplate
        let target = try request.target.validated(for: template)
        let operation = ProviderResourceOperation.cloudflareTokenCreate

        let state = try await metadata.load()
        let resolution: ProvisioningResolutionRecords
        do { resolution = try provisioningRecords(state, projectID: request.projectID, environmentID: request.environmentID, connectionID: request.connectionID) }
        catch {
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: request.connectionID, operation: operation.rawValue, decision: .blocked, result: Redactor.publicError(error)))
            throw error
        }
        try await requireActiveManagedConnection(resolution.connection.id)
        // Vaultage cannot attest that this token carries token-creation
        // permission: `/user/tokens/verify` reports status and ID, not
        // policies (contracts §7). What it can require is that the connection
        // is currently verified against the fixed probe. Cloudflare enforces
        // the rest on the POST, and a 403 surfaces as `permission_missing`.
        try requireCurrentVerification(connection: resolution.connection, item: resolution.managingItem, operation: .cloudflareVerifyToken)

        let digest = creationDigest(request: request, label: label, template: template, target: target, resolution: resolution)
        let disclosure = ProviderResourceCreationDisclosure(
            provider: Provider.cloudflare.title,
            accountDescription: target.sheetDescription,
            resourceKind: ProviderResourceKind.cloudflareAPIToken.title,
            templateDisplayName: template.displayName,
            templateEffect: template.effect,
            permissionGroupNames: template.permissionGroupNames,
            project: resolution.project.name,
            environment: resolution.environment.name,
            isProduction: resolution.environment.isProduction,
            vaultLabel: label,
            requestDigest: digest
        )
        let details = ApprovalDetails(
            project: resolution.project.name,
            environment: resolution.environment.name,
            provider: Provider.cloudflare.title,
            connection: resolution.connection.label,
            operation: operation.rawValue,
            reason: "\(ProviderResourceCreationDisclosure.custodySentence) \(providerEvidenceDescription(resolution.connection))",
            client: currentClient(state),
            providerResourceCreation: disclosure
        )
        guard await approve(details) else {
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: resolution.connection.id, operation: operation.rawValue, decision: .denied, result: "The owner denied creating a \(template.displayName) token."))
            throw VaultageError.approvalDenied
        }
        let approvedAt = now()

        // Approving names an immutable selection. Re-resolve before any
        // Keychain read, exactly as the read and runtime-delivery paths do.
        let refreshedState = try await metadata.load()
        let refreshed: ProvisioningResolutionRecords
        do { refreshed = try provisioningRecords(refreshedState, projectID: request.projectID, environmentID: request.environmentID, connectionID: request.connectionID) }
        catch {
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: nil, operation: operation.rawValue, decision: .blocked, result: "The connection or environment changed while approval was pending."))
            throw VaultageError.policyDenied("The approved provider resource creation changed before execution.")
        }
        guard creationDigest(request: request, label: label, template: template, target: target, resolution: refreshed) == digest else {
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: nil, operation: operation.rawValue, decision: .blocked, result: "The records this creation named changed while approval was pending."))
            throw VaultageError.policyDenied("The approved provider resource creation changed before execution.")
        }
        try await requireActiveManagedConnection(refreshed.connection.id)
        try requireCurrentVerification(connection: refreshed.connection, item: refreshed.managingItem, operation: .cloudflareVerifyToken)

        // The durable, value-free receipt is the egress precondition, as it is
        // for the Worker secret write. If it cannot be written, nothing is read
        // and nothing is sent.
        let invocationID = UUID()
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: nil, operation: operation.rawValue, requestDigest: digest, decision: .pending, result: "Approved \(template.displayName) token creation pending."))

        let managingToken: VaultSecret
        do { managingToken = try vault.read(account: refreshed.managingItem.keychainAccount, prompt: "Create a \(template.displayName) token for \(refreshed.project.name) / \(refreshed.environment.name)") }
        catch {
            try await completeResourceReceipt(invocationID, request: request, digest: digest, operation: operation, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: "OS authentication failed or was cancelled; no token was created.")
            throw error
        }
        do {
            guard now().timeIntervalSince(approvedAt) <= 60 else { throw VaultageError.approvalDenied }
            let finalState = try await metadata.load()
            let final = try provisioningRecords(finalState, projectID: request.projectID, environmentID: request.environmentID, connectionID: request.connectionID)
            guard creationDigest(request: request, label: label, template: template, target: target, resolution: final) == digest else {
                throw VaultageError.policyDenied("The approved provider resource creation changed before egress.")
            }
            try await requireActiveManagedConnection(final.connection.id)
            try requireCurrentVerification(connection: final.connection, item: final.managingItem, operation: .cloudflareVerifyToken)
        } catch {
            try await completeResourceReceipt(invocationID, request: request, digest: digest, operation: operation, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: "Creation authorization changed or expired after OS authentication; no token was created.")
            throw error
        }

        let created: CreatedProviderResource
        do {
            created = try await resourceCreator.createCloudflareToken(
                managingToken: managingToken,
                plan: CloudflareTokenCreationPlan(template: template, target: target, tokenName: ProvisionedResourceLabel.providerTokenName(for: label))
            )
        } catch let error as VaultageError where error == .resultUnknown {
            // The POST was dispatched and its outcome is unknown. A token may
            // exist in the Cloudflare account with a value Vaultage does not
            // have and can never retrieve. Say exactly that; do not retry.
            try? await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: nil, operation: operation.rawValue, requestDigest: digest, decision: .resultUnknown, result: "Cloudflare token creation result unknown; no retry was performed. A token named \(ProvisionedResourceLabel.providerTokenName(for: label)) may exist in this Cloudflare account with a value Vaultage does not hold. Review it in the Cloudflare dashboard and delete it if it is unwanted."))
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: refreshed.connection.id, operation: operation.rawValue, decision: .resultUnknown, result: "Cloudflare token creation result unknown; no retry was performed. Check the Cloudflare dashboard for a token named \(ProvisionedResourceLabel.providerTokenName(for: label))."))
            throw error
        } catch {
            try await completeResourceReceipt(invocationID, request: request, digest: digest, operation: operation, connectionID: refreshed.connection.id, decision: .failed, result: Redactor.publicError(error))
            throw error
        }

        // The value exists now and exists nowhere else. Write it to the
        // Keychain before anything else, and if the metadata commit fails,
        // remove the orphaned Keychain record rather than leaving a protected
        // value no record points at.
        let keychainAccount = UUID().uuidString
        do {
            var saved = false
            var saveError: Error?
            created.value.withBytes { raw in
                do { try vault.save(Data(raw), account: keychainAccount); saved = true }
                catch { saveError = error }
            }
            guard saved else { throw saveError ?? VaultageError.storage("The created token could not be stored.") }
        } catch {
            try? await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: nil, operation: operation.rawValue, requestDigest: digest, decision: .resultUnknown, result: "Cloudflare created token \(created.providerResourceID) but Vaultage could not store its value. The value is now unrecoverable; revoke that token in the Cloudflare dashboard."))
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: refreshed.connection.id, operation: operation.rawValue, decision: .resultUnknown, result: "A Cloudflare token was created but could not be stored locally. Revoke token \(created.providerResourceID) in the Cloudflare dashboard."))
            throw VaultageError.resultUnknown
        }

        let summary: ProviderResourceSummary
        do {
            summary = try await metadata.updateResult { fresh in
                guard let project = fresh.projects.first(where: { $0.id == request.projectID }),
                      let environment = fresh.environments.first(where: { $0.id == request.environmentID }),
                      environment.projectID == project.id,
                      let connection = fresh.connections.first(where: { $0.id == request.connectionID }),
                      connection.provider == .cloudflare else {
                    throw VaultageError.policyDenied("The project, environment or connection changed before the created token could be linked.")
                }
                let item = VaultItem(label: label, provider: .cloudflare, keychainAccount: keychainAccount)
                let binding = Binding(projectID: project.id, environmentID: environment.id, connectionID: connection.id, allowedOperations: request.capability.bindingOperations)
                let record = ProvisionedResource(
                    provider: .cloudflare,
                    kind: created.kind,
                    providerResourceID: created.providerResourceID,
                    vaultItemID: item.id,
                    connectionID: connection.id,
                    projectID: project.id,
                    environmentID: environment.id,
                    bindingID: binding.id,
                    capability: request.capability,
                    templateID: template.id,
                    createdAt: self.now(),
                    // BL-094. Cloudflare already returns this on a token
                    // create and BL-074 already puts it on the receipt; the
                    // record now keeps it, so the deployed-credential ledger
                    // can tell an environment card when a delivered credential
                    // is going to stop working.
                    expiresAt: created.expiresAt
                )
                fresh.vaultItems.append(item)
                fresh.bindings.append(binding)
                // D71: no source record — see `resolveProvisioningSelection`.
                fresh.provisionedResources.append(record)
                return ProviderResourceSummary(
                    provisionedResourceID: record.id,
                    vaultItemID: item.id,
                    bindingID: binding.id,
                    connectionID: connection.id,
                    projectID: project.id,
                    environmentID: environment.id,
                    providerResourceID: created.providerResourceID,
                    label: label,
                    capability: request.capability,
                    operations: binding.allowedOperations.map(\.rawValue).sorted()
                )
            }
        } catch {
            // The token exists and its value is in the Keychain, but nothing
            // points at it. Do not delete the Keychain record — that would
            // destroy the only copy of a live credential. Report unknown.
            try? await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: nil, operation: operation.rawValue, requestDigest: digest, decision: .resultUnknown, result: "Cloudflare token \(created.providerResourceID) was created and stored, but linking it to the project failed. It is not usable through Vaultage until relinked."))
            try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: refreshed.connection.id, operation: operation.rawValue, decision: .resultUnknown, result: "A Cloudflare token was created and stored but could not be linked to the project."))
            throw VaultageError.resultUnknown
        }

        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: summary.bindingID, operation: operation.rawValue, requestDigest: digest, decision: .executed, result: "Created Cloudflare \(created.kind.title) \(created.providerResourceID) under the \(template.displayName) template and stored it as a protected vault item. The value was not returned to any caller."))
        try? await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: refreshed.connection.id, operation: operation.rawValue, decision: .executed, result: "Created a \(template.displayName) Cloudflare token for \(refreshed.project.name) / \(refreshed.environment.name) and stored it as \(label)."))
        return summary
    }

    /// The separate approved revocation. BL-074 requires it to be its own
    /// operation and requires a failure to revoke to be reported honestly:
    /// a provider that does not confirm the deletion leaves `revokedAt` nil and
    /// stamps `revocationFailedAt` instead.
    ///
    /// **D44c — the sweep.** BL-074's live proof
    /// (`blueprint/evidence/core-lane-live-cloudflare-proof-2026-09-11.md` §7)
    /// observed that a confirmed revocation left the protected vault item's
    /// value in place, receipted as "Its protected vault item was left in
    /// place", and recorded that whether it should be swept was an open product
    /// question. The owner answered it: "When a provisioned token is revoked,
    /// the broker deletes the protected value and keeps the value-free record
    /// marked revoked for audit."
    ///
    /// The order is the rule, and it is one-directional:
    ///
    /// 1. The provider is asked to revoke. If that throws, **nothing is
    ///    deleted** — the token may still be live and its value is the only copy
    ///    Vaultage has; the record stays live with `revocationFailedAt`
    ///    stamped, and the receipt says the token may still be live. This is the
    ///    pre-existing path, unchanged.
    /// 2. The adapter's own read-back is what counts as confirmation: a 2xx
    ///    whose `result.id` is this exact token, or a 404, which is Cloudflare
    ///    saying it does not have the token at all. Anything else already threw
    ///    at step 1. The identifier is re-checked here rather than trusted, so a
    ///    confirmation for some *other* token can never authorize this
    ///    deletion.
    /// 3. Only then is the protected value deleted, and only then is
    ///    `valueSweptAt` stamped. A deletion that fails leaves the stamp unset
    ///    and says so in the receipt: the token is dead either way, but claiming
    ///    the local value is gone when it is not is the false state BL-074
    ///    exists to avoid.
    ///
    /// The value-free `ProvisionedResource` **stays**, marked revoked, for
    /// audit — that is the half of D44c that is not a deletion. So does the
    /// `VaultItem`, its `Binding` and its `RuntimeSourceAuthorization`: the
    /// sweep removes the secret, not the history of it, and
    /// `MetadataRemoval.reserveVaultItemDeletion` would refuse to remove the
    /// item anyway while those references exist. What the owner sees is a vault
    /// item whose `hasProtectedValue` still reads true and whose reveal now
    /// fails — recorded in the evidence note as the one rough edge, and owed to
    /// the UI lane rather than papered over here.
    @discardableResult
    /// What a revocation approval is over: the record, the provider's id, the
    /// managing connection and credential, and the environment.
    private static func revocationDigest(record: ProvisionedResource, managingItem: VaultItem) -> String {
        CanonicalDigest.hex([
            "vaultage.resource.revoke.digest",
            record.id.uuidString,
            record.providerResourceID,
            record.connectionID.uuidString,
            managingItem.keychainAccount,
            managingItem.credentialVersion?.uuidString ?? "none",
            record.projectID.uuidString,
            record.environmentID.uuidString
        ])
    }

    public func revokeProviderResource(_ provisionedResourceID: UUID) async throws -> ProviderResourceRevocation {
        guard let resourceCreator else {
            throw VaultageError.unsupported("This Vaultage composition cannot revoke provider resources.")
        }
        let operation = ProviderResourceOperation.cloudflareTokenRevoke
        let state = try await metadata.load()
        guard let record = state.provisionedResources.first(where: { $0.id == provisionedResourceID }), record.isLive,
              let project = state.projects.first(where: { $0.id == record.projectID }),
              let environment = state.environments.first(where: { $0.id == record.environmentID }),
              let connection = state.connections.first(where: { $0.id == record.connectionID }),
              connection.provider == .cloudflare,
              let managingItem = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
              managingItem.provider == .cloudflare,
              MetadataRemoval.deletionReservation(forVaultItem: managingItem.id, in: state) == nil else {
            throw VaultageError.policyDenied("That provisioned resource, its connection, or its managing credential is unavailable.")
        }
        try await requireActiveManagedConnection(connection.id)
        try requireCurrentVerification(connection: connection, item: managingItem, operation: .cloudflareVerifyToken)
        // Audit M-30: a token that still feeds a live deployment is not
        // revoked from here — the deployment would keep running on a dead
        // value with a ledger row that says otherwise. Rotate or revoke those
        // deliveries first.
        let liveDeployments = state.deployedCredentials.filter { $0.sourceVaultItemID == record.vaultItemID && $0.status.isLive }
        guard liveDeployments.isEmpty else {
            throw VaultageError.policyDenied("This token is deployed to \(liveDeployments.count) destination\(liveDeployments.count == 1 ? "" : "s") (\(liveDeployments.map(\.destination.name).sorted().joined(separator: ", "))). Rotate or revoke those deliveries before revoking the token.")
        }
        let label = state.vaultItems.first(where: { $0.id == record.vaultItemID })?.label ?? "(removed vault item)"
        let digest = Self.revocationDigest(record: record, managingItem: managingItem)
        let disclosure = ProviderResourceRevocationDisclosure(
            provider: Provider.cloudflare.title,
            resourceKind: record.kind.title,
            providerResourceID: record.providerResourceID,
            vaultLabel: label,
            project: project.name,
            environment: environment.name,
            requestDigest: digest
        )
        let details = ApprovalDetails(
            project: project.name,
            environment: environment.name,
            provider: Provider.cloudflare.title,
            connection: connection.label,
            operation: operation.rawValue,
            reason: "\(ProviderResourceRevocationDisclosure.effectSentence) \(providerEvidenceDescription(connection))",
            client: currentClient(state),
            providerResourceRevocation: disclosure
        )
        guard await approve(details) else {
            try? await audit.append(AuditEvent(projectID: record.projectID, environmentID: record.environmentID, connectionID: connection.id, operation: operation.rawValue, decision: .denied, result: "The owner denied revoking Cloudflare token \(record.providerResourceID)."))
            throw VaultageError.approvalDenied
        }
        let invocationID = UUID()
        // Audit M-30: the sheet was composed from a snapshot. Before anything
        // is read or sent, the live records must still be exactly what the
        // owner approved — the same digest, recomputed from a fresh load.
        let fresh = try await metadata.load()
        guard let liveRecord = fresh.provisionedResources.first(where: { $0.id == record.id }), liveRecord.isLive,
              let liveConnection = fresh.connections.first(where: { $0.id == record.connectionID }),
              let liveItem = fresh.vaultItems.first(where: { $0.id == liveConnection.vaultItemID }),
              MetadataRemoval.deletionReservation(forVaultItem: liveItem.id, in: fresh) == nil,
              !fresh.deployedCredentials.contains(where: { $0.sourceVaultItemID == record.vaultItemID && $0.status.isLive }),
              Self.revocationDigest(record: liveRecord, managingItem: liveItem) == digest else {
            try? await audit.append(AuditEvent(projectID: record.projectID, environmentID: record.environmentID, connectionID: connection.id, operation: operation.rawValue, decision: .blocked, result: "The records this revocation named changed while the approval was open; nothing was revoked."))
            throw VaultageError.policyDenied("The records this revocation named changed while the approval was open. Review and approve again.")
        }
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: invocationID, at: .now, projectID: record.projectID, environmentID: record.environmentID, bindingID: record.bindingID, operation: operation.rawValue, requestDigest: digest, decision: .pending, result: "Approved revocation of Cloudflare token \(record.providerResourceID) pending."))
        let managingToken: VaultSecret
        do { managingToken = try vault.read(account: liveItem.keychainAccount, prompt: "Revoke Cloudflare token \(record.providerResourceID)") }
        catch {
            try await completeResourceReceipt(invocationID, projectID: record.projectID, environmentID: record.environmentID, bindingID: record.bindingID, digest: digest, operation: operation, connectionID: connection.id, decision: terminalDecision(for: error), result: "OS authentication failed or was cancelled; the token was not revoked.")
            throw error
        }
        let outcome: ProviderResourceRevocation
        do { outcome = try await resourceCreator.revokeCloudflareToken(managingToken: managingToken, tokenID: record.providerResourceID) }
        catch {
            // Honest reporting: the local record still says live, and the
            // failure is stamped so the UI can show "revocation failed".
            _ = try? await metadata.update { fresh in
                if let index = fresh.provisionedResources.firstIndex(where: { $0.id == record.id }) {
                    fresh.provisionedResources[index].revocationFailedAt = self.now()
                }
            }
            try await completeResourceReceipt(invocationID, projectID: record.projectID, environmentID: record.environmentID, bindingID: record.bindingID, digest: digest, operation: operation, connectionID: connection.id, decision: .failed, result: "Cloudflare did not confirm revocation of token \(record.providerResourceID): \(Redactor.publicError(error)) The token may still be live; revoke it in the Cloudflare dashboard.")
            throw error
        }
        // D44c step 2. The adapter already refused anything that is not a
        // confirmation, but the identifier is re-checked here rather than
        // trusted: a `revoked: true` carrying some other token's id must never
        // be what authorizes deleting *this* record's value.
        guard outcome.revoked, outcome.providerResourceID == record.providerResourceID else {
            _ = try? await metadata.update { fresh in
                if let index = fresh.provisionedResources.firstIndex(where: { $0.id == record.id }) {
                    fresh.provisionedResources[index].revocationFailedAt = self.now()
                }
            }
            try await completeResourceReceipt(invocationID, projectID: record.projectID, environmentID: record.environmentID, bindingID: record.bindingID, digest: digest, operation: operation, connectionID: connection.id, decision: .failed, result: "Cloudflare did not confirm revocation of token \(record.providerResourceID). The token may still be live; revoke it in the Cloudflare dashboard. Its protected value was kept.")
            throw VaultageError.providerResultInvalid
        }

        // D44c step 3. The provider has confirmed; the value is dead. Delete it.
        // Every secret account this item owns, not only the primary: the
        // provisioned item is created with one field today, and a sweep that
        // quietly missed a second one later would leave a dead value behind
        // while the receipt said otherwise.
        let sweptState = try await metadata.load()
        let sweptItem = sweptState.vaultItems.first { $0.id == record.vaultItemID }
        var accounts: [String] = []
        if let sweptItem {
            accounts.append(sweptItem.keychainAccount)
            accounts.append(contentsOf: sweptItem.secretFields.compactMap(\.keychainAccount).filter { $0 != sweptItem.keychainAccount })
        }
        var sweepFailure: Error?
        for account in accounts {
            do { try vault.delete(account: account) } catch { sweepFailure = sweepFailure ?? error }
        }

        let swept = sweepFailure == nil
        _ = try? await metadata.update { fresh in
            if let index = fresh.provisionedResources.firstIndex(where: { $0.id == record.id }) {
                fresh.provisionedResources[index].revokedAt = self.now()
                fresh.provisionedResources[index].revocationFailedAt = nil
                // Only ever stamped for a deletion that actually returned. A
                // record whose item had already gone counts as swept: there is
                // no protected value left to delete, which is the state the
                // stamp describes.
                fresh.provisionedResources[index].valueSweptAt = swept ? self.now() : nil
            }
        }
        // `completeResourceReceipt` clips the result to 240 characters
        // (`Redactor.safeError`), and the sentence above spends 74 of them, so
        // each of these says its piece in the room that is left. The part that
        // must survive clipping is the part that differs.
        let sweepSentence: String
        if let sweepFailure {
            sweepSentence = "Its dead protected value could NOT be deleted here (\(Redactor.publicError(sweepFailure))) and is still present; delete that vault item."
        } else if sweptItem == nil {
            sweepSentence = "Its vault item was already gone; no protected value was left to delete."
        } else {
            sweepSentence = "Its protected value was deleted from this Mac. The value-free record is kept, marked revoked."
        }
        try await completeResourceReceipt(invocationID, projectID: record.projectID, environmentID: record.environmentID, bindingID: record.bindingID, digest: digest, operation: operation, connectionID: connection.id, decision: .executed, result: "Cloudflare confirmed revocation of token \(record.providerResourceID). \(sweepSentence)")
        return outcome
    }

    /// The records a provisioning or creation request names, resolved together
    /// so no partial match can proceed.
    private func provisioningRecords(_ state: VaultageMetadata, projectID: UUID, environmentID: UUID, connectionID: UUID) throws -> ProvisioningResolutionRecords {
        guard let project = state.projects.first(where: { $0.id == projectID }),
              let environment = state.environments.first(where: { $0.id == environmentID }),
              environment.projectID == project.id,
              let connection = state.connections.first(where: { $0.id == connectionID }),
              connection.provider == .cloudflare,
              let managingItem = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
              managingItem.provider == .cloudflare,
              MetadataRemoval.deletionReservation(forVaultItem: managingItem.id, in: state) == nil else {
            throw VaultageError.policyDenied("The project, environment, or Cloudflare connection named for this provisioning is not valid.")
        }
        return ProvisioningResolutionRecords(project: project, environment: environment, connection: connection, managingItem: managingItem)
    }

    /// RP-07: one canonical injective encoding, as every other digest here.
    private func creationDigest(request: ProviderResourceCreationRequest, label: String, template: CloudflareTokenPolicyTemplate, target: CloudflareTokenTarget, resolution: ProvisioningResolutionRecords) -> String {
        let evidence = resolution.connection.verification
        return CanonicalDigest.hex([
            "vaultage.resource.create.digest",
            request.projectID.uuidString,
            request.environmentID.uuidString,
            resolution.connection.id.uuidString,
            resolution.managingItem.id.uuidString,
            resolution.managingItem.keychainAccount,
            resolution.managingItem.credentialVersion?.uuidString ?? "none",
            evidence?.providerContractRevision ?? "none",
            "\(evidence?.verifiedAt.timeIntervalSince1970 ?? 0)",
            evidence?.principalID ?? "unknown",
            request.capability.rawValue,
            template.id,
            target.accountID,
            target.zoneID ?? "none",
            label
        ])
    }

    private func completeResourceReceipt(_ correlationID: UUID, request: ProviderResourceCreationRequest, digest: String, operation: ProviderResourceOperation, connectionID: UUID?, decision: AuditDecision, result: String) async throws {
        try await completeResourceReceipt(correlationID, projectID: request.projectID, environmentID: request.environmentID, bindingID: nil, digest: digest, operation: operation, connectionID: connectionID, decision: decision, result: result)
    }

    private func completeResourceReceipt(_ correlationID: UUID, projectID: UUID, environmentID: UUID, bindingID: UUID?, digest: String, operation: ProviderResourceOperation, connectionID: UUID?, decision: AuditDecision, result: String) async throws {
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: correlationID, at: .now, projectID: projectID, environmentID: environmentID, bindingID: bindingID, operation: operation.rawValue, requestDigest: digest, decision: decision, result: Redactor.safeError(result)))
        try? await audit.append(AuditEvent(projectID: projectID, environmentID: environmentID, connectionID: connectionID, operation: operation.rawValue, decision: decision, result: Redactor.safeError(result)))
    }

    // MARK: - BL-091 binding a provider resource (desktop only)

    /// Attaches a bound resource scope to an existing binding and widens that
    /// binding to the resource operations the human approved.
    ///
    /// This is how "the provisioning conversation can bind a resource created
    /// this way" is actually delivered, and it is deliberately **not** on
    /// `BrokerFacade`: like the provisioning selection and creation resolvers,
    /// it is desktop-only, so no MCP client, XPC message or grant can answer its
    /// own request. `vaultage_provision` produces the binding; the human then
    /// names the zone, account or project — including one whose id came back
    /// from a `create` this ticket added — in one more approved step.
    ///
    /// Three things are checked before the sheet and again after it:
    ///
    /// * the scope is well formed and belongs to the connection's provider;
    /// * every requested operation is a resource operation whose permitted
    ///   scope kinds include this scope's kind — so a Vercel project scope
    ///   cannot be attached to a Cloudflare DNS operation, or a zone scope to
    ///   the Worker script list; and
    /// * nothing that mints a credential is in the set.
    @discardableResult
    public func bindProviderResource(bindingID: UUID, scope: ProviderResourceScope, operations: Set<Operation>) async throws -> Binding {
        guard scope.isWellFormed else { throw VaultageError.invalidInput("That resource scope is not a valid provider identifier.") }
        guard !operations.isEmpty else { throw VaultageError.invalidInput("Name at least one operation to allow on this resource.") }
        for operation in operations {
            guard operation.isResourceOperation || operation.taxonomy.kind == .read else {
                throw VaultageError.invalidInput("\(operation.rawValue) is not a provider resource operation.")
            }
            guard operation.approvalRequirement != .nativeApprovalOnly else {
                throw VaultageError.policyDenied("\(operation.rawValue) mints a credential and cannot be put in a binding.")
            }
            guard operation.provider == scope.provider else {
                throw VaultageError.invalidInput("\(operation.rawValue) does not belong to \(scope.provider.title).")
            }
            if operation.isResourceOperation {
                guard ProviderResourceScope.kinds(for: operation).contains(scope.kind) else {
                    throw VaultageError.invalidInput("\(operation.rawValue) cannot run against a \(scope.kind.rawValue) scope.")
                }
            }
        }
        let state = try await metadata.load()
        guard let binding = state.bindings.first(where: { $0.id == bindingID }),
              let project = state.projects.first(where: { $0.id == binding.projectID }),
              let environment = state.environments.first(where: { $0.id == binding.environmentID }),
              let connection = state.connections.first(where: { $0.id == binding.connectionID }),
              connection.provider == scope.provider else {
            throw VaultageError.invalidInput("That binding no longer exists, or it is not for \(scope.provider.title).")
        }
        try await requireActiveManagedConnection(connection.id)
        let sorted = operations.map(\.rawValue).sorted()
        // BL-128 slice 3c, second security pass. A bind keeps what the binding
        // already allows and moves it onto the new scope — so re-pointing a
        // binding that may deliver into repository A at repository B carries
        // that write to B. The sheet therefore names everything the binding
        // will allow afterwards, not only what this bind adds, and the kept
        // set is a term of the digest, so a change to it while the sheet is
        // up refuses rather than binding something the sheet did not say.
        let kept = binding.allowedOperations.subtracting(operations).map(\.rawValue).sorted()
        let digest = CanonicalDigest.hex(["vaultage.resource.bind.digest", bindingID.uuidString, connection.id.uuidString, project.id.uuidString, environment.id.uuidString, "\(sorted.count)"] + sorted + ["kept", "\(kept.count)"] + kept + scope.canonicalFields)
        let mutations = binding.allowedOperations.union(operations).filter { $0.taxonomy.kind != .read }.map(\.rawValue).sorted()
        let repointed = binding.resourceScope.flatMap { $0 == scope ? nil : $0.sheetTarget }
        let details = ApprovalDetails(
            project: project.name,
            environment: environment.name,
            provider: connection.provider.title,
            connection: connection.label,
            operation: "provider.resource.bind",
            reason: "Bind \(scope.sheetTarget) to this environment and allow \(sorted.joined(separator: ", ")) on it.\(repointed.map { " This moves the binding off \($0); what it already allows moves with it." } ?? "")\(kept.isEmpty ? "" : " It keeps \(kept.joined(separator: ", ")), now on this scope.") \(mutations.isEmpty ? "These are reads; nothing here changes provider state." : "This binding will be able to change provider state: \(mutations.joined(separator: ", ")). Every delete and every production-affecting change still asks for approval and names the exact resource id.") \(providerEvidenceDescription(connection))",
            client: currentClient(state)
        )
        guard await approve(details) else {
            try? await audit.append(AuditEvent(projectID: project.id, environmentID: environment.id, connectionID: connection.id, operation: "provider.resource.bind", decision: .denied, result: "The owner declined binding \(scope.sheetTarget)."))
            throw VaultageError.approvalDenied
        }
        // Re-resolve and re-compare after the sheet: a binding, connection or
        // plan state that moved while it was up denies rather than being bound.
        let updated = try await metadata.updateResult { fresh in
            guard let index = fresh.bindings.firstIndex(where: { $0.id == bindingID }),
                  let freshProject = fresh.projects.first(where: { $0.id == fresh.bindings[index].projectID }),
                  let freshEnvironment = fresh.environments.first(where: { $0.id == fresh.bindings[index].environmentID }),
                  let freshConnection = fresh.connections.first(where: { $0.id == fresh.bindings[index].connectionID }),
                  freshConnection.provider == scope.provider else {
                throw VaultageError.policyDenied("The binding changed while the approval was open.")
            }
            let freshKept = fresh.bindings[index].allowedOperations.subtracting(operations).map(\.rawValue).sorted()
            let freshDigest = CanonicalDigest.hex(["vaultage.resource.bind.digest", bindingID.uuidString, freshConnection.id.uuidString, freshProject.id.uuidString, freshEnvironment.id.uuidString, "\(sorted.count)"] + sorted + ["kept", "\(freshKept.count)"] + freshKept + scope.canonicalFields)
            guard freshDigest == digest else { throw VaultageError.policyDenied("The binding changed while the approval was open.") }
            fresh.bindings[index].resourceScope = scope
            fresh.bindings[index].allowedOperations.formUnion(operations)
            return fresh.bindings[index]
        }
        try? await audit.append(AuditEvent(projectID: project.id, environmentID: environment.id, connectionID: connection.id, operation: "provider.resource.bind", decision: .executed, result: "Bound \(scope.sheetTarget) and allowed \(sorted.joined(separator: ", "))."))
        return updated
    }

    // MARK: - BL-092 the cross-provider Resources inventory

    /// `inventory.refresh(connectionID)`. Runs every read this connection's
    /// bindings already allow that would report a resource, and caches the
    /// results value-free.
    ///
    /// Four things are deliberate, and each one is the reason a piece of code is
    /// *missing* here rather than present:
    ///
    /// * **No new approval class.** Each step is dispatched through
    ///   `execute` / `executeResourceOperation` — the same functions an agent's
    ///   read goes through, with the same verification, digest re-proof,
    ///   grant check and receipt. A read is `bindingsAndGrants`, so a refresh is
    ///   silent under a covering grant and one sheet per read otherwise. There
    ///   is no policy branch that only a refresh can reach.
    /// * **On demand only.** Nothing calls this on a timer, at launch, or after
    ///   a connection verifies. The rate-limit claim below is what stops a held
    ///   button becoming a poll, and it is claimed *before* the first read so
    ///   two concurrent refreshes cannot both be told they are first.
    /// * **Per-operation error isolation.** A step that fails contributes no
    ///   kind, and `ResourceInventory.merge` replaces only the kinds that were
    ///   actually re-read — so one provider outage narrows what was learned
    ///   rather than deleting what was already known.
    /// * **Desktop-only.** It is absent from `BrokerFacade`, like the
    ///   provisioning resolvers and `bindProviderResource`, so no MCP client can
    ///   make this Mac talk to nine providers by asking. The agent-facing tool
    ///   reads the cache and is told, in words, when it needs refreshing.
    @discardableResult
    public func refreshInventory(connectionID: UUID, force: Bool = false) async throws -> InventoryRefreshReport {
        let state = try await metadata.load()
        guard let connection = state.connections.first(where: { $0.id == connectionID }) else {
            throw VaultageError.invalidInput("That connection no longer exists.")
        }
        guard connection.state == .verified, connection.verification != nil else {
            throw VaultageError.policyDenied("Verify this \(connection.provider.title) connection in Services before refreshing its resources.")
        }
        try await requireActiveManagedConnection(connectionID)
        let steps = InventoryRefreshPlan.steps(for: connectionID, in: state)
        guard !steps.isEmpty else {
            throw VaultageError.policyDenied("No binding allows a read that would list \(connection.provider.title) resources. Bind one of \(InventoryReadProjection.supportedOperations(for: connection.provider).map(\.rawValue).sorted().joined(separator: ", ")) to a project environment first.")
        }

        // The rate-limit claim, taken under the metadata lock and before any
        // read. It doubles as the "a refresh is in flight" record, so a crash
        // mid-refresh leaves an honest interrupted record rather than a silent
        // gap — and still holds the window, so a crash loop cannot poll.
        let started = now()
        let claim = try await metadata.updateResult { fresh -> InventoryRefreshRecord in
            if !force, ResourceInventory.isRateLimited(connectionID, in: fresh, at: started) {
                let next = ResourceInventory.nextRefreshAllowed(for: connectionID, in: fresh) ?? started
                throw VaultageError.policyDenied("\(connection.provider.title) resources were refreshed less than \(Int(ResourceInventory.minimumRefreshInterval)) seconds ago. Try again in \(max(1, Int(next.timeIntervalSince(started).rounded(.up)))) seconds, or refresh again deliberately.")
            }
            let record = InventoryRefreshRecord(connectionID: connectionID, startedAt: started)
            fresh.inventoryRefreshes.removeAll { $0.connectionID == connectionID }
            fresh.inventoryRefreshes.append(record)
            return record
        }

        let digest = CanonicalDigest.hex(["vaultage.inventory.refresh.digest", connectionID.uuidString, connection.provider.rawValue, "\(steps.count)"] + steps.map(\.requestIdentity))
        let correlationID = UUID()
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: correlationID, at: .now, projectID: nil, environmentID: nil, bindingID: nil, operation: "inventory.refresh", requestDigest: digest, decision: .pending, result: "Refreshing \(steps.count) \(connection.provider.title) read(s) for the resources inventory."))

        var outcomes: [InventoryOperationOutcome] = []
        var coverageNotices: Set<String> = []
        var fresh: [ResourceRecord] = []
        var refreshedKinds: Set<ResourceKind> = []
        for step in steps {
            let request = ActionRequest(projectID: step.projectID, environmentID: step.environmentID, bindingID: step.bindingID, operation: step.operation)
            do {
                var firstPageOnly: Bool?
                let produced: (records: [ResourceRecord], reportedCount: Int?)
                if let scope = step.scope {
                    let result = try await executeResourceOperation(request)
                    produced = InventoryReadProjection.records(fromResourceRead: step.operation, result: result, scope: scope, connectionID: connectionID, at: now())
                } else {
                    let result = try await execute(request)
                    produced = InventoryReadProjection.records(fromTableRead: step.operation, fields: result.fields, connectionID: connectionID, at: now())
                    if let notice = InventoryReadProjection.coverageNotice(fields: result.fields) {
                        coverageNotices.insert(notice)
                        firstPageOnly = true
                    }
                }
                fresh.append(contentsOf: produced.records)
                refreshedKinds.insert(step.kind)
                outcomes.append(InventoryOperationOutcome(operation: step.operation.rawValue, bindingID: step.bindingID, recordCount: produced.records.count, reportedCount: produced.reportedCount, firstPageOnly: firstPageOnly))
            } catch {
                // Isolation. The failure is recorded against this one read, the
                // kind it would have refreshed is not in `refreshedKinds`, and
                // the rows it produced last time are therefore kept.
                outcomes.append(InventoryOperationOutcome(operation: step.operation.rawValue, bindingID: step.bindingID, recordCount: 0, failure: Redactor.publicError(error)))
            }
        }

        let finished = now()
        let completed = InventoryRefreshRecord(id: claim.id, connectionID: connectionID, startedAt: claim.startedAt, finishedAt: finished, operations: outcomes)
        let discovered = fresh
        let kinds = refreshedKinds
        let updated = try await metadata.updateResult { state -> VaultageMetadata in
            ResourceInventory.merge(discovered, connectionID: connectionID, refreshedKinds: kinds, into: &state)
            state.inventoryRefreshes.removeAll { $0.connectionID == connectionID }
            state.inventoryRefreshes.append(completed)
            return state
        }
        let held = updated.resources.filter { $0.connectionID == connectionID }.count
        let failures = outcomes.filter { $0.failure != nil }
        var summary: String
        if failures.isEmpty {
            summary = "Refreshed \(connection.provider.title): \(held) resource(s) from \(outcomes.count) read(s)."
        } else if failures.count == outcomes.count {
            summary = "\(connection.provider.title) refresh failed: all \(outcomes.count) read(s) failed. The \(held) resource(s) already cached were kept."
        } else {
            summary = "Refreshed \(connection.provider.title): \(held) resource(s) from \(outcomes.count - failures.count) of \(outcomes.count) read(s); \(failures.count) failed and their earlier rows were kept."
        }
        if !coverageNotices.isEmpty {
            summary += " " + coverageNotices.sorted().joined(separator: " ")
        }
        let decision: AuditDecision = failures.count == outcomes.count ? .failed : .executed
        try? await receipts.append(DurableReceipt(eventID: UUID(), correlationID: correlationID, at: .now, projectID: nil, environmentID: nil, bindingID: nil, operation: "inventory.refresh", requestDigest: digest, decision: decision, result: Redactor.safeError(summary)))
        try? await audit.append(AuditEvent(connectionID: connectionID, operation: "inventory.refresh", decision: decision, result: summary))
        return InventoryRefreshReport(connectionID: connectionID, provider: connection.provider.rawValue, connectionLabel: connection.label, startedAt: started, finishedAt: finished, operations: outcomes, recordCount: held, summary: summary)
    }

    /// `inventory.search(query, filters: project, provider, kind)`.
    ///
    /// It reads the cache and nothing else: no provider is contacted, no
    /// credential is read, and no Keychain prompt is raised. What it *does* do
    /// is disclose local metadata to whoever asked, which is the same thing
    /// `vaultage_status(include_bindings: true)` does — so it takes the same
    /// approval, every call, and the sheet names the filters and the exact
    /// number of rows that would be disclosed.
    ///
    /// There is deliberately **no** "answer without a sheet when nothing
    /// matches" shortcut. It would be friendlier, and it would also be an
    /// oracle: an agent could learn whether a resource exists by watching
    /// whether a sheet appeared.
    public func searchInventory(_ query: InventoryQuery) async throws -> InventoryPage {
        let validated = try query.validated()
        let state = try await metadata.load()
        let page = ResourceInventory.search(validated, in: state, at: now())
        let providers = Set(page.rows.map(\.providerTitle)).sorted().joined(separator: ", ")
        let details = ApprovalDetails(
            project: "Local metadata",
            environment: "No environment",
            provider: providers.isEmpty ? "Vaultage" : providers,
            connection: "No credential",
            operation: "inventory.search",
            reason: "An MCP client asked to list cached provider resources — \(validated.description). \(page.totalMatching) resource(s) match and \(page.rows.count) would be returned as names, provider identifiers and documented attributes. No credential value is cached, and none is returned. No provider is contacted by this request.",
            client: currentClient(state)
        )
        guard await approve(details) else {
            try? await audit.append(AuditEvent(operation: "inventory.search", decision: .denied, result: "The owner declined disclosing the resources inventory."))
            throw VaultageError.approvalDenied
        }
        try? await audit.append(AuditEvent(operation: "inventory.search", decision: .executed, result: "Disclosed \(page.rows.count) of \(page.totalMatching) cached resource row(s) — \(validated.description)."))
        return page
    }

    /// `inventory.bind(resourceID, environmentID)`.
    ///
    /// It creates no new model. An inventory row becomes a **bound resource
    /// scope** on a binding that already exists — BL-091's `Binding.resourceScope`
    /// — and the binding is widened to that scope's read operations, or to
    /// whatever the human ticked. The approval, the well-formedness checks, the
    /// provider match, the scope-kind match and the re-resolve after the sheet
    /// are all `bindProviderResource`'s, unchanged: this function chooses the
    /// binding and reports the difference, and does not decide anything.
    ///
    /// Desktop-only, for the same reason `bindProviderResource` is: an agent
    /// that could bind its own scope would be choosing which zone its next
    /// request acts on.
    @discardableResult
    public func bindInventoryResource(resourceID: UUID, environmentID: UUID, operations: Set<Operation>? = nil) async throws -> InventoryBindOutcome {
        let state = try await metadata.load()
        guard let record = state.resources.first(where: { $0.id == resourceID }) else {
            throw VaultageError.invalidInput("That resource is not in the inventory. Refresh the provider's resources and try again.")
        }
        guard let scope = ResourceInventory.scope(for: record) else {
            throw VaultageError.invalidInput("A \(record.kind.label.lowercased()) is not something a binding can be scoped to. Bind the \(record.parent?.kind.label.lowercased() ?? "container") it lives in, and act on it through that binding.")
        }
        guard let environment = state.environments.first(where: { $0.id == environmentID }),
              let project = state.projects.first(where: { $0.id == environment.projectID }) else {
            throw VaultageError.invalidInput("That environment no longer exists.")
        }
        // Which binding. Preferring one that already carries this exact scope
        // makes re-binding idempotent; preferring an unscoped one next means a
        // first bind never silently re-points a binding that was already aimed
        // somewhere else. Ties break on the id so the choice is reproducible.
        let candidates = state.bindings
            .filter { $0.environmentID == environmentID && $0.connectionID == record.connectionID }
            .sorted { $0.id.uuidString < $1.id.uuidString }
        guard !candidates.isEmpty else {
            throw VaultageError.invalidInput("\(project.name) / \(environment.name) has no binding for the \(record.provider.title) connection this resource came from. Bind that connection to this environment first.")
        }
        let binding = candidates.first { $0.resourceScope == scope }
            ?? candidates.first { $0.resourceScope == nil }
            ?? candidates[0]
        let previousScope = binding.resourceScope
        let requested = operations ?? ResourceInventory.defaultOperations(for: scope)
        guard !requested.isEmpty else {
            throw VaultageError.invalidInput("This build has no operation that runs against a \(scope.kind.rawValue) scope.")
        }
        let alreadyAllowed = requested.intersection(binding.allowedOperations)
        let added = requested.subtracting(binding.allowedOperations)

        // One sheet, and it is BL-091's: it names the scope, the operations and
        // whether any of them changes provider state.
        let updated = try await bindProviderResource(bindingID: binding.id, scope: scope, operations: requested)

        let replaced = (previousScope != nil && previousScope != scope) ? previousScope?.sheetTarget : nil
        var summary = "Bound \(scope.sheetTarget) to \(project.name) / \(environment.name)."
        summary += added.isEmpty
            ? " The binding already allowed \(alreadyAllowed.map(\.rawValue).sorted().joined(separator: ", "))."
            : " It now also allows \(added.map(\.rawValue).sorted().joined(separator: ", "))."
        if let replaced { summary += " It was previously scoped to \(replaced); that scope was replaced." }
        try? await audit.append(AuditEvent(projectID: project.id, environmentID: environment.id, connectionID: record.connectionID, operation: "inventory.bind", decision: .executed, result: summary))
        return InventoryBindOutcome(
            resourceID: resourceID,
            bindingID: updated.id,
            projectID: project.id,
            environmentID: environment.id,
            connectionID: record.connectionID,
            scopeKind: scope.kind.rawValue,
            scopeLabel: scope.label,
            replacedScope: replaced,
            addedOperations: added.map(\.rawValue).sorted(),
            alreadyAllowedOperations: alreadyAllowed.map(\.rawValue).sorted(),
            summary: summary
        )
    }

    // MARK: - BL-094 cloud environment credential delivery (desktop only)

    /// Delivers one vault value into one provider secret store, so the deployed
    /// environment holds its own copy and keeps running with this Mac off
    /// (D36).
    ///
    /// The shape is BL-051's, generalised, and it is deliberately the same
    /// shape as the read path and the resource path because the invariants are
    /// the same: resolve, digest, approve, **re-resolve and re-compare the
    /// digest**, write a durable pending receipt before any protected read,
    /// read, re-prove immediately before egress, dispatch, complete the receipt
    /// exactly once. The four things a delivery adds are the preflight, the
    /// post-write verification, the ledger row, and the fact that both the
    /// preflight and the verification list **names only**.
    ///
    /// **Preflight and verify are part of the delivery, not separate
    /// operations.** Engineering contracts §7 already says so for Cloudflare —
    /// "exact bound account/script secret-list GET before the single approved
    /// PUT" — and the reason generalises: they run against the same bound
    /// scope, with the same credential the write uses, and they can reach
    /// nothing the write could not already reach. So they raise no second sheet
    /// and need no second permission. What they do need, and have, is the
    /// value-stripping adapter: Vercel returns values on that route, and the
    /// projection removes every value-bearing field inside the transport before
    /// anything reads it (BL-091 §5).
    ///
    /// **The preflight decides create versus update**, which is why the sheet
    /// says "creating it or replacing what is there" rather than naming a verb.
    /// The human is answering "should this secret live there?", and the answer
    /// does not change with the provider's choice of HTTP method.
    ///
    /// Desktop-only: absent from `BrokerFacade`, like `bindProviderResource`,
    /// `refreshInventory` and BL-073's resolvers.
    @discardableResult
    public func deliverCredential(_ request: CredentialDeliveryRequest) async throws -> CredentialDeliveryOutcome {
        try await deliver(request, door: .owner)
    }

    /// D71. The agent's door: the same delivery, with the agent's source rule —
    /// only a source the owner allowed for the binding — and the requester
    /// named on the sheet, the receipt and the ledger's effect line. Reached
    /// from `vaultage_deliver` and from nothing else.
    @discardableResult
    public func deliverForAgent(_ request: CredentialDeliveryRequest) async throws -> CredentialDeliveryOutcome {
        try await deliver(request, door: .agent)
    }

    /// The one delivery, with its door named by the caller. The two methods
    /// above are how the app and the MCP server name it in process; the XPC
    /// service names it by selector (`BrokerDeliverySelector`), through one
    /// body, so the door cannot drift between two copies.
    public func deliver(_ request: CredentialDeliveryRequest, door: DeliveryDoor) async throws -> CredentialDeliveryOutcome {
        guard let resourceExecutor else {
            throw VaultageError.unsupported("Credential delivery is unavailable in this build.")
        }
        let state = try await metadata.load()
        let resolution: DeliveryResolution
        do { resolution = try deliveryResolution(state, request: request, door: door) }
        catch {
            try? await appendDelivery(request, connectionID: nil, .blocked, "No permitted delivery destination for this binding.")
            throw error
        }
        try await requireActiveManagedConnection(resolution.connection.id)
        try requireCurrentVerification(connection: resolution.connection, item: resolution.destinationItem, operation: resolution.writeOperationIfNew)

        let digest = deliveryDigest(request: request, resolution: resolution)
        let details = deliveryApprovalDetails(request: request, resolution: resolution, digest: digest, state: state)
        guard await approve(details) else {
            try? await appendDelivery(request, connectionID: resolution.connection.id, .denied, "Human denied delivery to \(resolution.destination.sheetLine).")
            throw VaultageError.approvalDenied
        }
        let approvedAt = now()

        // Nothing the sheet named may have moved while it was up.
        let refreshed: DeliveryResolution
        do {
            let refreshedState = try await metadata.load()
            refreshed = try deliveryResolution(refreshedState, request: request, door: door)
            guard deliveryDigest(request: request, resolution: refreshed) == digest else {
                throw VaultageError.policyDenied("The approved delivery changed before execution.")
            }
        } catch {
            try? await appendDelivery(request, connectionID: nil, .blocked, "The delivery binding or destination changed while approval was pending.")
            throw VaultageError.policyDenied("The approved delivery changed before execution.")
        }
        try await requireActiveManagedConnection(refreshed.connection.id)
        try requireCurrentVerification(connection: refreshed.connection, item: refreshed.destinationItem, operation: refreshed.writeOperationIfNew)

        // The durable, value-free pending receipt is the egress precondition: if
        // local persistence fails, nothing is read and nothing is sent.
        let invocationID = UUID()
        try await persistDeliveryReceipt(request, resolution: refreshed, digest: digest, correlationID: invocationID, .pending, "Approved delivery to \(refreshed.destination.sheetLine) pending.", providerResourceID: nil)
        try? await appendDelivery(request, connectionID: refreshed.connection.id, .pending, "Approved delivery to \(refreshed.destination.sheetLine) pending; request \(digest.prefix(16)).")

        let destinationCredential: VaultSecret
        let sourceValue: VaultSecret
        do {
            destinationCredential = try vault.read(account: refreshed.destinationItem.keychainAccount, prompt: "Authorize delivery to \(refreshed.destination.sheetLine)")
            let stored = try vault.read(account: refreshed.sourceItem.keychainAccount, prompt: "Unlock source \(refreshed.sourceItem.label) for \(refreshed.project.name) / \(refreshed.environment.name)")
            // **CC-H6.** The stored value for a composite item is the `VLTC1`
            // envelope carrying every field, and it is a valid UTF-8 string for
            // an ASCII credential — so nothing downstream would have refused
            // it. This is the one place that knows whether the record is an
            // envelope, it runs before the preflight and therefore before any
            // egress, and what it returns is the only thing the rest of this
            // method can send.
            sourceValue = try CredentialDeliverySource.delivered(stored, field: request.sourceField, sourceLabel: refreshed.sourceItem.label)
            guard sourceValue.byteCount > 0, sourceValue.byteCount <= refreshed.store.maximumValueBytes else {
                throw VaultageError.invalidInput("The selected value is empty or exceeds the provider's \(refreshed.store.maximumValueBytes / 1024) KB limit for this store.")
            }
        } catch {
            try await completeDeliveryKnown(request, resolution: refreshed, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: Redactor.publicError(error))
            throw error
        }

        // A Keychain sheet can stay open while another process changes the
        // graph. Re-prove everything immediately before egress, under the same
        // 60-second approval lifetime every other write path imposes.
        do {
            guard now().timeIntervalSince(approvedAt) <= 60 else { throw VaultageError.approvalDenied }
            let finalState = try await metadata.load()
            let final = try deliveryResolution(finalState, request: request, door: door)
            guard deliveryDigest(request: request, resolution: final) == digest else {
                throw VaultageError.policyDenied("The approved delivery changed before egress.")
            }
            try await requireActiveManagedConnection(final.connection.id)
            try requireCurrentVerification(connection: final.connection, item: final.destinationItem, operation: final.writeOperationIfNew)
        } catch {
            try await completeDeliveryKnown(request, resolution: refreshed, digest: digest, correlationID: invocationID, decision: terminalDecision(for: error), result: "Delivery authorization changed or expired after OS authentication.")
            throw error
        }

        // 1. Preflight. Names only, through the value-stripping adapter. A
        //    failure here is a failure *before* the write, so nothing has been
        //    delivered and the receipt says so.
        let preflight: DeliveryStoreListing
        let alreadyThere: Bool
        do {
            preflight = try await listDestinationNames(resolution: refreshed, credential: destinationCredential, executor: resourceExecutor)
            alreadyThere = try await presence(of: refreshed.destination, in: preflight, resolution: refreshed, credential: destinationCredential, executor: resourceExecutor) == .present
        } catch {
            try await completeDeliveryKnown(request, resolution: refreshed, digest: digest, correlationID: invocationID, decision: .failed, result: "Preflight of \(refreshed.destination.sheetLine) failed; nothing was written. \(Redactor.publicError(error))")
            throw error
        }

        // 2. Write. Which operation runs is the preflight's answer, never the
        //    caller's.
        let existingID = preflight.identifier(for: refreshed.destination)
        let operation = existingID == nil ? refreshed.store.deliveryOperations[0] : refreshed.writeOperationForExisting
        let providerResourceID: String?
        do {
            providerResourceID = try await dispatchDelivery(
                resolution: refreshed,
                operation: operation,
                existingID: existingID,
                destinationCredential: destinationCredential,
                sourceValue: sourceValue,
                executor: resourceExecutor
            )
        } catch let error as VaultageError where error == .resultUnknown {
            // The provider may have committed. The ledger is deliberately not
            // written: a row claiming a delivery that may not have happened is
            // worse than no row, and the next verify-deployed will find the
            // truth either way.
            try? await persistDeliveryReceipt(request, resolution: refreshed, digest: digest, correlationID: invocationID, .resultUnknown, "Delivery to \(refreshed.destination.sheetLine) result unknown; no automatic retry was performed.", providerResourceID: nil)
            try? await appendDelivery(request, connectionID: refreshed.connection.id, .resultUnknown, "Delivery to \(refreshed.destination.sheetLine) result unknown; no automatic retry was performed.")
            throw error
        } catch {
            try await completeDeliveryKnown(request, resolution: refreshed, digest: digest, correlationID: invocationID, decision: .failed, result: Redactor.publicError(error))
            throw error
        }
        let deliveredAt = now()

        // 3. Verify, by listing names again. A verification failure never
        //    un-does the delivery and never fails the call: the write was
        //    accepted, and "we could not confirm it" is a state the ledger
        //    carries rather than an error the human has to interpret.
        var verified = false
        var entryCountAfter = preflight.count
        var verifyNote = ""
        do {
            let confirmation = try await listDestinationNames(resolution: refreshed, credential: destinationCredential, executor: resourceExecutor)
            entryCountAfter = confirmation.count
            switch try await presence(of: refreshed.destination, in: confirmation, resolution: refreshed, credential: destinationCredential, executor: resourceExecutor) {
            case .present:
                verified = true
            case .absent:
                verifyNote = " The destination's name list did not report it afterwards."
            case .truncated:
                verifyNote = " The destination holds more entries than one page reports, so this delivery could not be confirmed by name."
            }
        } catch {
            verifyNote = " Verification could not be run: \(Redactor.publicError(error))"
        }

        // 4. The ledger row, then the terminal receipt.
        let status: DeployedCredentialStatus = verified ? .delivered : .verifyFailed
        let rowID = DeployedCredentialLedger.rowID(environmentID: refreshed.environment.id, destination: refreshed.destination)
        let entry = DeployedCredential(
            id: rowID,
            projectID: refreshed.project.id,
            environmentID: refreshed.environment.id,
            bindingID: refreshed.binding.id,
            connectionID: refreshed.connection.id,
            sourceVaultItemID: refreshed.sourceItem.id,
            // CC-H6. Which field went here, so "which half is production
            // running?" is answerable and a rotation replaces like with like.
            sourceField: request.sourceField,
            fingerprint: DeployedCredentialLedger.fingerprint(of: refreshed.sourceItem),
            provider: refreshed.store.provider,
            principal: refreshed.connection.verification?.principalID,
            destination: refreshed.destination,
            operation: operation.rawValue,
            providerResourceID: providerResourceID,
            deliveredAt: deliveredAt,
            lastVerifiedAt: verified ? deliveredAt : nil,
            expiresAt: expiryOfSource(refreshed.sourceItem, in: state),
            status: status,
            rotationID: request.rotationID,
            requestedBy: refreshed.door,
            requestingClientID: refreshed.requesterClientID
        )
        _ = try? await metadata.update { state in
            DeployedCredentialLedger.record(entry, in: &state)
        }

        // BL-128 slice 3c. "Replaced" whenever the preflight saw the entry —
        // by its provider id where the store returns one, by its name where
        // it does not. Before this a name-keyed store (Cloudflare, GitHub)
        // always read "Delivered", even over a value that was there.
        let replacedExisting = existingID != nil || alreadyThere
        let verb = replacedExisting ? "Replaced the value of" : "Delivered"
        let asked = refreshed.requester.map { " Asked by an agent (\($0)) and approved on this Mac." } ?? ""
        let effect = "\(verb) \(refreshed.destination.sheetLine) from the vault item \"\(refreshed.sourceItem.label)\".\(asked) \(refreshed.store.deploymentSentence)\(verified ? " Verified by listing the destination's names." : verifyNote)"
        let outcome = CredentialDeliveryOutcome(
            ledgerRowID: rowID,
            destination: refreshed.destination,
            operation: operation.rawValue,
            replacedExistingEntry: replacedExisting,
            providerResourceID: providerResourceID,
            verified: verified,
            status: status,
            deliveredAt: deliveredAt,
            entryCountAfter: entryCountAfter,
            effect: effect
        )
        do {
            try await persistDeliveryReceipt(request, resolution: refreshed, digest: digest, correlationID: invocationID, .executed, effect, providerResourceID: providerResourceID)
        } catch {
            try? await persistDeliveryReceipt(request, resolution: refreshed, digest: digest, correlationID: invocationID, .resultUnknown, "The provider accepted a delivery but the final receipt could not be persisted; do not retry automatically.", providerResourceID: providerResourceID)
            try? await appendDelivery(request, connectionID: refreshed.connection.id, .resultUnknown, "Delivery may have completed; final receipt persistence failed.")
            throw VaultageError.resultUnknown
        }
        try? await appendDelivery(request, connectionID: refreshed.connection.id, .executed, effect)
        return outcome
    }

    /// Checks what the ledger says is deployed in one environment against what
    /// the providers report, by **listing names**.
    ///
    /// One native approval per (binding, store), naming the environment and how
    /// many entries the check covers. It raises a sheet rather than running
    /// silently for the same reason `searchInventory` does: it discloses which
    /// destinations Vaultage believes hold credentials, and it makes this Mac
    /// talk to a provider. It belongs to the delivery class, so no grant can
    /// ever cover it.
    ///
    /// It writes nothing at the provider and reads no vault value. The only
    /// thing it can change is a ledger row's `lastVerifiedAt` and its status
    /// between `delivered` and `verify-failed` — and it is advisory in both
    /// directions: a delivered credential keeps working whether or not this
    /// ever runs (D36).
    ///
    /// Desktop-only.
    @discardableResult
    public func verifyDeployedCredentials(environmentID: UUID) async throws -> DeployedVerificationReport {
        guard let resourceExecutor else {
            throw VaultageError.unsupported("Verifying deployed credentials is unavailable in this build.")
        }
        let state = try await metadata.load()
        guard let environment = state.environments.first(where: { $0.id == environmentID }),
              let project = state.projects.first(where: { $0.id == environment.projectID })
        else { throw VaultageError.invalidInput("That environment no longer exists.") }

        let entries = DeployedCredentialLedger.entries(in: state, environmentID: environmentID)
        guard !entries.isEmpty else {
            return DeployedVerificationReport(environmentID: environmentID, checkedAt: now(), rows: [], health: DeployedCredentialLedger.health(of: [], at: now()), message: "Nothing has been delivered to \(environment.name) yet, so there is nothing to verify.")
        }

        // One check per destination container, not per row: five variables on
        // one Vercel project are one name list, one approval and one request.
        var groups: [UUID: [DeployedCredential]] = [:]
        for entry in entries where entry.status.isLive {
            groups[entry.bindingID, default: []].append(entry)
        }

        var rows: [DeployedVerificationReport.Row] = []
        // Rows that are superseded or revoked are reported without being
        // checked: their status is a local fact about the credential, not a
        // question about the destination.
        for entry in entries where !entry.status.isLive {
            rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "This entry is \(entry.status.label.lowercased()) and was not checked."))
        }

        let checkedAt = now()
        for (bindingID, group) in groups.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            guard let first = group.first else { continue }
            // Re-resolve from scratch. A ledger row is not a capability: the
            // binding, the scope and the connection's verification are all
            // proved again, and a row whose binding has since been removed is
            // reported as not-checked rather than silently skipped.
            let probe = CredentialDeliveryRequest(projectID: project.id, environmentID: environmentID, bindingID: bindingID, sourceVaultItemID: first.sourceVaultItemID, sourceField: first.sourceField, destinationName: first.destination.name, target: first.destination.target)
            let resolution: DeliveryResolution
            do {
                resolution = try deliveryResolution(state, request: probe, door: .owner)
                try await requireActiveManagedConnection(resolution.connection.id)
                try requireCurrentVerification(connection: resolution.connection, item: resolution.destinationItem, operation: resolution.store.nameListOperation)
            } catch {
                for entry in group {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "The binding that delivered this entry can no longer be used to check it: \(Redactor.publicError(error))"))
                }
                continue
            }

            let disclosure = DeployedVerificationDisclosure(
                store: resolution.store,
                scopeLabel: resolution.destination.containerLine,
                project: project.name,
                environment: environment.name,
                entryCount: group.count,
                requestDigest: CanonicalDigest.hex(["vaultage.delivery.verify.digest", project.id.uuidString, environmentID.uuidString, bindingID.uuidString, resolution.connection.id.uuidString, resolution.store.rawValue] + resolution.scope.canonicalFields + group.map(\.destination.name).sorted())
            )
            let details = ApprovalDetails(
                project: project.name,
                environment: environment.name,
                provider: resolution.connection.provider.title,
                connection: resolution.connection.label,
                operation: resolution.store.nameListOperation.rawValue,
                reason: "\(disclosure.actionLine) \(DeployedVerificationDisclosure.safetySentence) \(providerEvidenceDescription(resolution.connection))",
                client: currentClient(state),
                deployedVerification: disclosure
            )
            guard await approve(details) else {
                for entry in group {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "The check was not approved."))
                }
                continue
            }

            let credential: VaultSecret
            do { credential = try vault.read(account: resolution.destinationItem.keychainAccount, prompt: "Check what is deployed on \(resolution.destination.scopeLabel)") }
            catch {
                for entry in group {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: Redactor.publicError(error)))
                }
                continue
            }

            let listing: DeliveryStoreListing
            do { listing = try await listDestinationNames(resolution: resolution, credential: credential, executor: resourceExecutor) }
            catch {
                for entry in group {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "The provider could not be asked which names exist: \(Redactor.publicError(error))"))
                }
                continue
            }

            for entry in group {
                // BL-128 slice 3c, second security pass. A row delivered to one
                // container is never "checked" by listing another: the binding
                // may have been re-pointed since, and a name that also exists
                // in the new container would read as present.
                guard entry.destination.store == resolution.store, entry.destination.scopeID == resolution.destination.scopeID else {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "This entry was delivered to \(entry.destination.containerLine), and the binding now points at \(resolution.destination.containerLine), so it cannot be checked through it."))
                    continue
                }
                let found: DeliveryStoreListing.Presence
                do { found = try await presence(of: entry.destination, in: listing, resolution: resolution, credential: credential, executor: resourceExecutor) }
                catch {
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "The provider could not be asked whether \(entry.destination.name) exists: \(Redactor.publicError(error))"))
                    continue
                }
                switch found {
                case .present:
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .present, detail: "\(entry.destination.sheetLine) is there."))
                    _ = try? await metadata.update { state in
                        DeployedCredentialLedger.applyVerification(rowID: entry.id, present: true, at: checkedAt, in: &state)
                    }
                case .absent:
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .absent, detail: "\(entry.destination.sheetLine) was not in the names the provider reported. Somebody may have removed it at the provider."))
                    _ = try? await metadata.update { state in
                        DeployedCredentialLedger.applyVerification(rowID: entry.id, present: false, at: checkedAt, in: &state)
                    }
                case .truncated:
                    // Not `absent`. "We did not see it in one page" is not "it
                    // is not there", and recording it as a failure would mark a
                    // working deployment broken.
                    rows.append(DeployedVerificationReport.Row(ledgerRowID: entry.id, destination: entry.destination, outcome: .notChecked, detail: "\(resolution.destination.scopeLabel) holds \(listing.count) entries, more than one page reports, so this one could not be confirmed by name."))
                }
            }
            try? await audit.append(AuditEvent(projectID: project.id, environmentID: environmentID, connectionID: resolution.connection.id, operation: resolution.store.nameListOperation.rawValue, decision: .executed, result: "Checked \(group.count) deployed \(group.count == 1 ? "entry" : "entries") on \(resolution.destination.scopeLabel) by listing names."))
        }

        let after = try await metadata.load()
        let health = DeployedCredentialLedger.health(in: after, environmentID: environmentID, at: checkedAt)
        let present = rows.filter { $0.outcome == .present }.count
        let absent = rows.filter { $0.outcome == .absent }.count
        let notChecked = rows.filter { $0.outcome == .notChecked }.count
        var message = "\(present) of \(rows.count) recorded \(rows.count == 1 ? "entry is" : "entries are") there."
        if absent > 0 { message += " \(absent) \(absent == 1 ? "was" : "were") not reported by the provider." }
        if notChecked > 0 { message += " \(notChecked) could not be checked." }
        message += " This is advisory: a delivered credential keeps working whether or not this check runs."
        return DeployedVerificationReport(environmentID: environmentID, checkedAt: checkedAt, rows: rows.sorted { $0.destination.name < $1.destination.name }, health: health, message: message)
    }

    /// Everything a delivery names, resolved, or a refusal.
    ///
    /// The load-bearing part is the same as BL-091's: the container comes from
    /// the **binding**, never from the caller. Cloudflare's comes from BL-051's
    /// `cloudflareWorkerDestination`, Vercel's from BL-091's `resourceScope`,
    /// and neither can be supplied or changed by whoever asked for the
    /// delivery.
    private func deliveryResolution(_ state: VaultageMetadata, request: CredentialDeliveryRequest, door: DeliveryDoor) throws -> DeliveryResolution {
        guard let binding = state.bindings.first(where: { $0.id == request.bindingID }),
              binding.projectID == request.projectID,
              binding.environmentID == request.environmentID,
              let project = state.projects.first(where: { $0.id == request.projectID }),
              let environment = state.environments.first(where: { $0.id == request.environmentID }),
              environment.projectID == project.id,
              let connection = state.connections.first(where: { $0.id == binding.connectionID }),
              let destinationItem = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
              destinationItem.provider == connection.provider,
              MetadataRemoval.deletionReservation(forVaultItem: destinationItem.id, in: state) == nil
        else { throw VaultageError.policyDenied("This delivery is not permitted by the selected binding.") }

        // Which store this binding can deliver into, and its container. Both
        // are read off records the human created; there is no request field for
        // either.
        let store: SecretStore
        let scope: ProviderResourceScope
        var cloudflareDestination: CloudflareWorkerDestination?
        if let workerDestination = binding.cloudflareWorkerDestination, connection.provider == .cloudflare {
            store = .cloudflareWorkerSecret
            cloudflareDestination = workerDestination
            scope = ProviderResourceScope(kind: .cloudflareWorkerScript, accountID: workerDestination.accountID, scriptName: workerDestination.scriptName, label: workerDestination.scriptName)
        } else if let bound = binding.resourceScope, bound.isWellFormed, let candidate = SecretStore.allCases.first(where: { $0.scopeKind == bound.kind }) {
            store = candidate
            scope = bound
        } else {
            throw VaultageError.policyDenied("This binding is not scoped to a provider secret store, so nothing can be delivered to it.")
        }
        guard store.provider == connection.provider else {
            throw VaultageError.policyDenied("This binding's destination does not belong to its connection's provider.")
        }
        // The app validates the identifier's canonical shape when the binding
        // is made; a binding from before it did is refused here in words that
        // say what to do, not as a provider mismatch.
        guard scope.isWellFormed else {
            throw VaultageError.policyDenied("This binding's destination identifier is not in the provider's canonical shape (a Cloudflare account id is 32 lowercase hexadecimal characters), so nothing can be delivered to it. Create the binding again with the exact identifier.")
        }
        // **Every** delivery this store can perform must be allowed by the
        // binding, not just the one the preflight happens to choose. A binding
        // that permits creating a variable but not replacing one would deliver
        // the first time and fail on every rotation, which is a worse failure
        // than refusing now.
        guard store.deliveryOperations.allSatisfy(binding.allowedOperations.contains) else {
            throw VaultageError.policyDenied("This binding does not allow \(store.deliveryOperations.map(\.rawValue).joined(separator: " and ")), which a delivery needs in order to create the entry or replace what is there.")
        }
        guard store.usesTargets == (request.target != nil) else {
            throw VaultageError.invalidInput(store.usesTargets ? "A \(store.inlineLabel) delivery names one deploy target." : "A \(store.inlineLabel) has no deploy target.")
        }
        guard let destination = DeliveryDestination.from(scope: scope, name: request.destinationName, target: request.target), destination.isWellFormed else {
            throw VaultageError.invalidInput("The destination name is not a shape this store accepts.")
        }
        // Source authorization is as important as destination authorization
        // (engineering contracts §4): the same record BL-051 and BL-091 require.
        //
        // D71: the source rule belongs to the door. In the app, the person
        // picking the source and approving a native sheet that names it *is*
        // the authorization (a separate record written before the sheet used
        // to outlive a denied delivery, and a rotation's new item never had
        // one). An agent may name only a source the owner allowed for this
        // binding — the `RuntimeSourceAuthorization` the app records. Either
        // way the item must exist, hold a value, not be the destination's own
        // token and not be on its way out.
        guard let sourceItem = state.vaultItems.first(where: { $0.id == request.sourceVaultItemID }),
              sourceItem.id != destinationItem.id,
              sourceItem.hasProtectedValue,
              MetadataRemoval.deletionReservation(forVaultItem: sourceItem.id, in: state) == nil,
              door == .owner || state.runtimeSourceAuthorizations.contains(where: { $0.sourceVaultItemID == sourceItem.id && $0.bindingID == binding.id && $0.projectID == project.id && $0.environmentID == environment.id })
        else { throw VaultageError.policyDenied(door == .agent ? "The owner has not allowed that vault item as a source for this binding. Ask them to allow it in Vaultage (the binding's Sources), then try again." : "The selected source item is not authorized for this binding, project and environment.") }
        // CC-H6, rule 3. A shape refusal, so a request that names the whole of
        // a credential as though it were one of its halves never reaches a
        // sheet, a digest or a Keychain record.
        try CredentialDeliverySource.validate(request.sourceField)

        // Who asked, for the agent's door: the identity this connection
        // presented, re-resolved now, so a revoked client is named as such.
        let client = door == .agent ? currentClient(state) : nil
        return DeliveryResolution(project: project, environment: environment, binding: binding, connection: connection, destinationItem: destinationItem, sourceItem: sourceItem, store: store, scope: scope, destination: destination, cloudflareDestination: cloudflareDestination, door: door, requester: client?.approvalLine, requesterClientID: client?.id)
    }

    /// RP-07, as every other digest here: one canonical, injective field-list
    /// encoding whose members state their own shape.
    private func deliveryDigest(request: CredentialDeliveryRequest, resolution: DeliveryResolution) -> String {
        let evidence = resolution.connection.verification
        var fields: [String] = [
            "vaultage.delivery.request.digest",
            request.projectID.uuidString,
            request.environmentID.uuidString,
            request.bindingID.uuidString,
            resolution.connection.id.uuidString,
            resolution.destinationItem.id.uuidString,
            resolution.destinationItem.keychainAccount,
            resolution.destinationItem.credentialVersion?.uuidString ?? "none",
            evidence?.providerContractRevision ?? "none",
            "\(evidence?.verifiedAt.timeIntervalSince1970 ?? 0)",
            evidence?.principalID ?? "unknown",
            "source",
            resolution.sourceItem.id.uuidString,
            resolution.sourceItem.keychainAccount,
            resolution.sourceItem.credentialVersion?.uuidString ?? "none",
            // CC-H6. The approval is for one named field, so the field is a
            // term of it: changing which half is delivered invalidates the
            // approval exactly as changing the destination does.
            "sourceField",
            request.sourceField?.wireName ?? "none",
            "production",
            "\(resolution.environment.isProduction)",
            "rotation",
            request.rotationID?.uuidString ?? "none",
            "door",
            resolution.door.rawValue,
            // Who asked is a term too: a client revoked or re-identified while
            // the sheet is up is a different requester from the one the sheet
            // named, and the owner's approval was of that one.
            "requester",
            resolution.requesterClientID?.uuidString ?? (resolution.door == .agent ? "unenrolled" : "owner")
        ]
        fields.append(contentsOf: resolution.scope.canonicalFields)
        fields.append(contentsOf: resolution.destination.canonicalFields)
        return CanonicalDigest.hex(fields)
    }

    /// D34's copy rule, plus D36's promise. Every string is built from resolved
    /// local records.
    private func deliveryApprovalDetails(request: CredentialDeliveryRequest, resolution: DeliveryResolution, digest: String, state: VaultageMetadata) -> ApprovalDetails {
        let destination = resolution.destination
        let rotationNote: String? = request.rotationID.flatMap { id in
            guard let rotation = state.rotations.first(where: { $0.id == id }) else { return nil }
            return "This is one step of a rotation. \(rotation.progressSummary) The old credential stays valid until every destination is delivered and verified."
        }
        // CC-H6. When the delivery names a field, the sheet says which field —
        // so the human is approving "the Auth token of Twilio, and nothing else
        // of it" rather than "the value of Twilio", which for a composite is
        // not a thing that exists.
        let fieldLabel = request.sourceField?.defaultLabel
        // Two vaults can hold two items with one label, and on the agent's
        // door the item is the agent's pick — so when there is more than one
        // vault, the sheet names the one the source is in.
        let vaultName = state.vaults.count > 1 ? state.vaults.first { $0.id == resolution.sourceItem.vaultID }?.name : nil
        let sourceLabel = vaultName.map { "\(resolution.sourceItem.label) (in the vault \($0))" } ?? resolution.sourceItem.label
        let actionLine = fieldLabel.map { label in
            "Write the \(label) of the vault item \"\(sourceLabel)\" here — that one field of it and nothing else — creating this entry or replacing what is there. \(resolution.store.deploymentSentence)"
        } ?? "Write the value of the vault item \"\(sourceLabel)\" here, creating this entry or replacing what is there. \(resolution.store.deploymentSentence)"
        let disclosure = CredentialDeliveryDisclosure(
            destinationLine: destination.sheetLine,
            actionLine: actionLine,
            safetyLine: CredentialDeliveryDisclosure.safetySentence,
            sourceLabel: sourceLabel,
            sourceVaultItemID: resolution.sourceItem.id,
            sourceFieldLabel: fieldLabel,
            sourceFieldNote: fieldLabel == nil ? nil : CredentialDeliverySource.oneFieldPerApprovalRationale,
            destination: destination,
            project: resolution.project.name,
            environment: resolution.environment.name,
            isProductionEnvironment: resolution.environment.isProduction,
            isLiveTrafficTarget: destination.target?.isLiveTraffic == true,
            productionWarning: resolution.environment.isProduction
                ? CredentialDeliveryDisclosure.productionSentence
                : (destination.target?.isLiveTraffic == true ? CredentialDeliveryDisclosure.liveTrafficSentence : nil),
            targetNote: resolution.store.usesTargets ? DeliveryDestination.oneTargetPerApprovalRationale : nil,
            valueDisclosure: resolution.store.nameListOperation.taxonomy.providerReturnsValues ? CredentialDeliveryDisclosure.valueReturningStoreSentence : nil,
            rotationNote: rotationNote,
            requestDigest: digest,
            // The agent's door says so on the sheet itself, not only on the
            // "Client:" line every sheet carries: the owner is approving a
            // request they did not make.
            requesterNote: resolution.requester.map { "An agent asked for this delivery — \($0). Approving it here is the only authorization the agent gets; it never sees the value." }
        )
        return ApprovalDetails(
            project: resolution.project.name,
            environment: resolution.environment.name,
            provider: resolution.connection.provider.title,
            connection: resolution.connection.label,
            operation: resolution.writeOperationIfNew.rawValue,
            reason: "\(disclosure.destinationLine). \(disclosure.actionLine) \(disclosure.safetyLine) \(providerEvidenceDescription(resolution.connection))",
            client: currentClient(state),
            credentialDelivery: disclosure
        )
    }

    /// Lists the destination store's entry **names**, through the adapter that
    /// drops every value-bearing field inside the transport.
    private func listDestinationNames(resolution: DeliveryResolution, credential: VaultSecret, executor: any ProviderResourceExecuting) async throws -> DeliveryStoreListing {
        let result = try await executor.performResourceOperation(
            resolution.store.nameListOperation,
            credential: credential,
            scope: resolution.scope,
            arguments: ResourceMutationArguments(),
            sourceValue: nil
        )
        return DeliveryStoreListing(store: resolution.store, items: result.items, count: result.count ?? result.items.count)
    }

    /// The destination a binding would deliver `name` to right now, chosen the
    /// way `deliveryResolution` chooses it: a Cloudflare binding's Worker
    /// destination first, then its resource scope. Nil when it has neither.
    /// Used by a rotation step to notice a re-pointed binding before anything
    /// is read (third security pass: reading the scope alone failed a Worker
    /// binding that also carried a scope for another script).
    static func currentDeliveryDestination(of binding: Binding, in state: VaultageMetadata, name: String, target: DeliveryTarget?) -> DeliveryDestination? {
        let provider = state.connections.first(where: { $0.id == binding.connectionID })?.provider
        if let worker = binding.cloudflareWorkerDestination, provider == .cloudflare {
            return DeliveryDestination(store: .cloudflareWorkerSecret, name: name, target: nil, scopeID: worker.scriptName, scopeLabel: worker.scriptName)
        }
        return binding.resourceScope.flatMap { DeliveryDestination.from(scope: $0, name: name, target: target) }
    }

    /// Whether the destination is there: the name list's answer, and — when
    /// that list is one page that did not reach it and the store can be asked
    /// about one entry directly — the direct answer (BL-128 slice 3c: a GitHub
    /// repository may hold 100 secrets and its list returns 30). Still names
    /// only: the direct read returns an entry's name and dates, never a value.
    private func presence(of destination: DeliveryDestination, in listing: DeliveryStoreListing, resolution: DeliveryResolution, credential: VaultSecret, executor: any ProviderResourceExecuting) async throws -> DeliveryStoreListing.Presence {
        let listed = listing.presence(of: destination)
        guard listed == .truncated,
              let exists = try await executor.deliveredEntryExists(destination, credential: credential, scope: resolution.scope) else { return listed }
        return exists ? .present : .absent
    }

    /// The one write. Cloudflare keeps BL-051's bounded PUT; Vercel uses
    /// BL-091's resource path, whose body is assembled into the same
    /// self-zeroing buffer; GitHub uses that path too, and its body carries no
    /// plaintext at all — the adapter seals the value to the repository's
    /// public key first (BL-128 slice 3c, D65).
    private func dispatchDelivery(resolution: DeliveryResolution, operation: Operation, existingID: String?, destinationCredential: VaultSecret, sourceValue: VaultSecret, executor: any ProviderResourceExecuting) async throws -> String? {
        switch resolution.store {
        case .cloudflareWorkerSecret:
            guard let runtimeExecutor, let workerDestination = resolution.cloudflareDestination else {
                throw VaultageError.unsupported("Cloudflare Worker secret delivery is unavailable in this build.")
            }
            _ = try await runtimeExecutor.putCloudflareWorkerSecret(destinationToken: destinationCredential, sourceValue: sourceValue, destination: workerDestination, variableName: resolution.destination.name)
            // Cloudflare's secret route is keyed by name and returns no
            // identifier of its own. Recording the name as one would invent a
            // fact.
            return nil
        case .vercelEnvironmentVariable:
            guard let target = resolution.destination.target?.rawValue else {
                throw VaultageError.invalidInput("A Vercel environment variable delivery names one deploy target.")
            }
            var fields: [ResourceFieldKey: String] = [.target: target]
            if operation == .vercelEnvCreate {
                fields[.name] = resolution.destination.name
                // Never `plain`: writing a vault value where the dashboard
                // shows it back would contradict the custody promise (BL-091).
                fields[.variableType] = "encrypted"
            }
            let arguments = ResourceMutationArguments(
                resourceID: operation.taxonomy.namesExistingResource ? existingID : nil,
                fields: fields,
                sourceVaultItemID: resolution.sourceItem.id
            )
            try ResourceFieldRules.validate(arguments, for: operation)
            let result = try await executor.performResourceOperation(operation, credential: destinationCredential, scope: resolution.scope, arguments: arguments, sourceValue: sourceValue)
            return result.resourceID
        case .githubActionsSecret:
            // BL-128 slice 3c (D65). BL-091's resource path, as Vercel's. The
            // adapter reads the repository's public key, seals the value to it
            // and sends only the ciphertext; the name is the only field.
            let arguments = ResourceMutationArguments(
                fields: [.name: resolution.destination.name],
                sourceVaultItemID: resolution.sourceItem.id
            )
            try ResourceFieldRules.validate(arguments, for: operation)
            _ = try await executor.performResourceOperation(operation, credential: destinationCredential, scope: resolution.scope, arguments: arguments, sourceValue: sourceValue)
            // Keyed by name, and GitHub returns no identifier of its own.
            return nil
        }
    }

    /// The provider-stated expiry of the delivered credential, when Vaultage
    /// created it and the provider said one. Nil means **not known**, never
    /// "does not expire": a pasted credential's expiry is something only the
    /// provider's dashboard knows, and inventing one would make the
    /// environment card's expiry warning meaningless.
    private func expiryOfSource(_ item: VaultItem, in state: VaultageMetadata) -> Date? {
        state.provisionedResources
            .filter { $0.vaultItemID == item.id && $0.revokedAt == nil }
            .compactMap(\.expiresAt)
            .min()
    }

    private func appendDelivery(_ request: CredentialDeliveryRequest, connectionID: UUID?, _ decision: AuditDecision, _ result: String) async throws {
        try await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: connectionID, operation: "vaultage.delivery", decision: decision, result: Redactor.safeError(result)))
    }

    private func persistDeliveryReceipt(_ request: CredentialDeliveryRequest, resolution: DeliveryResolution, digest: String, correlationID: UUID, _ decision: AuditDecision, _ result: String, providerResourceID: String?) async throws {
        // The receipt carries the source item id, the destination, the target
        // and the provider's returned identifier — and no value, by
        // construction: there is no field on `DurableReceipt` a value could go
        // in, and every string here is built from validated local records.
        try await receipts.append(DurableReceipt(
            eventID: UUID(),
            correlationID: correlationID,
            at: .now,
            projectID: request.projectID,
            environmentID: request.environmentID,
            bindingID: request.bindingID,
            vaultItemID: resolution.sourceItem.id,
            operation: resolution.writeOperationIfNew.rawValue,
            requestDigest: digest,
            decision: decision,
            result: Redactor.safeError(result),
            resourceID: providerResourceID ?? resolution.destination.name,
            effect: Redactor.safeError("\(resolution.destination.sheetLine) · target \(resolution.destination.target?.rawValue ?? "n/a") · source item \(resolution.sourceItem.id.uuidString)\(resolution.requester.map { " · asked by an agent (\($0))" } ?? "")")
        ))
    }

    private func completeDeliveryKnown(_ request: CredentialDeliveryRequest, resolution: DeliveryResolution, digest: String, correlationID: UUID, decision: AuditDecision, result: String) async throws {
        try await persistDeliveryReceipt(request, resolution: resolution, digest: digest, correlationID: correlationID, decision, result, providerResourceID: nil)
        try? await appendDelivery(request, connectionID: resolution.connection.id, decision, result)
    }

    // MARK: - BL-094 rotation with overlap (desktop only)

    /// Plans a rotation: every destination the old credential feeds becomes a
    /// step, and nothing is delivered yet.
    ///
    /// Rotation never mints. The new value is a vault item that already exists —
    /// pasted by the human, or created by `createProviderResource` in its own
    /// approval and its own class. A flow that could mint on its way through
    /// would be a flow that creates authority without the sheet that exists to
    /// authorize it.
    public func planRotation(_ request: CredentialRotationRequest) async throws -> CredentialRotation {
        let state = try await metadata.load()
        guard request.oldVaultItemID != request.newVaultItemID else {
            throw VaultageError.invalidInput("A rotation needs a different credential to rotate to.")
        }
        guard let oldItem = state.vaultItems.first(where: { $0.id == request.oldVaultItemID }),
              let newItem = state.vaultItems.first(where: { $0.id == request.newVaultItemID }),
              newItem.hasProtectedValue,
              MetadataRemoval.deletionReservation(forVaultItem: newItem.id, in: state) == nil
        else { throw VaultageError.invalidInput("Both the old and the new credential must be vault items, and the new one must hold a value.") }
        if let existing = CredentialRotationStore.openRotation(forOldItem: oldItem.id, in: state) {
            // One open rotation per credential. Two would be two overlaps
            // racing to decide when the old value stops being needed, and the
            // loser would revoke while the winner was still delivering.
            throw VaultageError.policyDenied("A rotation of \"\(oldItem.label)\" is already in progress (\(existing.progressSummary)). Resume or cancel it first.")
        }

        let rows = DeployedCredentialLedger.entries(in: state, sourceVaultItemID: oldItem.id).filter { $0.status.isLive }
        guard !rows.isEmpty else {
            throw VaultageError.invalidInput("Vaultage has not delivered \"\(oldItem.label)\" to any provider secret store, so there is nothing to rotate with overlap. Replace the value in the vault instead.")
        }
        guard rows.count <= CredentialRotation.maximumSteps else {
            throw VaultageError.policyDenied("A rotation covers at most \(CredentialRotation.maximumSteps) destinations.")
        }
        var provider: Provider?
        var steps: [RotationStep] = []
        // Deterministic order, so a resumed rotation walks its steps in the
        // same order the first turn did and a self-test can say what happens
        // next. Name, then target, then the row id as a tiebreak: two
        // destinations may legitimately share a name.
        let ordered = rows.sorted { left, right in
            let leftKey = [left.destination.store.rawValue, left.destination.scopeID, left.destination.name, left.destination.target?.rawValue ?? ""]
            let rightKey = [right.destination.store.rawValue, right.destination.scopeID, right.destination.name, right.destination.target?.rawValue ?? ""]
            if leftKey != rightKey { return leftKey.lexicographicallyPrecedes(rightKey) }
            return left.id.uuidString < right.id.uuidString
        }
        for row in ordered {
            guard let environment = state.environments.first(where: { $0.id == row.environmentID }) else { continue }
            provider = provider ?? row.provider
            steps.append(RotationStep(ledgerRowID: row.id, projectID: row.projectID, environmentID: row.environmentID, environmentName: environment.name, bindingID: row.bindingID, destination: row.destination, sourceField: row.sourceField))
        }
        guard let provider, !steps.isEmpty else {
            throw VaultageError.invalidInput("None of the recorded destinations for \"\(oldItem.label)\" can still be reached.")
        }

        let rotation = CredentialRotation(
            oldVaultItemID: oldItem.id,
            oldFingerprint: DeployedCredentialLedger.fingerprint(of: oldItem),
            newVaultItemID: newItem.id,
            newFingerprint: DeployedCredentialLedger.fingerprint(of: newItem),
            origin: request.origin,
            provider: provider,
            label: oldItem.label,
            startedAt: now(),
            steps: steps
        )
        _ = try await metadata.update { state in
            state.rotations.append(rotation)
        }
        try? await audit.append(AuditEvent(projectID: steps[0].projectID, environmentID: steps[0].environmentID, connectionID: nil, operation: "vaultage.rotation.plan", decision: .approved, result: "Planned a rotation of \"\(oldItem.label)\" across \(steps.count) \(steps.count == 1 ? "destination" : "destinations"). Nothing is delivered and nothing is revoked yet."))
        return rotation
    }

    /// Runs a rotation forward, one step at a time.
    ///
    /// Each step is a full delivery with its own native approval — **not one
    /// blanket approval for the rotation**. The human is agreeing to write a
    /// secret into a named production destination, and that is a different
    /// question for each destination; a rotation is the reason several of them
    /// are being asked in a row, not a reason to stop asking.
    ///
    /// Each step's outcome is persisted before the next one begins, so quitting
    /// the app between two approvals leaves a resumable record and never a
    /// revoked-before-delivered state. Calling this again resumes: a verified
    /// step is skipped, a delivered-but-unverified step is verified, and a
    /// failed step is retried.
    ///
    /// It stops at the first step that does not complete, so a rotation never
    /// ploughs on past a destination it could not reach.
    @discardableResult
    public func runRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress {
        var delivered: [CredentialDeliveryOutcome] = []
        while true {
            let state = try await metadata.load()
            guard let rotation = state.rotations.first(where: { $0.id == rotationID }) else {
                throw VaultageError.invalidInput("That rotation no longer exists.")
            }
            guard rotation.state.isOpen else { break }
            guard let step = rotation.nextStep else { break }
            // The step's own record is what the delivery re-resolves from, so a
            // binding or a scope that moved between two steps refuses here
            // exactly as it would refuse a first delivery.
            let request = CredentialDeliveryRequest(
                projectID: step.projectID,
                environmentID: step.environmentID,
                bindingID: step.bindingID,
                sourceVaultItemID: rotation.newVaultItemID,
                // CC-H6. The same field the ledger row this step replaces was
                // fed by — never a guess, and never the envelope.
                sourceField: step.sourceField,
                destinationName: step.destination.name,
                target: step.destination.target,
                rotationID: rotation.id
            )
            // BL-128 slice 3c, second security pass. The step was planned for
            // one container — a repository, a project, a Worker. If the binding
            // has since been re-pointed, delivering would write the new value
            // somewhere else and then supersede the old row while the old
            // container still holds the old value. Refused before anything is
            // read; checked again against the outcome below, for a re-point
            // that lands while the sheet is up.
            if let current = state.bindings.first(where: { $0.id == step.bindingID }),
               let now = Self.currentDeliveryDestination(of: current, in: state, name: step.destination.name, target: step.destination.target),
               now.store != step.destination.store || now.scopeID != step.destination.scopeID {
                let reason = "The binding now points at \(now.containerLine), but this step was planned for \(step.destination.containerLine). Plan the rotation again for where the credential is deployed."
                _ = try await metadata.update { state in
                    guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return }
                    RotationMachine.markFailed(&state.rotations[index], stepID: step.id, reason: reason)
                }
                break
            }
            // The attempt is counted and persisted *before* it is made, so a
            // crash loop cannot retry forever.
            _ = try await metadata.update { state in
                guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return }
                RotationMachine.countAttempt(&state.rotations[index], stepID: step.id)
            }

            do {
                let outcome = try await deliverCredential(request)
                delivered.append(outcome)
                // The same comparison after the fact: a delivery the human
                // approved to another container is recorded as that, and the
                // step it was not is failed rather than counted.
                guard outcome.destination.store == step.destination.store, outcome.destination.scopeID == step.destination.scopeID else {
                    let reason = "The delivery went to \(outcome.destination.containerLine), not \(step.destination.containerLine), because the binding was re-pointed while it ran. Plan the rotation again."
                    _ = try await metadata.update { state in
                        guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return }
                        RotationMachine.markFailed(&state.rotations[index], stepID: step.id, reason: reason)
                    }
                    break
                }
                _ = try await metadata.update { state in
                    guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return }
                    RotationMachine.markDelivered(&state.rotations[index], stepID: step.id, at: outcome.deliveredAt)
                    // The delivery's own post-write name list is the
                    // verification: it is the same read "verify deployed"
                    // issues, run at the only moment it is certain to be about
                    // this write. A delivery that could not be confirmed leaves
                    // the step `delivered`, which is deliberately not enough to
                    // revoke.
                    if outcome.verified {
                        RotationMachine.markVerified(&state.rotations[index], stepID: step.id, at: outcome.deliveredAt)
                    }
                    // The old credential's row for this destination is
                    // superseded only once the new one is actually there.
                    if outcome.verified {
                        for row in state.deployedCredentials where row.sourceVaultItemID == rotation.oldVaultItemID && row.id == step.ledgerRowID {
                            DeployedCredentialLedger.markSuperseded(rowID: row.id, rotationID: rotationID, at: outcome.deliveredAt, in: &state)
                        }
                    }
                }
                if !outcome.verified { break }
            } catch {
                let reason = Redactor.publicError(error)
                _ = try await metadata.update { state in
                    guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return }
                    RotationMachine.markFailed(&state.rotations[index], stepID: step.id, reason: reason)
                }
                break
            }
        }
        return try await rotationProgress(rotationID, delivered: delivered)
    }

    /// Marks the old credential revoked **locally**, and only when every
    /// destination is delivered and verified.
    ///
    /// This is the only path that sets `oldRevokedAt`, and it asks
    /// `RotationMachine.mayRevokeOldCredential` first. Vaultage does not revoke
    /// at the provider here: a credential the human created outside Vaultage
    /// may be in use by something Vaultage cannot see, so the flow marks it
    /// revoked locally, stops using it, and points at the credential's issuer —
    /// "Revoke at {issuer} ↗", or "Revoke it where it was issued" when Vaultage
    /// does not know it (`RotationMachine.issuer(of:in:)`).
    @discardableResult
    public func revokeRotatedCredential(_ rotationID: UUID) async throws -> CredentialRotationProgress {
        let state = try await metadata.load()
        guard let rotation = state.rotations.first(where: { $0.id == rotationID }) else {
            throw VaultageError.invalidInput("That rotation no longer exists.")
        }
        if let reason = RotationMachine.revocationBlockedReason(rotation) {
            throw VaultageError.policyDenied(reason)
        }
        // The sheet names the issuer — where the old credential lives on — not
        // the store it was delivered into.
        let issuer = RotationMachine.issuer(of: rotation, in: state)
        let details = ApprovalDetails(
            project: "Rotation",
            environment: rotation.steps.map(\.environmentName).sorted().joined(separator: ", "),
            provider: issuer?.title ?? "Issuer not recorded",
            connection: rotation.label,
            operation: "vaultage.rotation.revoke_old",
            reason: "Every one of the \(rotation.steps.count) \(rotation.steps.count == 1 ? "destination" : "destinations") now holds the new credential and each has been verified by listing names. Vaultage will stop using \"\(rotation.label)\" and mark it revoked here. \(RotationMachine.providerRevocationExplanation(issuer: issuer))",
            client: currentClient(state)
        )
        guard await approve(details) else {
            throw VaultageError.approvalDenied
        }
        let instant = now()
        let revokedRows = try await metadata.updateResult { state -> Int in
            guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return 0 }
            // Asked again against freshly loaded state: a step could have been
            // repaired away, or another process could have changed the ledger,
            // between the sheet and this write.
            guard RotationMachine.revokeOldCredential(&state.rotations[index], at: instant) else { return 0 }
            return DeployedCredentialLedger.markRevoked(sourceVaultItemID: state.rotations[index].oldVaultItemID, at: instant, in: &state)
        }
        let after = try await metadata.load()
        guard after.rotations.first(where: { $0.id == rotationID })?.oldRevokedAt != nil else {
            throw VaultageError.policyDenied("The rotation changed before the old credential could be revoked; nothing was revoked.")
        }
        try await receipts.append(DurableReceipt(
            eventID: UUID(),
            correlationID: rotationID,
            at: .now,
            projectID: rotation.steps.first?.projectID,
            environmentID: rotation.steps.first?.environmentID,
            bindingID: nil,
            vaultItemID: rotation.oldVaultItemID,
            operation: "vaultage.rotation.revoke_old",
            requestDigest: CanonicalDigest.hex(["vaultage.rotation.revoke.digest", rotationID.uuidString, rotation.oldVaultItemID.uuidString, rotation.oldFingerprint, rotation.newVaultItemID.uuidString, rotation.newFingerprint, "\(rotation.steps.count)"]),
            decision: .executed,
            result: "Marked \"\(rotation.label)\" revoked in Vaultage after \(rotation.steps.count) verified \(rotation.steps.count == 1 ? "delivery" : "deliveries"). It is still valid \(issuer.map { "at \($0.title)" } ?? "wherever it was issued") until revoked there.",
            effect: "\(revokedRows) ledger \(revokedRows == 1 ? "row" : "rows") marked revoked"
        ))
        try? await audit.append(AuditEvent(projectID: rotation.steps.first?.projectID, environmentID: rotation.steps.first?.environmentID, connectionID: nil, operation: "vaultage.rotation.revoke_old", decision: .executed, result: "Marked \"\(rotation.label)\" revoked in Vaultage. \(RotationMachine.providerRevocationPrompt(issuer: issuer))"))
        return try await rotationProgress(rotationID, delivered: [])
    }

    /// The human has revoked at the provider, or has said they are done.
    @discardableResult
    public func completeRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress {
        let instant = now()
        let moved = try await metadata.updateResult { state -> Bool in
            guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return false }
            return RotationMachine.complete(&state.rotations[index], at: instant)
        }
        guard moved else {
            throw VaultageError.policyDenied("A rotation is only complete once the old credential has been revoked in Vaultage.")
        }
        return try await rotationProgress(rotationID, delivered: [])
    }

    /// Stops a rotation. Delivered destinations keep the new value, because
    /// un-delivering would be a second production change nobody asked for, and
    /// the old credential is never revoked.
    @discardableResult
    public func cancelRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress {
        let instant = now()
        let moved = try await metadata.updateResult { state -> Bool in
            guard let index = state.rotations.firstIndex(where: { $0.id == rotationID }) else { return false }
            return RotationMachine.cancel(&state.rotations[index], at: instant)
        }
        guard moved else {
            throw VaultageError.policyDenied("This rotation cannot be cancelled: the old credential has already been revoked.")
        }
        try? await audit.append(AuditEvent(operation: "vaultage.rotation.cancel", decision: .blocked, result: "A rotation was cancelled. Destinations already delivered keep the new credential; the old one was not revoked."))
        return try await rotationProgress(rotationID, delivered: [])
    }

    public func openRotations() async throws -> [CredentialRotation] {
        CredentialRotationStore.openRotations(in: try await metadata.load())
    }

    private func rotationProgress(_ rotationID: UUID, delivered: [CredentialDeliveryOutcome]) async throws -> CredentialRotationProgress {
        let state = try await metadata.load()
        guard let rotation = state.rotations.first(where: { $0.id == rotationID }) else {
            throw VaultageError.invalidInput("That rotation no longer exists.")
        }
        let mayRevoke = RotationMachine.mayRevokeOldCredential(rotation)
        let blocked = RotationMachine.revocationBlockedReason(rotation)
        let issuer = RotationMachine.issuer(of: rotation, in: state)
        let message: String
        switch rotation.state {
        case .completed:
            message = "Rotation complete. \(rotation.progressSummary)"
        case .cancelled:
            message = "Rotation cancelled. \(rotation.verifiedSteps.count) \(rotation.verifiedSteps.count == 1 ? "destination" : "destinations") already carry the new credential and keep working; \"\(rotation.label)\" was not revoked."
        case .oldRevokedLocally:
            message = "\(rotation.progressSummary) \"\(rotation.label)\" is revoked in Vaultage. \(RotationMachine.providerRevocationExplanation(issuer: issuer))"
        case .delivered:
            message = "\(rotation.progressSummary) Every destination is delivered and verified, so the old credential can now be revoked."
        case .preparing, .delivering:
            message = "\(rotation.progressSummary) \(blocked ?? "")"
        }
        return CredentialRotationProgress(
            rotation: rotation,
            delivered: delivered,
            mayRevokeOldCredential: mayRevoke,
            blockedReason: blocked,
            providerRevocationPrompt: RotationMachine.providerRevocationPrompt(issuer: issuer),
            message: message
        )
    }

    // MARK: - BL-091 provider resource operations

    /// The BL-091 path: one function for every provider resource operation,
    /// with the approval class chosen by `ApprovalRequirement` rather than by
    /// the operation's name.
    ///
    /// It is deliberately the same shape as the read path and the Worker-secret
    /// path, because the invariants are the same and a third shape would be a
    /// third place to get them wrong: resolve, class the approval, prove
    /// verification, digest, approve, **re-resolve and re-compare the digest**,
    /// write a durable pending receipt before any protected read, read, re-prove
    /// immediately before egress, dispatch once, complete the receipt exactly
    /// once. The three things this path adds are the bound resource scope, the
    /// two-step delete, and the local idempotency ledger.
    ///
    /// BL-092 changed the return type from `ActionResult` to the structured
    /// `ResourceOperationResult` and moved the `.actionResult` flattening to the
    /// single call site in `execute`. Nothing about the path moved: the
    /// inventory refresh needs the projected *items* — a DNS record's type and
    /// content, an environment variable's target — which the flattening drops,
    /// and the alternative was a second copy of this function.
    private func executeResourceOperation(_ request: ActionRequest) async throws -> ResourceOperationResult {
        let operation = request.operation
        let taxonomy = operation.taxonomy
        let requirement = operation.approvalRequirement
        guard let resourceExecutor else {
            throw VaultageError.unsupported("Provider resource operations are unavailable in this build.")
        }
        // BL-074's class is a different enum and cannot reach `Operation`. This
        // asserts that rather than assuming it, so a future operation that was
        // classified as credential-minting fails closed here instead of
        // acquiring an agent surface by accident.
        guard requirement != .nativeApprovalOnly else {
            throw VaultageError.policyDenied("\(operation.rawValue) mints a credential and is not an agent operation.")
        }
        let arguments = request.resourceMutation ?? ResourceMutationArguments()
        // Audit H-11: a create the provider does not de-duplicate is never
        // dispatched from the agent's door without local replay protection —
        // the broker's own check on whatever crossed the process boundary,
        // not only the parser's. (The delivery path carries its own replay
        // control, the preflight, and does not pass here.)
        if taxonomy.idempotency == .idempotencyKey, arguments.idempotencyKey == nil {
            throw VaultageError.invalidInput("\(operation.rawValue) requires an idempotency key: a string of 8–64 letters, digits, `_` or `-`, chosen once per intended change and repeated exactly on a retry.")
        }
        // Re-validated here even though `VaultageMCPServer` already validated
        // it: a request that crossed a process boundary is input again on
        // arrival, and this is the last place before a credential is read.
        do { try ResourceFieldRules.validate(arguments, for: operation) }
        catch {
            try? await append(request, connectionID: nil, .blocked, "The resource request did not validate.")
            throw error
        }

        let state = try await metadata.load()
        let resolution: ResourceResolution
        do { resolution = try resourceResolution(state, request: request, arguments: arguments) }
        catch {
            try? await append(request, connectionID: nil, .blocked, "No permitted bound resource scope for this operation.")
            throw error
        }

        // The first half of the two-step delete. It is answered entirely from
        // local records: no credential is read and no provider request is sent.
        // That is deliberate on both counts — it costs the human nothing, and it
        // means an unapproved call cannot be used as an oracle for whether a
        // given id exists at the provider.
        if taxonomy.isTwoStepDelete, !arguments.confirmDelete {
            guard let resourceID = arguments.resourceID else {
                throw VaultageError.invalidInput("A delete requires the exact resource id.")
            }
            let preview = ResourceDeletePreview(
                resourceID: resourceID,
                resourceKind: taxonomy.resource,
                summary: "\(taxonomy.resource.label) \(resourceID) on \(resolution.scope.sheetTarget) in \(resolution.project.name) / \(resolution.environment.name).",
                confirmationToken: resourceID
            )
            let result = ResourceOperationResult(
                operation: operation.rawValue,
                kind: taxonomy.kind,
                resourceKind: taxonomy.resource,
                resourceID: resourceID,
                effect: "Nothing was deleted. Call \(operation.rawValue) again with the same resource_id and confirm: true to remove it; the approval sheet will name that exact id.",
                preview: preview
            )
            try? await append(request, connectionID: resolution.connection.id, .pending, "Delete preview only; nothing was removed and no provider request was sent.")
            return result
        }

        try await requireActiveManagedConnection(resolution.connection.id)
        let decisionInstant = now()
        await grantCache.purge(now: decisionInstant)
        // The one branch a grant can change, and only for the two classes that
        // permit it. A delete, anything production-affecting and anything admin
        // never consults a grant at all, so there is no path on which a grant
        // could be the thing that is wrong.
        let autoAllow: Grant? = requirement.mayBeCoveredByGrant
            ? GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: state, now: decisionInstant, signer: grantSigner)
            : nil
        try requireCurrentVerification(connection: resolution.connection, item: resolution.item, operation: operation, grant: autoAllow)
        let digest = resourceDigest(request: request, resolution: resolution, arguments: arguments)
        if let autoAllow {
            try? await append(request, connectionID: resolution.connection.id, .approved, "Auto-allowed without a prompt by grant \(autoAllow.id.uuidString), which expires \(ISO8601DateFormatter().string(from: autoAllow.expiresAt)).")
        } else {
            let details = resourceApprovalDetails(request: request, resolution: resolution, arguments: arguments, digest: digest, client: currentClient(state))
            guard await approve(details) else {
                try? await append(request, connectionID: resolution.connection.id, .denied, "Human denied \(operation.rawValue).")
                throw VaultageError.approvalDenied
            }
        }
        let approvedAt = now()

        // Nothing the sheet named may have moved while it was up.
        let refreshedState: VaultageMetadata
        let refreshed: ResourceResolution
        do {
            refreshedState = try await metadata.load()
            refreshed = try resourceResolution(refreshedState, request: request, arguments: arguments)
            guard resourceDigest(request: request, resolution: refreshed, arguments: arguments) == digest else {
                throw VaultageError.policyDenied("The approved resource request changed before execution.")
            }
            if let autoAllow {
                guard GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: refreshedState, now: now(), signer: grantSigner)?.id == autoAllow.id else {
                    throw VaultageError.policyDenied("The auto-allow grant no longer covers this action.")
                }
            }
        } catch {
            try? await append(request, connectionID: nil, .blocked, "The resource binding or scope changed while approval was pending.")
            throw VaultageError.policyDenied("The approved resource request changed before execution.")
        }
        try await requireActiveManagedConnection(refreshed.connection.id)
        try requireCurrentVerification(connection: refreshed.connection, item: refreshed.item, operation: operation, grant: autoAllow)

        // The durable, value-free pending receipt is the egress precondition: if
        // local persistence fails, nothing is read and nothing is sent.
        let invocationID = UUID()
        try await persistResourceReceipt(request, digest: digest, correlationID: invocationID, .pending, autoAllow == nil ? "Approved \(operation.rawValue) pending." : "Auto-allowed \(operation.rawValue) pending.", grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)

        // Local replay protection, claimed *before* dispatch so two concurrent
        // agents cannot both be told they are the first. See
        // `ResourceMutationKey`: the providers in this slice document no
        // idempotency key of their own, so this is the only thing between a
        // retried agent and a second DNS record.
        var claimedKey: String?
        if let key = arguments.idempotencyKey {
            let claim = try await claimIdempotencyKey(key, bindingID: request.bindingID, operation: operation, digest: digest, at: now())
            switch claim {
            case let .replay(record) where record.effect == ResourceMutationKey.unresolvedEffect:
                // Audit H-11: the earlier dispatch never reported — a crash
                // before or after it, or an ambiguous reply. That is not
                // "already done"; it is unknown, and the same key must not be
                // spent again until the owner has looked.
                try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: .resultUnknown, result: "An earlier dispatch under idempotency key \(key) has no known result. Nothing was sent.", grantID: autoAllow?.id, resourceID: nil, effect: nil)
                throw VaultageError.resultUnknown
            case let .replay(record):
                let replayed = ResourceOperationResult(
                    operation: operation.rawValue,
                    kind: taxonomy.kind,
                    resourceKind: taxonomy.resource,
                    resourceID: record.resourceID,
                    effect: "Already done under idempotency key \(key). \(record.effect) Nothing was sent to the provider."
                )
                try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: .executed, result: replayed.effect, grantID: autoAllow?.id, resourceID: record.resourceID, effect: record.effect)
                return replayed
            case .conflict:
                try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: .blocked, result: "That idempotency key was already used for a different request.", grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)
                throw VaultageError.invalidInput("That idempotency key was already used for a different request. Use a new key, or repeat the original request exactly.")
            case .claimed:
                claimedKey = key
            }
        }

        let credential: VaultSecret
        // D71: nothing on this path reads a source value — see
        // `resourceResolution` — and the adapter is handed none.
        let sourceValue: VaultSecret? = nil
        do {
            credential = try vault.read(account: refreshed.item.keychainAccount, prompt: "Approve \(operation.rawValue) on \(refreshed.scope.sheetTarget) for \(refreshed.project.name) / \(refreshed.environment.name)")
        } catch {
            await releaseIdempotencyKey(claimedKey, bindingID: request.bindingID, operation: operation)
            try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: Redactor.publicError(error), grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)
            throw error
        }

        // A Keychain sheet can stay open while another process changes the
        // graph. Re-prove everything immediately before egress, under the same
        // 60-second approval lifetime the runtime path imposes.
        do {
            if let autoAllow {
                let finalState = try await metadata.load()
                guard GrantPolicy.authorizingGrant(for: request, presented: presentedClient, in: finalState, now: now(), signer: grantSigner)?.id == autoAllow.id else {
                    throw VaultageError.policyDenied("The auto-allow grant no longer covers this action.")
                }
                let final = try resourceResolution(finalState, request: request, arguments: arguments)
                guard resourceDigest(request: request, resolution: final, arguments: arguments) == digest else {
                    throw VaultageError.policyDenied("The approved resource request changed before egress.")
                }
                try await requireActiveManagedConnection(final.connection.id)
                try requireCurrentVerification(connection: final.connection, item: final.item, operation: operation, grant: autoAllow)
            } else {
                guard now().timeIntervalSince(approvedAt) <= 60 else { throw VaultageError.approvalDenied }
                let finalState = try await metadata.load()
                let final = try resourceResolution(finalState, request: request, arguments: arguments)
                guard resourceDigest(request: request, resolution: final, arguments: arguments) == digest else {
                    throw VaultageError.policyDenied("The approved resource request changed before egress.")
                }
                try await requireActiveManagedConnection(final.connection.id)
                try requireCurrentVerification(connection: final.connection, item: final.item, operation: operation, grant: autoAllow)
            }
        } catch {
            await releaseIdempotencyKey(claimedKey, bindingID: request.bindingID, operation: operation)
            try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: terminalDecision(for: error), result: "Resource authorization changed or expired after OS authentication.", grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)
            throw error
        }

        let result: ResourceOperationResult
        do {
            result = try await resourceExecutor.performResourceOperation(operation, credential: credential, scope: refreshed.scope, arguments: arguments, sourceValue: sourceValue)
        } catch let error as VaultageError where error == .resultUnknown {
            // An ambiguous mutation keeps its claim, precisely because a retry
            // under the same key must not dispatch a second time.
            try? await persistResourceReceipt(request, digest: digest, correlationID: invocationID, .resultUnknown, "\(operation.rawValue) result unknown; no automatic retry was performed.", grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)
            try? await append(request, connectionID: refreshed.connection.id, .resultUnknown, "\(operation.rawValue) result unknown; no automatic retry was performed.")
            throw error
        } catch {
            // A known failure — a 4xx the provider named, a malformed reply —
            // means nothing was created, so the key is released and the agent
            // may correct the request and try again.
            await releaseIdempotencyKey(claimedKey, bindingID: request.bindingID, operation: operation)
            try await completeResourceKnown(request, digest: digest, correlationID: invocationID, connectionID: refreshed.connection.id, decision: .failed, result: Redactor.publicError(error), grantID: autoAllow?.id, resourceID: arguments.resourceID, effect: nil)
            throw error
        }

        if let claimedKey {
            await recordIdempotencyOutcome(claimedKey, bindingID: request.bindingID, operation: operation, resourceID: result.resourceID, effect: result.effect)
        }
        do {
            try await persistResourceReceipt(request, digest: digest, correlationID: invocationID, .executed, result.effect, grantID: autoAllow?.id, resourceID: result.resourceID ?? arguments.resourceID, effect: result.effect)
        } catch {
            // The provider may already have applied the change. Keep the
            // no-retry state rather than inventing a conflicting failure.
            try? await persistResourceReceipt(request, digest: digest, correlationID: invocationID, .resultUnknown, "Provider accepted a change but final receipt persistence failed; do not retry automatically.", grantID: autoAllow?.id, resourceID: result.resourceID ?? arguments.resourceID, effect: result.effect)
            try? await append(request, connectionID: refreshed.connection.id, .resultUnknown, "Provider change may have completed; final receipt persistence failed.")
            throw VaultageError.resultUnknown
        }
        try? await append(request, connectionID: refreshed.connection.id, .executed, result.effect)
        return result
    }

    /// Resolves every record a resource operation names, or throws.
    ///
    /// The scope is the load-bearing part: it comes from the *binding*, it must
    /// be well formed, it must belong to this operation's provider, and its kind
    /// must be one this operation runs against. An agent cannot supply one and
    /// cannot change one, so "create a DNS record" can only ever mean "in the
    /// zone the human bound".
    private func resourceResolution(_ state: VaultageMetadata, request: ActionRequest, arguments: ResourceMutationArguments) throws -> ResourceResolution {
        guard let binding = state.bindings.first(where: { $0.id == request.bindingID }),
              binding.projectID == request.projectID,
              binding.environmentID == request.environmentID,
              binding.allowedOperations.contains(request.operation),
              let scope = binding.resourceScope,
              scope.isWellFormed,
              scope.provider == request.operation.provider,
              ProviderResourceScope.kinds(for: request.operation).contains(scope.kind),
              let project = state.projects.first(where: { $0.id == request.projectID }),
              let environment = state.environments.first(where: { $0.id == request.environmentID }),
              environment.projectID == project.id,
              let connection = state.connections.first(where: { $0.id == binding.connectionID }),
              connection.provider == request.operation.provider,
              let item = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
              item.provider == connection.provider,
              MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil
        else { throw VaultageError.policyDenied("This resource operation is not permitted by the selected binding and scope.") }
        // D71: no operation this path performs takes a vault value. `execute`
        // refuses every delivery before it gets here, and the adapter refuses
        // a delivery handed no value — so a source is neither resolved nor
        // read on this path.
        return ResourceResolution(project: project, environment: environment, binding: binding, connection: connection, item: item, scope: scope)
    }

    /// RP-07, as every other digest here: one canonical, injective, field-list
    /// encoding. The scope and the typed arguments state their own lengths, so
    /// no provider-shaped string can impersonate a second field.
    private func resourceDigest(request: ActionRequest, resolution: ResourceResolution, arguments: ResourceMutationArguments) -> String {
        let evidence = resolution.connection.verification
        var fields: [String] = [
            "vaultage.resource.request.digest",
            request.projectID.uuidString,
            request.environmentID.uuidString,
            request.bindingID.uuidString,
            resolution.connection.id.uuidString,
            resolution.item.id.uuidString,
            resolution.item.keychainAccount,
            resolution.item.credentialVersion?.uuidString ?? "none",
            evidence?.providerContractRevision ?? "none",
            "\(evidence?.verifiedAt.timeIntervalSince1970 ?? 0)",
            evidence?.principalID ?? "unknown",
            request.operation.rawValue,
            "production",
            "\(resolution.environment.isProduction)",
            // D71: no source on this path. The term stays, fixed, so the
            // encoding is the one every receipt before it was written under.
            "source",
            "none",
            "none",
            "none"
        ]
        fields.append(contentsOf: resolution.scope.canonicalFields)
        fields.append(contentsOf: arguments.canonicalFields)
        return CanonicalDigest.hex(fields)
    }

    /// D34's copy rule as code: resource, then action, then safety. Every string
    /// on this sheet is built from *resolved local records* and from typed
    /// fields that have already passed `ResourceFieldRules`, never from provider
    /// text and never from an agent-supplied description.
    private func resourceApprovalDetails(request: ActionRequest, resolution: ResourceResolution, arguments: ResourceMutationArguments, digest: String, client: ClientIdentity) -> ApprovalDetails {
        let operation = request.operation
        let taxonomy = operation.taxonomy
        let resourceLine = "\(taxonomy.resource.label) on \(resolution.scope.sheetTarget)"
        var actionLine: String
        switch taxonomy.kind {
        case .read:
            actionLine = "List the \(taxonomy.resource.label.lowercased())s Vaultage can see there. Nothing is changed."
        case .create:
            let described = arguments.fields.keys.sorted().map { "\($0.rawValue) \(arguments.fields[$0] ?? "")" }.joined(separator: ", ")
            actionLine = "Create a new \(taxonomy.resource.label.lowercased()): \(described)."
        case .update:
            let described = arguments.fields.keys.sorted().map { "\($0.rawValue) \(arguments.fields[$0] ?? "")" }.joined(separator: ", ")
            actionLine = "Update the existing \(taxonomy.resource.label.lowercased()) \(arguments.resourceID ?? "unknown")\(described.isEmpty ? "" : " to \(described)")."
        case .delete:
            actionLine = "Delete the \(taxonomy.resource.label.lowercased()) whose id is exactly \(arguments.resourceID ?? "unknown")."
        case .deliver:
            // BL-094. A delivery's sheet names the destination, not the verb:
            // whether the provider ends up creating the entry or replacing an
            // existing one is decided by the preflight, and the human is
            // answering "should this secret live there?" either way.
            let destination = arguments.fields[.name] ?? arguments.resourceID ?? "the named entry"
            let target = arguments.fields[.target].map { " (\($0))" } ?? ""
            actionLine = "Deliver a value from the vault into \(resolution.scope.sheetTarget) as \(destination)\(target), creating it or replacing what is there."
        }
        let disclosure = ResourceOperationDisclosure(
            resourceLine: resourceLine,
            actionLine: actionLine,
            safetyLine: taxonomy.kind == .delete ? ResourceOperationDisclosure.deleteSafetySentence : ResourceOperationDisclosure.safetySentence,
            trustClass: taxonomy.trust,
            kind: taxonomy.kind,
            resourceKind: taxonomy.resource,
            resourceID: arguments.resourceID,
            scopeLabel: resolution.scope.label,
            productionWarning: resolution.environment.isProduction ? ResourceOperationDisclosure.productionSentence : nil,
            valueDisclosure: taxonomy.providerReturnsValues ? ResourceOperationDisclosure.vercelValueSentence : nil,
            idempotencyNote: taxonomy.idempotency == .idempotencyKey ? ResourceOperationDisclosure.localIdempotencySentence : nil,
            requestDigest: digest
        )
        return ApprovalDetails(
            project: resolution.project.name,
            environment: resolution.environment.name,
            provider: resolution.connection.provider.title,
            connection: resolution.connection.label,
            operation: operation.rawValue,
            reason: "\(resourceLine). \(actionLine) \(disclosure.safetyLine) \(providerEvidenceDescription(resolution.connection))",
            client: client,
            resourceOperation: disclosure
        )
    }

    // MARK: BL-091 local idempotency ledger

    private enum IdempotencyClaim: Sendable {
        case claimed
        case replay(ResourceMutationKey)
        case conflict
    }

    /// Claims a key for this exact request, before dispatch, under the metadata
    /// lock. A key already held for the *same* request digest replays; a key
    /// held for a different one is a conflict and is refused rather than
    /// silently becoming a second, different mutation.
    private func claimIdempotencyKey(_ key: String, bindingID: UUID, operation: Operation, digest: String, at instant: Date) async throws -> IdempotencyClaim {
        try await metadata.updateResult { state in
            state.resourceMutationKeys.removeAll { !$0.isLive(at: instant) }
            if let existing = state.resourceMutationKeys.first(where: { $0.key == key && $0.bindingID == bindingID && $0.operation == operation.rawValue }) {
                return existing.requestDigest == digest ? .replay(existing) : .conflict
            }
            if state.resourceMutationKeys.count >= ResourceMutationKey.maximumRecords {
                state.resourceMutationKeys.removeFirst(state.resourceMutationKeys.count - ResourceMutationKey.maximumRecords + 1)
            }
            state.resourceMutationKeys.append(ResourceMutationKey(key: key, bindingID: bindingID, operation: operation.rawValue, requestDigest: digest, at: instant, resourceID: nil, effect: ResourceMutationKey.unresolvedEffect))
            return .claimed
        }
    }

    /// Releases a claim after a failure that provably created nothing. An
    /// ambiguous outcome deliberately never calls this.
    private func releaseIdempotencyKey(_ key: String?, bindingID: UUID, operation: Operation) async {
        guard let key else { return }
        _ = try? await metadata.update { state in
            state.resourceMutationKeys.removeAll { $0.key == key && $0.bindingID == bindingID && $0.operation == operation.rawValue }
        }
    }

    private func recordIdempotencyOutcome(_ key: String, bindingID: UUID, operation: Operation, resourceID: String?, effect: String) async {
        _ = try? await metadata.update { state in
            guard let index = state.resourceMutationKeys.firstIndex(where: { $0.key == key && $0.bindingID == bindingID && $0.operation == operation.rawValue }) else { return }
            let existing = state.resourceMutationKeys[index]
            state.resourceMutationKeys[index] = ResourceMutationKey(id: existing.id, key: existing.key, bindingID: existing.bindingID, operation: existing.operation, requestDigest: existing.requestDigest, at: existing.at, resourceID: resourceID, effect: effect)
        }
    }

    private func completeResourceKnown(_ request: ActionRequest, digest: String, correlationID: UUID, connectionID: UUID?, decision: AuditDecision, result: String, grantID: UUID?, resourceID: String?, effect: String?) async throws {
        try await persistResourceReceipt(request, digest: digest, correlationID: correlationID, decision, result, grantID: grantID, resourceID: resourceID, effect: effect)
        try? await append(request, connectionID: connectionID, decision, result)
    }

    private func persistResourceReceipt(_ request: ActionRequest, digest: String, correlationID: UUID, _ decision: AuditDecision, _ result: String, grantID: UUID?, resourceID: String?, effect: String?) async throws {
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: correlationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: request.bindingID, operation: request.operation.rawValue, requestDigest: digest, decision: decision, result: Redactor.safeError(result), grantID: grantID, resourceID: resourceID, effect: effect.map(Redactor.safeError)))
    }



    private func readResolution(_ state: VaultageMetadata, request: ActionRequest) throws -> ReadResolution {
        guard let binding = state.bindings.first(where: { $0.id == request.bindingID }),
              binding.projectID == request.projectID,
              binding.environmentID == request.environmentID,
              binding.allowedOperations.contains(request.operation),
              let project = state.projects.first(where: { $0.id == request.projectID }),
              let environment = state.environments.first(where: { $0.id == request.environmentID }),
              environment.projectID == project.id,
              let connection = state.connections.first(where: { $0.id == binding.connectionID }),
              connection.provider == request.operation.provider,
              let item = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
              item.provider == connection.provider,
              MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil
        else { throw VaultageError.policyDenied("This action is not permitted by the selected binding.") }
        return ReadResolution(project: project, environment: environment, binding: binding, connection: connection, item: item)
    }

    /// RP-07. Length-prefixed fields, not a `|`-joined string: `principalID` is
    /// provider-supplied text and must not be able to impersonate several
    /// fields by containing the separator. See `CanonicalDigest`.
    private func readDigest(request: ActionRequest, resolution: ReadResolution) -> String {
        let evidence = resolution.connection.verification
        return CanonicalDigest.hex([
            "vaultage.read.digest",
            request.projectID.uuidString,
            request.environmentID.uuidString,
            request.bindingID.uuidString,
            resolution.connection.id.uuidString,
            resolution.item.id.uuidString,
            resolution.item.keychainAccount,
            resolution.item.credentialVersion?.uuidString ?? "none",
            evidence?.providerContractRevision ?? "none",
            "\(evidence?.verifiedAt.timeIntervalSince1970 ?? 0)",
            evidence?.principalID ?? "unknown",
            // D44a. The region names the host this read will reach, so it is
            // part of what the human approved. `primary` rather than an empty
            // string keeps the encoding injective.
            resolution.connection.region ?? "primary",
            request.operation.rawValue
        ])
    }

    private func validateDestination(_ value: CloudflareWorkerDestination) throws {
        guard value.accountID.utf8.count <= 32, value.accountID.range(of: "^[A-Za-z0-9]+$", options: .regularExpression) != nil, value.scriptName.utf8.count <= 128, value.scriptName.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil, !value.scriptName.contains("..") else { throw VaultageError.invalidInput("The bound Cloudflare account or Worker name is invalid.") }
    }

    /// Reconciles persisted pause state while holding MetadataStore's
    /// cross-process lock, then verifies the exact connection requested by the
    /// binding is active. Account failures are deliberately Free, never Pro.
    private func requireActiveManagedConnection(_ connectionID: UUID) async throws {
        let entitlement: AccountEntitlement
        do { entitlement = try await accountClient.currentEntitlement() }
        catch { entitlement = .free }
        let state = try await metadata.update { state in
            connectionPolicy.applies(entitlement: entitlement, to: &state)
        }
        guard let connection = state.connections.first(where: { $0.id == connectionID }) else {
            throw VaultageError.policyDenied("The selected connection no longer exists.")
        }
        if let reason = connectionPolicy.deniedMessage(for: connection) {
            throw VaultageError.policyDenied(reason)
        }
    }

    /// D19. The only thing `grant` changes is the freshness ceiling: a grant
    /// that is active and already proved it covers this exact request keeps the
    /// verification the human approved it with current for the grant's
    /// remaining duration, instead of fifteen minutes. Every other condition —
    /// the connection being verified at all, the provider contract revision,
    /// the credential version, the Keychain account, the provider's own expiry
    /// and the attested capability — is unchanged and is still checked against
    /// freshly loaded state on each of this method's three calls per action.
    /// `nil`, and a grant that does not open a ceiling, both fall back to the
    /// fifteen-minute rule.
    private func requireCurrentVerification(connection: Connection, item: VaultItem, operation: Operation, grant: Grant? = nil) throws {
        let instant = now()
        guard connection.state == .verified,
              let evidence = connection.verification,
              evidence.providerContractRevision == ConnectionVerification.contractRevision(for: connection.provider),
              evidence.permits(operation, item: item, provider: connection.provider, at: instant, freshUntil: grant?.verificationFreshnessCeiling(for: evidence, at: instant))
        else { throw VaultageError.policyDenied("This connection lacks current server verification for \(operation.rawValue). Verify it before using the binding.") }
    }

    /// RP-08. The principal is provider-supplied text and it lands in the body
    /// of a security-critical `NSAlert` that also carries the "Client:" line and
    /// the sentence about credentials never being returned. The adapters bound
    /// it at the source; this clamps and strips it again at the sink, the way
    /// `ClientEnrollment.sanitizedDisplayName` already does for the one other
    /// human-chosen string on that sheet, so no evidence value can reshape the
    /// sheet with newlines or length.
    private func providerEvidenceDescription(_ connection: Connection) -> String {
        guard let evidence = connection.verification else { return "No provider identity evidence is available." }
        if let principal = (evidence.principalLabel ?? evidence.principalID).map(Self.sheetSafeEvidence) , !principal.isEmpty {
            return "Provider evidence: \(principal). Local connection labels are not identity."
        }
        return "Provider principal and full scopes are unknown for this fixed capability; the local connection label is not identity."
    }

    private static func sheetSafeEvidence(_ value: String) -> String {
        let stripped = value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0) }
        return String(String.UnicodeScalarView(stripped.prefix(128)))
    }

    /// A pending durable receipt is completed exactly once on every known
    /// post-pending terminal path. Metadata activity is a secondary projection
    /// and cannot change the durable outcome.
    private func completeKnown(_ request: ActionRequest, digest: String, correlationID: UUID, connectionID: UUID?, decision: AuditDecision, result: String, grantID: UUID? = nil) async throws {
        try await persistReceipt(request, digest: digest, correlationID: correlationID, decision, result, grantID: grantID)
        try? await append(request, connectionID: connectionID, decision, result)
    }

    private func terminalDecision(for error: Error) -> AuditDecision {
        if let error = error as? VaultageError {
            switch error {
            case .approvalDenied: return .denied
            case .policyDenied: return .blocked
            default: return .failed
            }
        }
        return .failed
    }

    private func append(_ request: ActionRequest, connectionID: UUID?, _ decision: AuditDecision, _ result: String) async throws {
        try await audit.append(AuditEvent(projectID: request.projectID, environmentID: request.environmentID, connectionID: connectionID, operation: request.operation.rawValue, decision: decision, result: Redactor.safeError(result)))
    }
    private func persistReceipt(_ request: ActionRequest, digest: String, correlationID: UUID, _ decision: AuditDecision, _ result: String, grantID: UUID? = nil) async throws {
        try await receipts.append(DurableReceipt(eventID: UUID(), correlationID: correlationID, at: .now, projectID: request.projectID, environmentID: request.environmentID, bindingID: request.bindingID, operation: request.operation.rawValue, requestDigest: digest, decision: decision, result: Redactor.safeError(result), grantID: grantID))
    }
}


private struct ReadResolution: Sendable {
    let project: Project; let environment: Environment; let binding: Binding; let connection: Connection; let item: VaultItem
}

/// BL-091. Everything a provider resource operation names: the same five
/// records a read names, plus the bound scope and — for the two operations that
/// write a value into a provider's secret store — the authorized source item.
private struct ResourceResolution: Sendable {
    let project: Project; let environment: Environment; let binding: Binding; let connection: Connection; let item: VaultItem
    let scope: ProviderResourceScope
}

/// BL-074/BL-073. The records a provisioning conversation or a resource
/// creation names. `managingItem` is the connection's own credential — the one
/// that must itself be allowed to create tokens — never the created value.
// MARK: - BL-094 delivery internals

/// Everything one delivery names, resolved from local records. The container
/// and the store come from the binding; nothing here came from a caller except
/// the destination's name and target, and both have been validated.
private struct DeliveryResolution: Sendable {
    let project: Project
    let environment: Environment
    let binding: Binding
    let connection: Connection
    /// The vault item holding the credential that is allowed to write the store.
    let destinationItem: VaultItem
    /// The vault item whose value is delivered.
    let sourceItem: VaultItem
    let store: SecretStore
    let scope: ProviderResourceScope
    let destination: DeliveryDestination
    /// BL-051's immutable Worker destination, for the Cloudflare path only.
    let cloudflareDestination: CloudflareWorkerDestination?
    /// D71. The door this delivery came through, and — for the agent's door —
    /// the "Client:" line naming who asked, as the sheet shows it.
    let door: DeliveryDoor
    let requester: String?
    /// The enrolled client's id behind that line, when it was enrolled: a
    /// digest term, and what the ledger row keeps.
    let requesterClientID: UUID?

    /// The operation named on the sheet and in the receipt before the preflight
    /// has spoken: the create-shaped one, because that is the wider statement
    /// of what may happen and the sheet says "creating it or replacing what is
    /// there" either way.
    var writeOperationIfNew: Operation { store.deliveryOperations[0] }

    /// The operation for a destination that already exists. The same one for a
    /// store whose route does not distinguish, which is Cloudflare's case.
    var writeOperationForExisting: Operation { store.deliveryOperations.count > 1 ? store.deliveryOperations[1] : store.deliveryOperations[0] }
}

/// One page of a secret store's entry **names**, and nothing else. It is built
/// from `ResourceOperationResult.items`, which the value-stripping adapters
/// produce, so there is no field here a value could be in.
private struct DeliveryStoreListing: Sendable {
    enum Presence: Sendable { case present, absent, truncated }

    let store: SecretStore
    let items: [ResourceOperationItem]
    /// The provider's own count, which may exceed the projected page.
    let count: Int

    /// Whether this page reports the destination. A page that is **truncated**
    /// answers `truncated` rather than `absent`, because "we did not see it in
    /// the first 25" is not "it is not there", and treating it as absence would
    /// mark a perfectly good deployment unverified.
    func presence(of destination: DeliveryDestination) -> Presence {
        if matching(destination) != nil { return .present }
        return count > items.count ? .truncated : .absent
    }

    /// The provider's identifier for an existing entry, when the store has one.
    /// This is what decides create versus update.
    func identifier(for destination: DeliveryDestination) -> String? {
        guard store.returnsIdentifier else { return nil }
        return matching(destination)?.id
    }

    private func matching(_ destination: DeliveryDestination) -> ResourceOperationItem? {
        items.first { item in
            // Cloudflare's projection puts the secret's name in both fields;
            // Vercel's puts the variable's key in `label` and its id in `id`.
            guard item.label == destination.name || (!store.returnsIdentifier && item.id == destination.name) else { return false }
            guard let target = destination.target else { return true }
            // A Vercel variable exists once per target, and the projection
            // reports its targets joined with "+". A row that reports none is
            // not a match for a specific target: guessing would let a preview
            // variable be replaced under a production approval.
            guard let targets = item.attributes["targets"] else { return false }
            return targets.split(separator: "+").contains(Substring(target.rawValue))
        }
    }
}

public extension SecretStore {
    /// The largest value this store accepts, as the provider documents it.
    /// Cloudflare's Worker secret limit is 5 KB (BL-051). Vercel allows 64 KB
    /// for **all** of a deployment's environment variables together, so no
    /// single one can be larger (docs, "Environment variable size", read
    /// 2026-09-21); Vaultage stops at 60 KiB so a value at the limit still
    /// leaves room for the deployment's other variables. Functions and
    /// middleware on the `edge` runtime take only 5 KB per variable, which is
    /// the deployment's runtime and not something the store can see.
    var maximumValueBytes: Int {
        switch self {
        case .cloudflareWorkerSecret: 5 * 1024
        case .vercelEnvironmentVariable: 60 * 1024
        // GitHub: "Secrets are limited to 48 KB in size" (docs.github.com,
        // Actions secrets reference, read 2026-09-21). The sealed body is
        // larger — 48 bytes of overhead, then base64 — and is built to fit.
        case .githubActionsSecret: 48 * 1024
        }
    }

    /// When the delivered value starts being used — immediately for a Worker,
    /// at the next build for Vercel, for the next job on GitHub — which is the
    /// sentence the human most needs.
    var deploymentSentence: String {
        switch self {
        case .cloudflareWorkerSecret: CredentialDeliveryDisclosure.immediateDeploymentSentence
        case .vercelEnvironmentVariable: CredentialDeliveryDisclosure.deploymentNeededSentence
        case .githubActionsSecret: CredentialDeliveryDisclosure.nextWorkflowRunSentence
        }
    }
}

private struct ProvisioningResolutionRecords: Sendable {
    let project: Project; let environment: Environment; let connection: Connection; let managingItem: VaultItem
}

public struct ProjectStatus: Codable, Sendable { public let id: UUID; public let name: String; public init(id: UUID, name: String) { self.id = id; self.name = name } }
public struct EnvironmentStatus: Codable, Sendable { public let id: UUID; public let projectID: UUID; public let name: String; public init(id: UUID, projectID: UUID, name: String) { self.id = id; self.projectID = projectID; self.name = name } }
public struct RuntimeSourceStatus: Codable, Sendable { public let id: UUID; public let label: String; public init(id: UUID, label: String) { self.id = id; self.label = label } }
public struct WorkerDestinationStatus: Codable, Sendable { public let accountID: String; public let scriptName: String; public let destinationClass: String; public init(accountID: String, scriptName: String, destinationClass: String) { self.accountID = accountID; self.scriptName = scriptName; self.destinationClass = destinationClass } }
/// BL-091. The bound provider resource a binding is scoped to, as identifiers
/// and one label. Never a credential, never a URL.
public struct ResourceScopeStatus: Codable, Sendable { public let kind: String; public let label: String; public let accountID: String?; public let zoneID: String?; public let scriptName: String?; public let projectID: String?; /* BL-128: a GitHub `owner/name`. */ public let repository: String?; public init(kind: String, label: String, accountID: String? = nil, zoneID: String? = nil, scriptName: String? = nil, projectID: String? = nil, repository: String? = nil) { self.kind = kind; self.label = label; self.accountID = accountID; self.zoneID = zoneID; self.scriptName = scriptName; self.projectID = projectID; self.repository = repository } }
public struct BindingStatus: Codable, Sendable { public let id: UUID; public let projectID: UUID; public let environmentID: UUID; public let provider: String; public let connection: String; public let operations: [String]; public let runtimeSources: [RuntimeSourceStatus]; public let workerDestination: WorkerDestinationStatus?; public let resourceScope: ResourceScopeStatus?; public init(id: UUID, projectID: UUID, environmentID: UUID, provider: String, connection: String, operations: [String], runtimeSources: [RuntimeSourceStatus] = [], workerDestination: WorkerDestinationStatus? = nil, resourceScope: ResourceScopeStatus? = nil) { self.id = id; self.projectID = projectID; self.environmentID = environmentID; self.provider = provider; self.connection = connection; self.operations = operations; self.runtimeSources = runtimeSources; self.workerDestination = workerDestination; self.resourceScope = resourceScope } }
/// BL-094 / D36. One deployed credential, value-free, as an agent sees it.
///
/// There is **no delivery tool and no rotation tool** for an agent: delivery is
/// a native-only class, and so is rotation. What an agent can do is *report*
/// what is deployed where, so it can tell a human "production on Vercel is
/// running five keys, four verified this morning and one never checked" without
/// ever being able to change it. Every field here is an identifier, a name, a
/// timestamp or a status word; the `fingerprint` is a digest of the source
/// item's identity and never of its value.
public struct DeploymentStatus: Codable, Sendable {
    public let projectID: UUID
    public let environmentID: UUID
    public let provider: String
    public let store: String
    public let destinationName: String
    public let target: String?
    public let scopeLabel: String
    public let sourceVaultItemID: UUID
    /// CC-H6. Which field of that item feeds this destination, by its stable
    /// wire name, or nil for an item that holds one value. A name like every
    /// other member here, and the reason an agent can say "production runs the
    /// secret half of this pair" without being able to touch either half.
    public let sourceField: String?
    public let fingerprint: String
    public let status: String
    public let deliveredAt: Date
    public let lastVerifiedAt: Date?
    public let expiresAt: Date?
    /// D71. `owner` or `agent`: which door wrote the row, and for the agent's
    /// the enrolled client that asked — so an agent reading its own status can
    /// tell what it delivered from what the owner did.
    public let requestedBy: String
    public let requestingClientID: UUID?
    public init(projectID: UUID, environmentID: UUID, provider: String, store: String, destinationName: String, target: String?, scopeLabel: String, sourceVaultItemID: UUID, sourceField: String? = nil, fingerprint: String, status: String, deliveredAt: Date, lastVerifiedAt: Date?, expiresAt: Date?, requestedBy: String = DeliveryDoor.owner.rawValue, requestingClientID: UUID? = nil) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.provider = provider
        self.store = store
        self.destinationName = destinationName
        self.target = target
        self.scopeLabel = scopeLabel
        self.sourceVaultItemID = sourceVaultItemID
        self.sourceField = sourceField
        self.fingerprint = fingerprint
        self.status = status
        self.deliveredAt = deliveredAt
        self.lastVerifiedAt = lastVerifiedAt
        self.expiresAt = expiresAt
        self.requestedBy = requestedBy
        self.requestingClientID = requestingClientID
    }
}

public struct VaultageStatus: Codable, Sendable {
    public let projects: [ProjectStatus]
    public let environments: [EnvironmentStatus]
    public let bindings: [BindingStatus]
    /// BL-094. What Vaultage has delivered into each environment's provider
    /// secret stores. Read-only, value-free, and reported under the same single
    /// approval `vaultage_status` already takes — the sheet says so.
    public let deployments: [DeploymentStatus]
    public let message: String
    public init(projects: [ProjectStatus], environments: [EnvironmentStatus], bindings: [BindingStatus], deployments: [DeploymentStatus] = [], message: String) {
        self.projects = projects
        self.environments = environments
        self.bindings = bindings
        self.deployments = deployments
        self.message = message
    }
}

public enum Redactor {
    public static func publicError(_ error: Error) -> String {
        guard let vaultage = error as? VaultageError else { return "Vaultage operation failed." }
        return safeError(vaultage.localizedDescription)
    }
    /// BL-117 (D51) §5.1, finding CC-L1 — **five more needles, and a longer
    /// bite for `authorization`**.
    ///
    /// The pattern this replaces was
    /// `(?i)(authorization|token|api[_-]?key|secret)\\s*[:=]\\s*[^\\s,]+`, which
    /// stops at the first whitespace **or comma**. An AWS `Authorization` value
    /// is
    /// `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`, so that
    /// alternation consumed the algorithm name and left `Signature=` intact —
    /// the one part of the header worth redacting. And `code=`, `state=` and
    /// `Signature=` were not needles at all, so an OAuth error string carrying
    /// an authorization code or a `state` passed through whole.
    ///
    /// Two changes, both owed **before the first signed request** because that
    /// is the first moment `Signature=` exists anywhere in the product:
    ///
    ///   1. `signature`, `code`, `state`, `assertion` and `verifier` join the
    ///      alternation. `code` and `state` are short and ordinary English
    ///      words, which is why they are matched only in the
    ///      `name=value` / `name: value` shape the pattern already requires —
    ///      the word "state" in a sentence is untouched, `state=abc123` is not.
    ///   2. An `authorization` match is redacted **to end of line** rather than
    ///      to the first comma, so a comma-separated header value is taken
    ///      whole. It is a separate pattern rather than a wider `[^\\s,]+`,
    ///      because widening the shared class would also make `token: a, b`
    ///      swallow an unrelated clause.
    ///
    /// This is a redactor of last resort, not a control: the controls are that
    /// no signature is ever a receipt field (§5.1), that the two-needle byte
    /// scan refuses a reply echoing one, and that `VaultSecret` never
    /// materialises a credential. This is what catches the string that reaches
    /// a human anyway.
    /// BL-117's Google Cloud slot (§7.3, §5.1) — **two more needles, and both
    /// are shapes rather than names.**
    ///
    /// Every needle above this slot is `name=value`: the redactor finds a
    /// *label* and eats what follows it. That is the shape a secret leaks in
    /// when a caller built the string. It is not the shape the two secrets this
    /// slot introduces leak in, because both are recognisable on sight and both
    /// travel without a label:
    ///
    ///   1. **A PEM private key.** It arrives as armour and base64, in a
    ///      diagnostic that quoted a file or a field. The match runs **to the
    ///      end of the string** rather than to the end of the block, and
    ///      deliberately: `safeError` clips its input to 240 characters, which
    ///      is shorter than any PEM, so a block-shaped pattern would never find
    ///      its `-----END` and would match nothing at all. Losing the tail of a
    ///      diagnosis is the right trade against leaving key material in one.
    ///   2. **A JSON Web Token.** Three base64url segments, the first beginning
    ///      `eyJ` — which is `{"` — is what an assertion and a Microsoft access
    ///      token both look like, and neither needs a `name=` in front of it to
    ///      be quoted into an error. The pattern is specific enough that it
    ///      cannot fire on ordinary provider text: a bare word does not have two
    ///      dots and a `{"` prefix.
    ///
    /// `private[_-]?key` joins the name alternation too, because the key file's
    /// own field name is `private_key` and `api[_-]?key` does not cover it.
    ///
    /// This is still a redactor of last resort, not a control. The controls are
    /// that no key, assertion or token is ever a receipt field (§5.1), that the
    /// **three**-needle byte scan refuses a reply echoing one — including, since
    /// this slot, a reply echoing part of a key — and that `VaultSecret` never
    /// materialises a credential. This is what catches the string that reaches a
    /// human anyway.
    public static func safeError(_ error: String) -> String {
        let clipped = String(error.prefix(240))
        let patterns = [
            "(?i)bearer\\s+[A-Za-z0-9._~+/-]+",
            // The `authorization` header value, taken to end of line: an AWS
            // SigV4 value is three comma-separated parts and the signature is
            // the last of them.
            "(?i)authorization\\s*[:=].*",
            // A PEM private key, taken to the end of the clipped string. See the
            // note above for why it is not bounded at `-----END`.
            "(?i)-----BEGIN[A-Z ]*PRIVATE KEY-----[\\s\\S]*",
            // A JSON Web Token: header.payload.signature, base64url, with a
            // header that begins `{"`.
            "eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
            "(?i)(token|api[_-]?key|private[_-]?key|secret|signature|code|state|assertion|verifier)\\s*[:=]\\s*[^\\s,]+"
        ]
        return patterns.reduce(clipped) { partial, pattern in
            (try? NSRegularExpression(pattern: pattern)).map { regex in
                regex.stringByReplacingMatches(in: partial, range: NSRange(partial.startIndex..., in: partial), withTemplate: "[redacted]")
            } ?? partial
        }
    }
}
