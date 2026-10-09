import Foundation

// BL-136 steps 2–5 (D70 amendment 2) — the pairing ceremony on the broker.
//
// `vaultage_pair`, two calls. The first, from an unpaired connection with a
// known origin, keeps one pending pairing for this connection in memory and
// answers with the code and one instruction. The second raises the pairing
// sheet on the Mac — the person types the code their agent showed and gives
// the agent a name — then Touch ID, then the binding. Pairing grants nothing:
// it gives the agent its name on every sheet and receipt, its identification
// path, and its own revoke. A client-scoped grant still takes its own sheet.
//
// Where the code exists: the pending record here, and the first call's result
// to the requesting agent. Never in a receipt, the audit log, stderr,
// metadata, another connection's result, or on the sheet.

/// The agent's request: the first call has `confirm` false, the second true.
public struct AgentPairingRequest: Codable, Sendable, Hashable {
    public let confirm: Bool
    public init(confirm: Bool) { self.confirm = confirm }
}

/// What the agent is told.
public struct AgentPairingOutcome: Codable, Sendable, Hashable {
    public enum Status: String, Codable, Sendable { case codeIssued = "code_issued", paired }

    public let status: Status
    /// Only on `codeIssued`: the code, as `XXXX-XXXX`, for the agent to show
    /// the person at the Mac. The one place it leaves the broker.
    public let code: String?
    public let expiresAt: Date?
    /// On `paired`: the name the person gave the agent, and how it is identified.
    public let clientName: String?
    public let identification: String?
    public let nextStep: String

    public init(status: Status, code: String? = nil, expiresAt: Date? = nil, clientName: String? = nil, identification: String? = nil, nextStep: String) {
        self.status = status
        self.code = code
        self.expiresAt = expiresAt
        self.clientName = clientName
        self.identification = identification
        self.nextStep = nextStep
    }
}

/// What the pairing sheet shows. The code is **not** on it: the person types
/// the code their agent showed them.
public struct PairingSheetDetails: Codable, Sendable, Hashable {
    public let clientLine: String
    public let folderLine: String
    /// The strength sentence, on the sheet as on every later sheet.
    public let identification: String
    public let suggestedName: String
    public let attemptsRemaining: Int
    public let expiresAt: Date

    public init(clientLine: String, folderLine: String, identification: String, suggestedName: String, attemptsRemaining: Int, expiresAt: Date) {
        self.clientLine = clientLine
        self.folderLine = folderLine
        self.identification = identification
        self.suggestedName = suggestedName
        self.attemptsRemaining = attemptsRemaining
        self.expiresAt = expiresAt
    }
}

/// What the person typed on the sheet. Nil from the presenter means denied.
public struct PairingSheetReply: Codable, Sendable, Hashable {
    public let typedCode: String
    public let name: String
    public init(typedCode: String, name: String) { self.typedCode = typedCode; self.name = name }
}

/// The presenter seam: the client process draws the sheet the broker composed
/// and returns what the person typed, or nil.
public typealias PairingSheetPresenter = @Sendable (PairingSheetDetails) async -> PairingSheetReply?

extension VaultageBroker {
    /// BL-136 step 2/3. Resolves this connection's identity: the OS-derived
    /// origin's Keychain binding first (S7), then the legacy bearer credential
    /// for records that still exist. Remembers the origin for `pair`.
    @discardableResult
    public func identify(origin: AgentConnectionOrigin?, presenting credential: ClientCredential?) async -> ClientIdentity {
        connectionOrigin = origin
        if let origin, origin.origin.canPair,
           let bound = try? agentBindings.clientID(forDigest: origin.origin.digest),
           let state = try? await metadata.load(),
           let client = state.enrolledClients.first(where: { $0.id == bound }),
           client.isActive, client.kind == .pairedInstance {
            let identity = ClientIdentity.enrolled(id: client.id, name: client.displayName, generation: client.generation, identification: origin.origin.strength)
            presentedClient = identity
            return identity
        }
        return await identify(presenting: credential)
    }

    /// Test-visible: whether a pairing is pending on this connection.
    public func hasPendingPairing() -> Bool { pendingPairing != nil }

    /// `vaultage_pair`.
    public func pair(_ request: AgentPairingRequest) async throws -> AgentPairingOutcome {
        guard let origin = connectionOrigin?.origin, origin.canPair else {
            throw VaultageError.policyDenied(AgentIdentificationStrength.none.sentence)
        }
        if presentedClient.isEnrolled, presentedClient.identification != nil {
            throw VaultageError.policyDenied("This agent is already paired as \(presentedClient.name ?? "an agent"). Revoke it in the Vaultage app to pair it again.")
        }
        let now = now()
        guard request.confirm else {
            // One pending pairing per connection; a new request replaces it.
            let pending = PendingPairing(origin: origin, createdAt: now)
            pendingPairing = pending
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .pending, result: "A pairing was requested by \(origin.clientLine) in \(origin.folderLine). \(origin.strength.sentence)"))
            return AgentPairingOutcome(
                status: .codeIssued,
                code: pending.code.display,
                expiresAt: pending.expiresAt,
                nextStep: "Show this code to the person at the Mac, exactly as written, and ask them to type it on the Vaultage pairing sheet. Then call vaultage_pair again with confirm set to true; the sheet opens on the Mac, they type the code, name this agent and confirm with Touch ID. The code expires in ten minutes and allows five wrong entries."
            )
        }
        guard var pending = pendingPairing else {
            throw VaultageError.invalidInput("No pairing is pending on this connection. Call vaultage_pair without confirm first to get a code.")
        }
        guard pending.origin == origin else {
            pendingPairing = nil
            throw VaultageError.policyDenied("The pairing request no longer matches this connection.")
        }
        guard !pending.isExpired(at: now) else {
            pendingPairing = nil
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .blocked, result: "The pairing code expired before it was typed."))
            throw VaultageError.policyDenied("The pairing code expired. Call vaultage_pair without confirm to get a new one.")
        }
        guard let presenter = pairingSheet else {
            throw VaultageError.unsupported("This Vaultage composition cannot present a pairing sheet.")
        }
        let details = PairingSheetDetails(
            clientLine: origin.clientLine,
            folderLine: origin.folderLine,
            identification: origin.strength.sentence,
            suggestedName: origin.suggestedName,
            attemptsRemaining: PendingPairing.attemptBudget - pending.wrongAttempts,
            expiresAt: pending.expiresAt
        )
        guard let reply = await presenter(details) else {
            pendingPairing = nil
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .denied, result: "The pairing sheet was dismissed; nothing was paired."))
            throw VaultageError.approvalDenied
        }
        switch pending.check(typed: reply.typedCode, at: self.now()) {
        case .matched:
            break
        case let .wrong(remaining):
            pendingPairing = pending
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .denied, result: "The typed code did not match; \(remaining) attempt\(remaining == 1 ? "" : "s") left."))
            throw VaultageError.policyDenied("The code did not match. \(remaining) attempt\(remaining == 1 ? "" : "s") left; call vaultage_pair with confirm true to try again.")
        case .exhausted:
            pendingPairing = nil
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .blocked, result: "Five wrong codes; the pairing request was discarded."))
            throw VaultageError.policyDenied("The code did not match five times. The pairing request is over; call vaultage_pair without confirm to start again.")
        case .expired:
            pendingPairing = nil
            throw VaultageError.policyDenied("The pairing code expired. Call vaultage_pair without confirm to get a new one.")
        }
        guard let name = ClientEnrollment.sanitizedDisplayName(reply.name) ?? ClientEnrollment.sanitizedDisplayName(origin.suggestedName) else {
            throw VaultageError.invalidInput("A paired agent needs a name.")
        }
        // Touch ID, with the origin in the reason (S4). It gates a decision,
        // not a read, so the presence unlocks nothing and is spent at once.
        let authentication: OwnerAuthentication
        do {
            authentication = try await authenticator.authenticateOwner(reason: "Pair \(origin.clientLine) in \(origin.folderLine) with Vaultage as \"\(name)\"", unlocking: [])
        } catch {
            pendingPairing = nil
            try? await audit.append(AuditEvent(operation: "agent.pair", decision: .denied, result: "Owner authentication failed or was cancelled; nothing was paired."))
            throw error
        }
        authentication.invalidate()
        // The record, then the binding; a binding that cannot be written takes
        // the record with it, so no row ever exists without its binding.
        let client = try await metadata.updateResult { state in
            try ClientEnrollment.enrollPaired(displayName: name, origin: origin, now: self.now(), in: &state)
        }
        do {
            try agentBindings.bind(digest: origin.digest, clientID: client.id)
        } catch {
            _ = try? await metadata.update { state in state.enrolledClients.removeAll { $0.id == client.id } }
            pendingPairing = nil
            throw error
        }
        pendingPairing = nil
        presentedClient = .enrolled(id: client.id, name: client.displayName, generation: client.generation, identification: origin.strength)
        try? await audit.append(AuditEvent(operation: "agent.pair", decision: .approved, result: "Paired \"\(client.displayName)\" — \(origin.clientLine) in \(origin.folderLine). \(origin.strength.sentence)"))
        return AgentPairingOutcome(
            status: .paired,
            clientName: client.displayName,
            identification: origin.strength.sentence,
            nextStep: "This agent is paired and named on every approval. It has no standing permission: the owner can now grant it auto-allow for chosen environments in the Vaultage app, and each such grant takes its own approval and Touch ID."
        )
    }

    /// BL-136 step 5. Revokes a paired agent: the record, its Keychain binding
    /// and every grant keyed on it, in one transaction (S2), with the
    /// revocation anchor raised (audit H-08). A legacy-bearer record is
    /// revoked the same way; it has no binding to remove.
    @discardableResult
    public func revokeAgent(_ clientID: UUID) async throws -> EnrolledClient {
        let (client, revokedGrants, generation) = try await metadata.updateResult { state -> (EnrolledClient, [UUID], Int) in
            let client = try ClientEnrollment.revoke(clientID, now: self.now(), in: &state)
            var revoked: [UUID] = []
            for grant in state.grants where grant.scope.clientID == clientID && grant.revokedAt == nil {
                if (try? GrantPolicy.revoke(grant.id, now: self.now(), in: &state, signer: self.grantSigner)) != nil { revoked.append(grant.id) }
            }
            state.revocationGeneration += 1
            return (client, revoked, state.revocationGeneration)
        }
        try grantSigner.raiseRevocationWatermark(to: generation)
        if let digest = client.pairingDigest { try agentBindings.unbind(digest: digest) }
        for id in revokedGrants { await grantCache.invalidate(grantID: id) }
        if presentedClient.id == clientID { presentedClient = .unenrolled(.revoked) }
        try? await audit.append(AuditEvent(operation: "agent.revoke", decision: .blocked, result: "Revoked \"\(client.displayName)\"\(revokedGrants.isEmpty ? "" : " and ended \(revokedGrants.count) grant\(revokedGrants.count == 1 ? "" : "s") keyed on it"). No other agent was touched."))
        return client
    }

    /// Step 4 (S1). Whether the host instance this connection was launched
    /// from is still the same running process; a connection with no recorded
    /// host is not held to one.
    func hostInstanceStillRunning() -> Bool {
        guard let host = connectionOrigin?.host else { return true }
        return AgentOriginReader.isRunning(host)
    }
}
