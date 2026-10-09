import Foundation

/// BL-099 — the transport seam between the Mac's pure publication logic and the
/// control plane's routes (§6.2), plus the signed-decision wire shape (§4.2).
///
/// **A seam, not a layer.** Everything that decides anything is a pure function
/// over local records; this protocol carries bytes. That is what lets §9.2's
/// Mac suite assert the rules without a Worker, and what lets
/// `sheetIsNotBlockedWhenControlPlaneUnreachable` be true by construction: the
/// native sheet never awaits any of these.

// MARK: - The wire shapes

/// One pending's publication, as `POST /api/approvals` carries it.
public struct RemotePublicationEnvelope: Codable, Hashable, Sendable {
    public let pendingId: String
    public let header: RemoteRoutingHeader
    public let summaries: [Summary]

    public struct Summary: Codable, Hashable, Sendable {
        public let recipientDeviceId: String
        public let recipientThumbprint: String
        /// base64url of the whole envelope.
        public let ciphertext: String
        /// The raw envelope length, which migration 0007's CHECK constrains to
        /// the four permitted sizes.
        public let byteLength: Int
        /// P8's `issuedAt`, per recipient (BL-096 slice 2). The Worker stores it
        /// in `pending_summaries.sealed_at` and serves it back on the pending
        /// route, because the phone needs it to build the `info` that is also
        /// the AAD — and cannot read it out of the summary it has not opened.
        /// Sent on **both** `POST /api/approvals` and
        /// `POST /api/approvals/republish`, which carry the same envelope type.
        public let sealedAt: Int

        public init(_ sealed: RemoteSealedSummary) {
            self.recipientDeviceId = sealed.phoneDeviceID
            self.recipientThumbprint = sealed.recipientThumbprint
            self.ciphertext = RemoteBase64URL.encode(sealed.envelope)
            self.byteLength = sealed.envelope.count
            self.sealedAt = sealed.sealedAt
        }
    }

    public init(pendingId: String, header: RemoteRoutingHeader, sealed: [RemoteSealedSummary]) {
        self.pendingId = pendingId
        self.header = header
        self.summaries = sealed.sorted { $0.phoneDeviceID < $1.phoneDeviceID }.map(Summary.init)
    }
}

/// §4.2's stored decision, as the Mac fetches it from
/// `GET /api/approvals/:id/decision`.
///
/// **`approvalRequestDigest` and `summaryDigest` are not on the wire.** The
/// phone derives them; the Mac derives them; neither accepts the other's copy
/// and neither accepts the server's. `accountSubject` and `macDeviceId` are
/// likewise absent and filled by the Mac from its own state.
///
/// **`includedMutations` is on the wire and §4.2's example body does not show
/// it.** It has to be: it is a field of the signed preimage (§4.1, DB-H14) and
/// the Mac cannot reconstruct what the owner ticked from anything it holds.
/// §4.2's JSON is an abbreviated example rather than a field list — reported, so
/// a second implementer does not read the omission as a rule.
///
/// **`decidingDeviceId` is relay-supplied and is verified, not sourced**
/// (checklist 15, DB-M27). The Mac has no state saying which phone decided; it
/// learns it from `approval_decisions.device_id`, which the Worker derives from
/// the posting session and which a compromised Worker can write freely. §4.3
/// check 2 is what makes that safe, and `deciding_device_unrecognised` is why a
/// relay that renames the deciding device produces a *denial the owner can read*
/// rather than tampering copy.
public struct RemoteSignedDecision: Codable, Hashable, Sendable {
    /// §4.2: body ≤ 2 KiB.
    public static let maximumEncodedBytes = 2048

    public let decisionId: String
    public let decision: RemoteDecisionVerdict
    public let scope: RemoteDecisionScope
    public let scopeClientId: String?
    public let scopeProjectIds: [String]
    public let duration: RemoteDecisionDuration
    public let includeProduction: Bool
    public let typedEnvironmentName: String?
    public let includedMutations: [String]
    public let choiceId: String?
    public let issuedAt: Int
    public let expiresAt: Int
    public let apvThumbprint: String
    public let decidingDeviceId: String
    /// base64url, 64 raw bytes, `r ‖ s`.
    public let signature: String

    public init(decisionId: String, decision: RemoteDecisionVerdict, scope: RemoteDecisionScope, scopeClientId: String?, scopeProjectIds: [String], duration: RemoteDecisionDuration, includeProduction: Bool, typedEnvironmentName: String?, includedMutations: [String], choiceId: String?, issuedAt: Int, expiresAt: Int, apvThumbprint: String, decidingDeviceId: String, signature: String) {
        self.decisionId = decisionId
        self.decision = decision
        self.scope = scope
        self.scopeClientId = scopeClientId
        self.scopeProjectIds = scopeProjectIds
        self.duration = duration
        self.includeProduction = includeProduction
        self.typedEnvironmentName = typedEnvironmentName
        self.includedMutations = includedMutations
        self.choiceId = choiceId
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.apvThumbprint = apvThumbprint
        self.decidingDeviceId = decidingDeviceId
        self.signature = signature
    }

    public var signatureBytes: Data? {
        guard let bytes = RemoteBase64URL.decode(signature), bytes.count == 64 else { return nil }
        return bytes
    }

    /// The four fields the Mac fills from its **own** state, joined to the
    /// thirteen the wire carries, to produce the preimage §4.1 defines.
    ///
    /// The two digests come from the Mac's **retained** field list for the
    /// verified deciding device — never from the wire and never from a fresh
    /// rebuild (§3.2, §4.3 step 9a).
    public func payload(accountSubject: String, macDeviceId: String, summaryDigest: String, approvalRequestDigest: String) -> RemoteDecisionPayload {
        RemoteDecisionPayload(
            approvalRequestDigest: approvalRequestDigest,
            summaryDigest: summaryDigest,
            decision: decision,
            scope: scope,
            scopeClientId: scopeClientId,
            scopeProjectIds: scopeProjectIds,
            duration: duration,
            includeProduction: includeProduction,
            typedEnvironmentName: typedEnvironmentName,
            includedMutations: includedMutations,
            choiceId: choiceId,
            decisionId: decisionId,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            accountSubject: accountSubject,
            macDeviceId: macDeviceId,
            decidingDeviceId: decidingDeviceId,
            apvThumbprint: apvThumbprint
        )
    }

    /// Strict decoding: **unknown keys rejected** (§6.2), body bounded. The
    /// Worker applies the same rule to what it accepts; this is the Mac applying
    /// it to what it is served, because the relay is the party this whole design
    /// treats as hostile.
    public static func decode(_ data: Data) throws -> RemoteSignedDecision {
        guard data.count <= maximumEncodedBytes else {
            throw VaultageError.invalidInput("A decision body is at most \(maximumEncodedBytes) bytes.")
        }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw VaultageError.invalidInput("A decision body is a JSON object.")
        }
        let known: Set<String> = [
            "decisionId", "decision", "scope", "scopeClientId", "scopeProjectIds", "duration",
            "includeProduction", "typedEnvironmentName", "includedMutations", "choiceId",
            "issuedAt", "expiresAt", "apvThumbprint", "decidingDeviceId", "signature"
        ]
        let unknown = Set(object.keys).subtracting(known).sorted()
        guard unknown.isEmpty else {
            throw VaultageError.invalidInput("A decision body carried unknown key(s): \(unknown.joined(separator: ", ")).")
        }
        return try JSONDecoder().decode(RemoteSignedDecision.self, from: data)
    }
}

// MARK: - The seam

/// What the Mac asks of the control plane for remote approvals. One protocol, so
/// the self-tests drive a fake and the product drives `DeviceAccountClient`.
public protocol RemoteApprovalTransport: Sendable {
    /// `POST /api/approvals`. Publishing is best-effort and never blocks the
    /// native sheet (§3.7).
    func publishPending(_ envelope: RemotePublicationEnvelope) async throws

    /// `POST /api/approvals/republish`. **Batched**, ≤8 entries — a different
    /// quantity from the ≤16 retained-version cap (NEW-L1) — each entry an
    /// upsert that never creates a pending.
    func republishPendings(_ envelopes: [RemotePublicationEnvelope]) async throws

    /// `POST /api/approvals/:id/cancel`, origin device only. Issued
    /// **immediately on verification, before applying** (Q11 item 3), so the gap
    /// between the decision write and the cancel is not correlated with the
    /// outcome.
    func cancelPending(_ pendingID: String, reason: RemoteCancelReason) async throws

    /// `GET /api/approvals/:id/decision`. `nil` while the pending is still open
    /// (the route answers `204`).
    func fetchDecision(for pendingID: String) async throws -> RemoteSignedDecision?
}

/// What a publication attempt did, so the caller can record it without
/// inspecting an error.
public enum RemotePublishOutcome: Equatable, Sendable {
    case published
    /// §3.6 or §3.7 said this request does not mirror. Not a failure.
    case notMirrored(RemoteMirrorEligibility.Refusal)
    /// The transport failed. **The sheet is unaffected and the request is simply
    /// not mirrored** (§3.7); a publish failure is never an approval failure.
    case transportUnavailable(String)
    /// This OS cannot perform §5.3's construction.
    case sealingUnavailable(String)
}

// MARK: - The shipped client

/// `DeviceAccountClient` is the one place a device route is spoken, and remote
/// approvals do not get a second one: the same `Authorization: Device <token>`
/// header, the same fresh DPoP proof per request bound to the exact method and
/// absolute URL, the same origin pin, and the same `401` handling that clears a
/// rejected session and its cached lease.
///
/// **The Mac's single `sig` key serves every route here.** §2.2's `sig`/`sigw`
/// split is the *phone's*, and exists because a `.userPresence` Enclave key
/// cannot be exercised in a background task (DB-H10). The Mac has no such
/// constraint and no such second key.
extension DeviceAccountClient: RemoteApprovalTransport {
    public func publishPending(_ envelope: RemotePublicationEnvelope) async throws {
        _ = try await remoteApprovalRequest(path: "/api/approvals", method: "POST", body: try remoteJSON(envelope), accepting: [201, 200])
    }

    public func republishPendings(_ envelopes: [RemotePublicationEnvelope]) async throws {
        guard !envelopes.isEmpty else { return }
        guard envelopes.count <= RemoteOpenPendingLimits.republishBatchSize else {
            throw AccountClientError.invalidResponse
        }
        _ = try await remoteApprovalRequest(path: "/api/approvals/republish", method: "POST", body: try remoteJSON(["pendings": envelopes]), accepting: [200])
    }

    public func cancelPending(_ pendingID: String, reason: RemoteCancelReason) async throws {
        let id = try remoteApprovalIdentifier(pendingID)
        _ = try await remoteApprovalRequest(path: "/api/approvals/\(id)/cancel", method: "POST", body: try remoteJSON(["reason": reason.rawValue]), accepting: [200, 409, 410])
    }

    public func fetchDecision(for pendingID: String) async throws -> RemoteSignedDecision? {
        let id = try remoteApprovalIdentifier(pendingID)
        let response = try await remoteApprovalRequest(path: "/api/approvals/\(id)/decision", method: "GET", body: nil, accepting: [200, 204])
        // `204` while pending. An empty body at `200` is a malformed answer, not
        // an absent decision, and is refused rather than read as "no decision".
        guard response.statusCode == 200 else { return nil }
        return try RemoteSignedDecision.decode(response.body)
    }

}

/// §6.2's four connect routes, on the same client and the same rules: one
/// device session, a fresh DPoP proof bound to the exact method and absolute
/// URL, the pinned origin, and no second way to speak a device route.
extension DeviceAccountClient: RemoteConnectTransport {
    public func createConnectRequest(_ request: RemoteConnectRequestCreation) async throws -> String {
        let response = try await remoteApprovalRequest(path: "/api/connect-requests", method: "POST", body: try remoteJSON(request), accepting: [201, 200])
        struct Created: Decodable { let id: String }
        // **The echo is compared, never adopted** (slice 3 step (b)). The id is
        // already inside the sealed summary, inside P9's `info` and inside the
        // context the phone will sign; a Worker answering with a different one
        // is a Worker substituting the identifier the owner's signature covers.
        guard let created = try? JSONDecoder().decode(Created.self, from: response.body),
              let echoed = UUID(uuidString: created.id),
              let minted = UUID(uuidString: request.id),
              echoed == minted
        else {
            throw AccountClientError.invalidResponse
        }
        return request.id
    }

    /// **`404` is `nil`, and `nil` is a second consume** (§5.4). The route is
    /// one `DELETE … RETURNING`, so the absence of a row *is* the answer; it is
    /// never read as "try again".
    public func consumeEnvelope(connectRequestID: String) async throws -> RemoteConsumedEnvelope? {
        let id = try remoteApprovalIdentifier(connectRequestID)
        let response = try await remoteApprovalRequest(path: "/api/connect-requests/\(id)/envelope/consume", method: "POST", body: nil, accepting: [200, 404, 410])
        guard response.statusCode == 200 else { return nil }
        // §5.6 step 1 — bound the response **before parsing**.
        guard response.body.count <= RemoteConsumedEnvelope.maximumResponseBytes else {
            throw AccountClientError.invalidResponse
        }
        guard let consumed = try? JSONDecoder().decode(RemoteConsumedEnvelope.self, from: response.body) else {
            throw AccountClientError.invalidResponse
        }
        return consumed
    }

    public func reportConnectResult(connectRequestID: String, result: RemoteConnectResult) async throws {
        let id = try remoteApprovalIdentifier(connectRequestID)
        _ = try await remoteApprovalRequest(path: "/api/connect-requests/\(id)/result", method: "POST", body: try remoteJSON(result), accepting: [200, 409, 410])
    }
}

private extension DeviceAccountClient {
    /// The pending id becomes part of the path and therefore part of the DPoP
    /// proof's `htu`, so it is validated against its own shape before it reaches
    /// a URL — the same rule `revokeAPIToken` applies to a token id.
    private func remoteApprovalIdentifier(_ value: String) throws -> String {
        guard let uuid = UUID(uuidString: value) else { throw AccountClientError.invalidResponse }
        return uuid.uuidString.lowercased()
    }

    private func remoteJSON<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(value) } catch { throw AccountClientError.invalidResponse }
    }

    /// `deviceRouteRequest` is the seam in `AccountClient.swift`: same session,
    /// same fresh DPoP proof, same pinned origin, and the same `401` handling
    /// that clears a rejected session and its cached lease.
    private func remoteApprovalRequest(path: String, method: String, body: Data?, accepting: Set<Int>) async throws -> AccountHTTPResponse {
        try await deviceRouteRequest(path: path, method: method, body: body, accepting: accepting)
    }
}
