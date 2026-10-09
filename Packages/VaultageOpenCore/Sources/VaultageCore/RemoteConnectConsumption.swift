import CryptoKit
import Foundation

/// BL-099 slice 2 — **§5.6, what the Mac does on receipt**, as one ordered
/// function over seams.
///
/// Nine steps, in the document's order, all failing closed. The ordering is the
/// security property, not a style: the presence check precedes the consume so a
/// locked Mac never burns the one envelope it cannot store; the consume precedes
/// nothing except storage ("consume late, not early", §5.4 / Q5); the signature
/// check precedes the contract check so an unsigned plaintext is never parsed
/// for meaning; and the Keychain write precedes verification so a failed
/// verification has something to **delete** rather than something to leak.

// MARK: - Seams

/// §3.7.1's presence, as the one thing §5.6 consults before touching custody.
///
/// It is asked **before** the Keychain, never after: `presence_unavailable` is
/// the answer to "LocalAuthentication cannot prompt here", and finding that out
/// by attempting a `.userPresence` read is exactly the failure spike fact 4
/// says not to produce.
public protocol RemotePresenceProbe: Sendable {
    func currentPresence() -> RemotePresence
}

extension RemotePresence {
    /// **Can LocalAuthentication prompt right now?** (spike fact 4 = §12
    /// platform fact 5.)
    ///
    /// `unknown` is treated as *cannot* — the fail-closed reading. §3.7.1 keeps
    /// `unknown → alert` for routing, which is a disclosure decision; this is a
    /// custody decision, and a build whose detection silently never works must
    /// not be a build that silently attempts presence-gated reads on a locked
    /// screen.
    public var canPromptForPresence: Bool {
        switch self {
        case .active, .idle: true
        case .locked, .asleep, .unknown: false
        }
    }
}

/// What the consumption path needs from custody, so the self-tests drive a fake
/// vault and the product drives `KeychainVault` through the broker.
public protocol RemoteConnectCustody: Sendable {
    /// §5.6 step 5 — the **ordinary BL-005 path**, unchanged: this ticket adds
    /// no second way to write a credential.
    func save(_ secret: VaultSecret, account: String) throws
    /// §5.6 step 8's delete-on-failure.
    func delete(account: String) throws
}

// MARK: - Inputs and outcome

public struct RemoteConnectConsumptionRequest: Sendable {
    public let connectRequestID: String
    public let accountSubject: String
    public let macDeviceID: String
    public let phoneDeviceID: String
    public let providerSlug: String
    public let capability: String
    public let connectionLabel: String
    /// The Mac's **own pinned** `kex` thumbprint. Never the value the relay
    /// returned beside the ciphertext.
    public let macKexThumbprint: String
    public let keychainAccount: String
    public let credentialVersion: UUID
    public let expiresAt: Date

    public init(connectRequestID: String, accountSubject: String, macDeviceID: String, phoneDeviceID: String, providerSlug: String, capability: String, connectionLabel: String, macKexThumbprint: String, keychainAccount: String, credentialVersion: UUID, expiresAt: Date) {
        self.connectRequestID = connectRequestID
        self.accountSubject = accountSubject
        self.macDeviceID = macDeviceID
        self.phoneDeviceID = phoneDeviceID
        self.providerSlug = providerSlug
        self.capability = capability
        self.connectionLabel = connectionLabel
        self.macKexThumbprint = macKexThumbprint
        self.keychainAccount = keychainAccount
        self.credentialVersion = credentialVersion
        self.expiresAt = expiresAt
    }
}

public enum RemoteConnectOutcome: Sendable, Equatable {
    /// Stored, verified, reported.
    case verified(ConnectionVerification)
    /// Refused. `reported` says whether §5.6 step 7's value-free result reached
    /// the relay — `presence_unavailable` is local-only and never does.
    case refused(RemoteConnectFailure, reported: Bool)

    public static func == (lhs: RemoteConnectOutcome, rhs: RemoteConnectOutcome) -> Bool {
        switch (lhs, rhs) {
        case let (.verified(a), .verified(b)): a == b
        case let (.refused(a, ra), .refused(b, rb)): a == b && ra == rb
        default: false
        }
    }

    public var failure: RemoteConnectFailure? {
        if case let .refused(reason, _) = self { return reason }
        return nil
    }
}

/// What each step did, so a test can assert **what was not touched** as well as
/// what was. `presenceUnavailableOnALockedMacDeniesWithoutTouchingTheKeychain`
/// is an assertion about absence, and absence needs a witness.
public struct RemoteConnectTrace: Sendable, Equatable {
    public var consumeAttempted = false
    public var keychainSaveAttempted = false
    public var keychainDeleteAttempted = false
    public var verificationAttempted = false
    public var resultPosted = false
    /// §5.6 step 9. False on every refusal path, including the one that deletes
    /// the item at step 8 — there is no connection to report.
    public var connectionReported = false
    public init() {}
}

// MARK: - The path

public struct RemoteConnectConsumer: Sendable {
    let transport: RemoteConnectTransport
    let presence: RemotePresenceProbe
    let custody: RemoteConnectCustody
    let verifier: ConnectionVerifier
    let pin: DevicePairingRecord
    /// §5.6 **step 9** — *"Report the connection through
    /// `PUT /api/device-connections`"*.
    ///
    /// **Required and nullable**, like the metadata snapshot BM-L7 made a
    /// required argument: a seam that can be forgotten is a seam that was
    /// forgotten once already. `nil` is a caller that has no device session —
    /// an unlinked Mac — and it is a decision the call site has to make rather
    /// than a parameter it can omit.
    let connections: (any DeviceConnectionReporting)?
    /// The Secure Enclave `kex` private key, as an HPKE recipient. Injected so
    /// the self-tests can run the whole path unsigned against a software key —
    /// which is the only way to run it at all without a Keychain, and is
    /// recorded as such rather than presented as evidence about the Enclave.
    let openEnvelope: @Sendable (Data, RemoteConnectEnvelopeInfo) throws -> Data

    public init(
        transport: RemoteConnectTransport,
        presence: RemotePresenceProbe,
        custody: RemoteConnectCustody,
        verifier: ConnectionVerifier,
        pin: DevicePairingRecord,
        connections: (any DeviceConnectionReporting)?,
        openEnvelope: @escaping @Sendable (Data, RemoteConnectEnvelopeInfo) throws -> Data
    ) {
        self.transport = transport
        self.presence = presence
        self.custody = custody
        self.verifier = verifier
        self.pin = pin
        self.connections = connections
        self.openEnvelope = openEnvelope
    }

    /// §5.6 **steps 1–9**.
    ///
    /// **Step 9, and what it turned out to be** (BM-M9). §5.6 step 9 is *"Report
    /// the connection through `PUT /api/device-connections`"*, and BM-M9
    /// narrowed the claim to steps 1–8 because `RemoteConnectTransport` has
    /// three methods and none of them is it. The route needs **no Worker
    /// change**: it shipped under BL-075 / owner decision D20, it is Mac-only,
    /// and this Mac already calls it — `DeviceAccountClient.reportConnections`
    /// through `DeviceConnectionMetadataReporter`, on every local connection
    /// change. What was missing was not the call but this path reaching it.
    ///
    /// So step 9 is the existing BL-075 reporting seam, invoked here with the
    /// rows this connect **will** leave behind. It runs only on the success
    /// path: a refusal has no connection to report, including the step 8 path
    /// that deletes the item it just wrote.
    ///
    /// **It cannot fail this flow.** BL-075's rule is that a connection is
    /// created and verified on this Mac whether or not any of it reaches a
    /// server, and a remote connect is not the exception: the credential is in
    /// custody and verified before step 9 is attempted, the call is value-free,
    /// and its failure is swallowed exactly as the local path swallows it.
    public func consume(
        _ request: RemoteConnectConsumptionRequest,
        connection: Connection,
        item: VaultItem,
        pairedIn state: VaultageMetadata,
        now: Date = Date(),
        trace: @Sendable (inout RemoteConnectTrace) -> Void = { _ in }
    ) async -> RemoteConnectOutcome {
        var steps = RemoteConnectTrace()
        defer { trace(&steps) }

        // **§4.3 check 2's predicate, re-run here** (BM-L7). The consumer takes
        // its `pin` at `init`, and step 4 then verifies `connectContextPreimage`
        // against whatever pin the caller supplied. There is no product caller
        // yet — and the natural shape for one is to look the pin up by
        // `phoneDeviceID`, which is exactly the lookup that skips the
        // revocation. The metadata snapshot is a required argument rather than
        // an optional one so that seam cannot be written without answering the
        // question. Local-only: the relay learns nothing.
        guard RemoteDevicePairingPolicy.isServedAndPaired(pin.phoneDeviceID, in: state) else {
            return .refused(.pairingRevoked, reported: false)
        }

        // §5.6's closing paragraph, and it runs **first**. The item this path
        // creates carries `.userPresence`, and LocalAuthentication cannot prompt
        // outside an active foreground console session, so a locked Mac is not a
        // prompt nobody answers — it is a read that fails. The broker returns
        // `approval_denied` with `presence_unavailable` **without touching the
        // Keychain** and without consuming the one envelope it could not store.
        guard presence.currentPresence().canPromptForPresence else {
            return .refused(.presenceUnavailable, reported: false)
        }

        guard now < request.expiresAt else {
            return await report(.approvalExpired, for: request, steps: &steps)
        }

        // Step 1 — consume, one statement, **when ready to store** (§5.4, Q5).
        steps.consumeAttempted = true
        let consumed: RemoteConsumedEnvelope?
        do { consumed = try await transport.consumeEnvelope(connectRequestID: request.connectRequestID) }
        catch { return await report(.envelopeInvalid, for: request, steps: &steps) }
        // A second consume is `404`. It is a refusal, never an empty result.
        guard let consumed else {
            return await report(.envelopeConsumed, for: request, steps: &steps)
        }

        // Step 2 — size, version and suite **before any curve operation**, and
        // the 16 KiB bound **before the base64url decode** (BM-L8). The shipped
        // client already bounds the raw body before parsing, which is what §5.6
        // step 1 asks for, so this is ordering rather than a hole — but this
        // consumer is the seam a second transport would be written against, and
        // a bound applied after decoding is a bound a caller can hand 12 MiB to.
        guard consumed.ciphertext.count <= RemoteConsumedEnvelope.maximumResponseBytes else {
            return await report(.envelopeInvalid, for: request, steps: &steps)
        }
        guard let envelope = RemoteBase64URL.decode(consumed.ciphertext),
              envelope.count <= RemoteConsumedEnvelope.maximumResponseBytes,
              RemoteEnvelopePadding.rawEnvelopeSizes.contains(envelope.count),
              envelope.count >= 2,
              envelope[envelope.startIndex] == RemoteSealedSummary.version,
              envelope[envelope.index(after: envelope.startIndex)] == RemoteSealedSummary.suite
        else { return await report(.envelopeInvalid, for: request, steps: &steps) }

        // Step 4, first half — **verify `connectSignature` before decrypting
        // anything further** (§5.3a item 3). The context is rebuilt from this
        // Mac's own state and its own pinned `kex` thumbprint, so the only field
        // the relay contributes is the signature it must match.
        let context = RemoteConnectContext(
            connectRequestId: request.connectRequestID,
            accountSubject: request.accountSubject,
            macDeviceId: request.macDeviceID,
            phoneDeviceId: request.phoneDeviceID,
            providerSlug: request.providerSlug,
            capability: request.capability,
            fieldSchemaId: RemoteConnectContract.compiled(forProviderSlug: request.providerSlug)?.fieldSchemaId ?? "",
            macKexThumbprint: request.macKexThumbprint,
            issuedAt: consumed.issuedAt
        )
        guard let contract = RemoteConnectContract.compiled(forProviderSlug: request.providerSlug),
              contract.permits(capability: request.capability)
        else { return await report(.capabilityNotCompiled, for: request, steps: &steps) }
        guard let signature = RemoteBase64URL.decode(consumed.connectSignature), signature.count == 64,
              RemoteConnectContextVerification.verify(signature: signature, context: context, pin: pin)
        else { return await report(.connectSignatureInvalid, for: request, steps: &steps) }

        // Step 3 — derive, open, verify the tag. Failure is terminal and
        // nothing is stored.
        let info = RemoteConnectEnvelopeInfo(
            connectRequestId: request.connectRequestID,
            accountSubject: request.accountSubject,
            macDeviceId: request.macDeviceID,
            providerSlug: request.providerSlug,
            phoneDeviceId: request.phoneDeviceID,
            macKexThumbprint: request.macKexThumbprint,
            fieldSchemaId: contract.fieldSchemaId
        )
        guard let plaintext = try? openEnvelope(envelope, info),
              let parsed = try? RemoteConnectPlaintext.parse(plaintext)
        else { return await report(.envelopeInvalid, for: request, steps: &steps) }

        // Step 4, second half — validate against the **compiled** contract,
        // never against anything the control plane or the phone supplied. An
        // unknown field name is a refusal and **no Keychain item is created**;
        // a missing one is too, because a contract is an exact list.
        guard parsed.header.fieldSchemaId == contract.fieldSchemaId,
              parsed.header.providerSlug == contract.providerSlug,
              parsed.header.capability == request.capability
        else { return await report(.schemaMismatch, for: request, steps: &steps) }
        guard Set(parsed.fieldNames) == Set(contract.fieldNames) else {
            return await report(.unknownField, for: request, steps: &steps)
        }
        guard let credential = parsed.secret(for: contract.fieldNames[0]), !credential.isEmpty else {
            return await report(.envelopeInvalid, for: request, steps: &steps)
        }

        // Step 5 — the ordinary BL-005 custody path. The value has been a
        // `VaultSecret` since the moment it was sliced out of the plaintext and
        // never a `String`.
        steps.keychainSaveAttempted = true
        do { try custody.save(credential, account: request.keychainAccount) }
        catch { return await report(.storageFailed, for: request, steps: &steps) }

        // Step 6 — the adapter's fixed verification, recorded exactly as a
        // locally entered credential would be. **This works remotely**: the
        // plaintext is already in memory from step 3, so there is no Keychain
        // read and no presence prompt.
        steps.verificationAttempted = true
        let evidence: ConnectionVerification
        do { evidence = try await verifier.verify(connection: connection, item: item, credential: credential) }
        catch {
            // Step 8 — delete the item, then report a fixed reason code.
            steps.keychainDeleteAttempted = true
            try? custody.delete(account: request.keychainAccount)
            return await report(.verificationFailed, for: request, steps: &steps)
        }

        // Step 7 — report back, value-free, with BL-075's bounds applied.
        steps.resultPosted = true
        try? await transport.reportConnectResult(
            connectRequestID: request.connectRequestID,
            result: RemoteConnectResult(
                verified: true,
                principalHint: Self.boundedPrincipalHint(evidence.principalLabel ?? evidence.principalID),
                verifiedAt: Int(evidence.verifiedAt.timeIntervalSince1970),
                resultCode: nil
            )
        )

        // Step 9 — report the connection through `PUT /api/device-connections`,
        // which is an idempotent full replace, so what goes is the whole list
        // with this connection applied. Step 8 is the failure path above; there
        // is no step between 7 and 9 on the way out.
        if let connections {
            steps.connectionReported = true
            try? await connections.reportConnections(
                DeviceConnectionReport.reports(in: state, verifiedByRemoteConnect: connection, evidence: evidence)
            )
        }
        return .verified(evidence)
    }

    /// §5.6 step 7 for the failure paths, and the one place the local-only rule
    /// is enforced: a reason on `RemoteConnectFailure.isLocalOnly` is **never
    /// posted**.
    private func report(_ failure: RemoteConnectFailure, for request: RemoteConnectConsumptionRequest, steps: inout RemoteConnectTrace) async -> RemoteConnectOutcome {
        guard let code = failure.wireResultCode else { return .refused(failure, reported: false) }
        steps.resultPosted = true
        try? await transport.reportConnectResult(
            connectRequestID: request.connectRequestID,
            result: RemoteConnectResult(verified: false, principalHint: nil, verifiedAt: nil, resultCode: code)
        )
        return .refused(failure, reported: true)
    }

    /// ≤96 characters, and never a value. The bound is applied here rather than
    /// trusted from the adapter, because this string is the one thing the relay
    /// learns about the credential.
    static func boundedPrincipalHint(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        return String(raw.prefix(RemoteConnectResult.maximumPrincipalHintCharacters))
    }
}
