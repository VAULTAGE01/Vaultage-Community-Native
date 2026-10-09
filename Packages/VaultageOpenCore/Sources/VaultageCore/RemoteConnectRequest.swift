import Foundation

/// BL-099 slice 3 step (b) — **what the Mac composes when an agent asks for a
/// provider this Mac has no connection for** (§5.1, §5.3a, §6.2).
///
/// Slice 2 built the receiving half — §5.6's steps 1–9, `connectContextPreimage`
/// verified against the pin, the single consumption — and left a named gap: *"the
/// connect **request creation** path is specified and its transport method
/// exists, but the Mac-side composition that drives it is not wired."* This is
/// that composition, and it is where §5.3a's three rules are enforced on the way
/// out rather than only on the way back in:
///
/// 1. **`fieldSchemaId` comes from the compiled contract**, so the field list the
///    phone is about to render is one both sides derive and neither is told.
/// 2. **`capability` comes from the compiled set**, never from the agent's
///    `vaultage_provision` argument. The agent asks for `dns:read`; what the
///    *owner* is asked to paste is whatever the compiled contract says a connect
///    is for, and the wording the phone displays is keyed by
///    `(provider, capability)` on the phone's own compiled copy. A relay that
///    rewrites the column has nothing to rewrite it into.
/// 3. **The `connectContextPreimage` the phone signs with `apv` is a function of
///    what this Mac already knows** — including `macKexThumbprint` from the pin,
///    never from the request — so the signature the Mac verifies at §5.6 step 4
///    is over a statement the Mac itself could have written.
///
/// **One phone, and the protocol does not say which.** `RemoteConnectRequestCreation`
/// carries exactly one ciphertext and one recipient, because a connect is a thing
/// the owner does once on one device; §5.3a binds `phoneDeviceId` into the
/// context for the same reason. With more than one phone paired the protocol is
/// silent, so this composition takes the **first in `phoneDeviceId` order** — the
/// same deterministic tie-break §3.2's routing header already uses for
/// `requestDigest` (DB-M41) — and says so rather than implying a rule exists.

public struct RemoteConnectRequestComposition: Sendable {
    /// `POST /api/connect-requests`' body.
    public let creation: RemoteConnectRequestCreation
    /// The Mac's own record of the open pending, with the retained field list
    /// check 9a would need if this pending were ever decided rather than
    /// answered with an envelope.
    public let pending: RemotePendingPublication
    public let summary: RemoteApprovalSummary
    public let recipient: DevicePairingRecord
    public let contract: RemoteConnectContract
    /// The capability drawn from the compiled set, and the wording the *owner*
    /// will be shown for it — both from the contract, neither from the agent.
    public let capability: String
    public let permissionWording: String
    /// What §5.6 step 4 will later verify against the pin. `issuedAt` is the
    /// phone's and arrives beside the ciphertext, which is why it is a
    /// parameter here rather than a stored field: the Mac fixes every other
    /// field at composition time and refuses anything that does not match.
    public let macKexThumbprint: String
    public let accountSubject: String
    public let macDeviceID: String
    public let connectRequestID: String

    public func context(issuedAt: Int) -> RemoteConnectContext {
        RemoteConnectContext(
            connectRequestId: connectRequestID,
            accountSubject: accountSubject,
            macDeviceId: macDeviceID,
            phoneDeviceId: recipient.phoneDeviceID,
            providerSlug: contract.providerSlug,
            capability: capability,
            fieldSchemaId: contract.fieldSchemaId,
            macKexThumbprint: macKexThumbprint,
            issuedAt: issuedAt
        )
    }

    /// The consumption request §5.6 runs against this composition. Every field
    /// is one the Mac fixed; nothing here is read back from the relay.
    public func consumptionRequest(keychainAccount: String, credentialVersion: UUID, expiresAt: Date) -> RemoteConnectConsumptionRequest {
        RemoteConnectConsumptionRequest(
            connectRequestID: connectRequestID,
            accountSubject: accountSubject,
            macDeviceID: macDeviceID,
            phoneDeviceID: recipient.phoneDeviceID,
            providerSlug: contract.providerSlug,
            capability: capability,
            connectionLabel: creation.connectionLabel,
            macKexThumbprint: macKexThumbprint,
            keychainAccount: keychainAccount,
            credentialVersion: credentialVersion,
            expiresAt: expiresAt
        )
    }
}

public enum RemoteConnectRequestComposer {
    /// The Mac mints the id — see `RemoteConnectRequestCreation.id` for why it
    /// cannot be the Worker's. Lowercase, hyphenated, 8-4-4-4-12, because it is
    /// a field of P4, P9 and P10 and deviation 4 is canonical before hashing.
    public static func freshConnectRequestID() -> String { UUID().uuidString.lowercased() }

    /// The one place `class: connect`'s summary is built.
    ///
    /// - Parameters:
    ///   - provider: the slug the agent named. A provider with no compiled
    ///     connect contract is refused here rather than half-published — it is
    ///     not in `CONNECTABLE_PROVIDERS` (§5.2, DB-M2) precisely because the
    ///     contract does not exist.
    ///   - recipients: this Mac's pins. Sorted and the first taken; see above.
    public static func compose(
        connectRequestID: String,
        provider: String,
        connectionLabel: String,
        projectName: String,
        environmentName: String,
        sensitivity: EnvironmentSensitivity,
        isProduction: Bool,
        agentState: String,
        agentLabel: String?,
        agentClientID: String?,
        accountSubject: String,
        macDeviceID: String,
        macKexThumbprint: String,
        recipients: [DevicePairingRecord],
        presence: RemotePresence,
        openPendingCount: Int,
        issuedAt: Int
    ) throws -> RemoteConnectRequestComposition {
        guard let contract = RemoteConnectContract.compiled(forProviderSlug: provider) else {
            throw VaultageError.unsupported("This version of Vaultage cannot connect \(provider) from a phone.")
        }
        // **Rule 2, and it fails closed.** Today every compiled contract carries
        // exactly one capability. A contract with two would mean the owner has a
        // choice to make, and where that choice is offered is a question §5.3a
        // does not answer — so the composition refuses rather than picking one
        // and telling the owner it was the only option.
        guard contract.compiledCapabilities.count == 1, let capability = contract.compiledCapabilities.first,
              let wording = contract.wording(for: capability)
        else {
            throw VaultageError.unsupported("\(provider)'s compiled connect contract does not name exactly one capability, so this Mac cannot say what the owner would be asked for.")
        }
        guard RemoteDeviceKeyThumbprint.isWellFormed(macKexThumbprint) else {
            throw VaultageError.invalidInput("This Mac's kex thumbprint is malformed; re-pair before connecting from a phone.")
        }
        guard let recipient = recipients.sorted(by: { $0.phoneDeviceID < $1.phoneDeviceID }).first else {
            throw VaultageError.invalidInput("No phone is paired with this Mac, so there is nobody to ask.")
        }
        guard recipient.isWellFormed else {
            throw VaultageError.invalidInput("A paired phone's pin record is incoherent; re-pair it before connecting.")
        }

        let request = RemotePublicationRequest(
            pendingID: connectRequestID,
            accountSubject: accountSubject,
            macDeviceID: macDeviceID,
            summaryClass: .connect,
            agentState: agentState,
            agentLabel: agentLabel,
            agentClientID: agentClientID,
            provider: contract.providerSlug,
            connectionLabel: connectionLabel,
            principalHint: nil,
            projectName: projectName,
            environmentName: environmentName,
            sensitivity: sensitivity.rawValue,
            isProduction: isProduction,
            operation: "connection.connect",
            verb: "connect",
            effect: wording,
            trustClass: OperationTrustClass.ordinary.rawValue,
            resourceLabel: nil,
            custodyClass: .presenceRequired,
            brokerDigestKind: brokerDigestKind,
            brokerRequestDigest: brokerRequestDigest(
                provider: contract.providerSlug,
                capability: capability,
                fieldSchemaId: contract.fieldSchemaId,
                connectionLabel: connectionLabel,
                projectName: projectName,
                environmentName: environmentName
            ),
            connect: RemoteConnectSection(
                providerSlug: contract.providerSlug,
                connectionLabel: connectionLabel,
                capability: capability,
                fieldSchemaId: contract.fieldSchemaId
            )
        )
        let publication = try RemoteSummaryComposer.compose(
            request,
            to: [recipient],
            presence: presence,
            openPendingCount: openPendingCount,
            issuedAt: issuedAt,
            expiresAt: issuedAt + RemotePendingTTL.seconds(for: .connect)
        )
        guard let composed = publication.perRecipient.first else {
            throw VaultageError.storage("A connect summary composed to no recipient.")
        }
        let sealed = try RemoteSummarySealing.seal(composed)
        var retained = RemoteRetainedFieldLists()
        retained.record(composed.retainedVersion, for: recipient.phoneDeviceID)

        return RemoteConnectRequestComposition(
            creation: RemoteConnectRequestCreation(
                id: connectRequestID,
                provider: contract.providerSlug,
                capability: capability,
                connectionLabel: connectionLabel,
                summaryCiphertext: RemoteBase64URL.encode(sealed.envelope),
                recipientDeviceId: recipient.phoneDeviceID,
                recipientThumbprint: sealed.recipientThumbprint,
                byteLength: sealed.envelope.count
            ),
            pending: RemotePendingPublication(
                pendingID: connectRequestID,
                summaryClass: .connect,
                issuedAt: issuedAt,
                expiresAt: issuedAt + RemotePendingTTL.seconds(for: .connect),
                recipients: [recipient.phoneDeviceID],
                retained: retained
            ),
            summary: composed.summary,
            recipient: recipient,
            contract: contract,
            capability: capability,
            permissionWording: wording,
            macKexThumbprint: macKexThumbprint,
            accountSubject: accountSubject,
            macDeviceID: macDeviceID,
            connectRequestID: connectRequestID
        )
    }

    /// §3.3's `brokerDigestKind` for this class, and the digest under it.
    ///
    /// Check 10 re-proves `brokerRequestDigest` against freshly loaded state, so
    /// it has to be a function of what the broker resolved and of nothing the
    /// agent supplied verbatim. The six fields below are exactly the ones a
    /// re-resolution would produce again.
    public static let brokerDigestKind = "vaultage.connect.request.v1"

    public static func brokerRequestDigest(
        provider: String,
        capability: String,
        fieldSchemaId: String,
        connectionLabel: String,
        projectName: String,
        environmentName: String
    ) -> String {
        CanonicalDigest.hex([
            brokerDigestKind, "6",
            provider, capability, fieldSchemaId, connectionLabel, projectName, environmentName
        ])
    }
}

extension RemoteConnectContract {
    /// The compiled capability set, in a fixed order so two builds of the same
    /// contract compose the same request.
    public var compiledCapabilities: [String] { capabilities.keys.sorted() }
}
