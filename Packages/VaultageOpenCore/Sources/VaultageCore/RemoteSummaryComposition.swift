import Foundation

/// BL-099 — composing one pending's summary, once per recipient, and sealing it.
///
/// **The composition is a pure function of resolved local records.** Nothing
/// here reads the network, the Keychain or a clock it was not handed, and
/// nothing here is populated from agent-supplied text (§7 A7). The broker
/// resolves a request into `RemotePublicationRequest` and this file turns that
/// into the bytes the relay carries.

/// The non-recipient half of §3.3.1's `grant` section. The recipient half —
/// `phoneDeviceId` and `phoneApvThumbprint` — is filled per recipient by the
/// composer, which is exactly why the retained field lists are per recipient
/// (residual 8, DB-M37).
public struct RemoteGrantCoverageOffer: Hashable, Sendable {
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
    public let offeredCoverageDigest: String

    public init(scopeLabel: String, durationLabel: String, expiresAtEpoch: Int, environments: [String], operations: [String], mutations: [String], mutationKinds: [String], productionEnvs: [String], includesProduction: Bool, offeredMutations: [String], offeredCoverageDigest: String) {
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
    }

    func section(recipient: DevicePairingRecord) -> RemoteGrantSection {
        RemoteGrantSection(
            scopeLabel: scopeLabel, durationLabel: durationLabel, expiresAtEpoch: expiresAtEpoch,
            environments: environments, operations: operations, mutations: mutations,
            mutationKinds: mutationKinds, productionEnvs: productionEnvs,
            includesProduction: includesProduction, offeredMutations: offeredMutations,
            offeredCoverageDigest: offeredCoverageDigest,
            recipientDeviceId: recipient.phoneDeviceID,
            recipientApvThumbprint: recipient.apvThumbprint
        )
    }
}

/// Everything the Mac has resolved about one request, before a recipient is
/// chosen. One object so the composition has one input and the self-tests have
/// one thing to vary.
public struct RemotePublicationRequest: Hashable, Sendable {
    public let pendingID: String
    public let accountSubject: String
    public let macDeviceID: String
    public let summaryClass: RemoteApprovalClass
    public let agentState: String
    public let agentLabel: String?
    public let agentClientID: String?
    public let provider: String
    public let connectionLabel: String
    public let principalHint: String?
    public let projectName: String
    public let environmentName: String
    public let sensitivity: String
    public let isProduction: Bool
    public let operation: String
    public let verb: String
    public let effect: String
    public let trustClass: String
    public let resourceLabel: String?
    public let destination: RemoteSummaryDestination?
    public let offeredScopes: [String]
    public let offeredDurations: [String]
    public let offeredProjects: [RemoteOfferedProject]
    public let offeredProduction: Bool
    public let choices: [RemoteChoice]
    public let custodyClass: RemoteCustodyClass
    public let brokerDigestKind: String
    public let brokerRequestDigest: String
    public let grant: RemoteGrantCoverageOffer?
    public let connect: RemoteConnectSection?

    public init(pendingID: String, accountSubject: String, macDeviceID: String, summaryClass: RemoteApprovalClass, agentState: String, agentLabel: String?, agentClientID: String?, provider: String, connectionLabel: String, principalHint: String?, projectName: String, environmentName: String, sensitivity: String, isProduction: Bool, operation: String, verb: String, effect: String, trustClass: String, resourceLabel: String?, destination: RemoteSummaryDestination? = nil, offeredScopes: [String] = [], offeredDurations: [String] = [], offeredProjects: [RemoteOfferedProject] = [], offeredProduction: Bool = false, choices: [RemoteChoice] = [], custodyClass: RemoteCustodyClass = .presenceRequired, brokerDigestKind: String, brokerRequestDigest: String, grant: RemoteGrantCoverageOffer? = nil, connect: RemoteConnectSection? = nil) {
        self.pendingID = pendingID
        self.accountSubject = accountSubject
        self.macDeviceID = macDeviceID
        self.summaryClass = summaryClass
        self.agentState = agentState
        self.agentLabel = agentLabel
        self.agentClientID = agentClientID
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
        self.custodyClass = custodyClass
        self.brokerDigestKind = brokerDigestKind
        self.brokerRequestDigest = brokerRequestDigest
        self.grant = grant
        self.connect = connect
    }

    /// **Which recipient key this summary seals to** (§3.2, DB-M19).
    ///
    /// §3.2 words the test as "`sensitivity == production`, or `trustClass ∈
    /// {admin, billing, productionAffecting}`". That first clause is a residue
    /// of the pre-DB-H21 wording and it is **wrong in the direction that
    /// weakens the ACL**: checklist 2 established that every production
    /// predicate in this protocol is `Environment.isProduction`, and §3.2 itself
    /// derives `sensitivityBucket` from `isProduction` for exactly that reason
    /// (DB-L24). An environment *named* "production" with the default
    /// sensitivity would otherwise bucket as `production` in the header while
    /// sealing to `sum` — the key with no biometric constraint — which is
    /// DB-H21 reopening on the one field §2.5's promise rests on.
    ///
    /// So the predicate here is **`isProduction`**, not `sensitivity`. Reported
    /// as a defect in §3.2's wording rather than resolved silently.
    public var isSensitive: Bool {
        if isProduction { return true }
        return ["admin", "billing", OperationTrustClass.productionAffecting.rawValue].contains(trustClass)
    }
}

/// One recipient's share of a publication.
public struct RemoteRecipientPublication: Sendable {
    public let recipient: DevicePairingRecord
    public let summary: RemoteApprovalSummary
    public let fields: [String]
    public let summaryDigest: String
    public let approvalRequestDigest: String
    public let isSensitive: Bool

    /// The HPKE `info` for this recipient's seal, which is also the AAD.
    public var envelopeInfo: RemoteSummaryEnvelopeInfo {
        RemoteSummaryEnvelopeInfo(
            pendingId: summary.pendingId,
            accountSubject: summary.accountSubject,
            macDeviceId: summary.macDeviceId,
            phoneDeviceId: recipient.phoneDeviceID,
            recipientThumbprint: recipient.summaryRecipient(isSensitive: isSensitive).thumbprint,
            issuedAt: summary.issuedAt
        )
    }

    public var retainedVersion: RemoteRetainedVersion {
        RemoteRetainedVersion(issuedAt: summary.issuedAt, fields: fields, summaryDigest: summaryDigest, approvalRequestDigest: approvalRequestDigest)
    }
}

/// A whole publication: the cleartext header the Worker routes on, and one
/// composed summary per paired phone.
public struct RemotePublication: Sendable {
    public let header: RemoteRoutingHeader
    public let perRecipient: [RemoteRecipientPublication]

    /// One ciphertext per paired phone (cap 4 ⇒ ≤4 rows).
    public var recipientCount: Int { perRecipient.count }
}

public enum RemoteSummaryComposer {
    /// Composes one summary per recipient, validating each one before it can be
    /// sealed.
    ///
    /// **Validation runs here, at one of the two parties that matter** (§3.1).
    /// The Worker cannot screen a sealed summary, so the Mac screens before
    /// sealing and the phone screens after opening. A failure refuses the whole
    /// publication; there is no silent scrub.
    public static func compose(
        _ request: RemotePublicationRequest,
        to recipients: [DevicePairingRecord],
        presence: RemotePresence,
        openPendingCount: Int,
        issuedAt: Int,
        expiresAt: Int
    ) throws -> RemotePublication {
        guard !recipients.isEmpty else {
            throw VaultageError.invalidInput("A publication needs at least one paired phone to seal to.")
        }
        guard recipients.count <= DevicePairingRecord.maximumPairedPhones else {
            throw VaultageError.invalidInput("A publication seals to at most \(DevicePairingRecord.maximumPairedPhones) phones.")
        }
        guard RemotePendingTTL.isWithinCeiling(issuedAt: issuedAt, expiresAt: expiresAt) else {
            throw VaultageError.invalidInput("A pending's lifetime is at most \(RemotePendingTTL.ceilingSeconds / 60) minutes.")
        }
        let ordered = recipients.sorted { $0.phoneDeviceID < $1.phoneDeviceID }
        var perRecipient: [RemoteRecipientPublication] = []
        for recipient in ordered {
            guard recipient.isWellFormed else {
                throw VaultageError.invalidInput("A paired phone's pin record is incoherent; re-pair it before mirroring.")
            }
            let summary = RemoteApprovalSummary(
                summaryClass: request.summaryClass,
                pendingId: request.pendingID,
                accountSubject: request.accountSubject,
                macDeviceId: request.macDeviceID,
                agentState: request.agentState,
                agentLabel: request.agentLabel,
                agentClientId: request.agentClientID,
                provider: request.provider,
                connectionLabel: request.connectionLabel,
                principalHint: request.principalHint,
                projectName: request.projectName,
                environmentName: request.environmentName,
                sensitivity: request.sensitivity,
                isProduction: request.isProduction,
                operation: request.operation,
                verb: request.verb,
                effect: request.effect,
                trustClass: request.trustClass,
                resourceLabel: request.resourceLabel,
                destination: request.destination,
                offeredScopes: request.offeredScopes,
                offeredDurations: request.offeredDurations,
                offeredProjects: request.offeredProjects,
                offeredProduction: request.offeredProduction,
                choices: request.choices,
                presence: presence,
                openPendingCount: openPendingCount,
                custodyClass: request.custodyClass,
                brokerDigestKind: request.brokerDigestKind,
                brokerRequestDigest: request.brokerRequestDigest,
                issuedAt: issuedAt,
                expiresAt: expiresAt,
                grant: request.grant?.section(recipient: recipient),
                connect: request.connect
            )
            try RemoteSummaryValidation.validate(summary)
            let fields = RemoteApprovalDigests.summaryFields(summary)
            let digests = RemoteApprovalDigests.digests(for: summary)
            perRecipient.append(RemoteRecipientPublication(
                recipient: recipient,
                summary: summary,
                fields: fields,
                summaryDigest: digests.summary,
                approvalRequestDigest: digests.request,
                isSensitive: request.isSensitive
            ))
        }
        // The header's `requestDigest` is the **first** recipient's, in
        // `phoneDeviceId` order, and is routing metadata only (DB-M41).
        let header = RemoteRoutingHeader(
            summaryClass: request.summaryClass,
            verb: request.verb,
            sensitivityBucket: RemoteRoutingHeader.sensitivityBucket(isProduction: request.isProduction),
            presence: presence,
            expiresAt: expiresAt,
            openPendingCount: openPendingCount,
            requestDigest: perRecipient[0].approvalRequestDigest
        )
        return RemotePublication(header: header, perRecipient: perRecipient)
    }

    /// The plaintext that goes inside the seal: the summary as canonical JSON,
    /// exactly the bytes the phone will decode and digest.
    public static func plaintext(_ summary: RemoteApprovalSummary) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(summary)
    }
}
