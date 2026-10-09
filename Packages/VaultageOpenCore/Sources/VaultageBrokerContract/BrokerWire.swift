import Foundation
import VaultageCore

/// Everything that is allowed to cross the XPC boundary, and nothing else.
///
/// What crosses, in both directions:
///
/// * opaque local identifiers (project, environment, binding, vault-item UUIDs)
///   and the operation name — the same values an MCP client already sends;
/// * the value-free projections `VaultageStatus` and `ActionResult`;
/// * the approval disclosure the broker composed, which is labels, names, an
///   environment class and a request digest;
/// * an `Int32` status and one already-redacted public sentence.
///
/// What never crosses: a credential value or any borrow of one, a Keychain
/// account or persistent reference, a local file path, a provider response
/// body, a durable-receipt identifier list, and the `--run` injection
/// disclosure (which names a command line and a working directory). The
/// encoders below fail closed rather than omit a field they cannot carry.
public enum BrokerWire {
    /// Returns a Swift `String`: value-type payloads only cross into Objective-C
    /// storage at the call itself, never as captured reference state.
    public static func encode<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        guard data.count <= maximumPayloadBytes else { throw VaultageError.invalidInput("The broker payload is too large.") }
        return String(decoding: data, as: UTF8.self)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from json: NSString?) throws -> T {
        try decode(type, from: json as String?)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from json: String?) throws -> T {
        guard let text = json, !text.isEmpty else { throw VaultageError.invalidInput("The broker reply was empty.") }
        guard text.utf8.count <= maximumPayloadBytes else { throw VaultageError.invalidInput("The broker payload is too large.") }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: Data(text.utf8))
    }

    /// New request doors reject unknown fields instead of silently ignoring them.
    public static func strictDecode<T: Decodable>(_ type: T.Type, from json: NSString,
                                                   allowed: Set<String>, required: Set<String>) throws -> T {
        let text = json as String
        guard text.utf8.count <= maximumPayloadBytes,
              let object = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              Set(object.keys).isSubset(of: allowed), required.isSubset(of: Set(object.keys)) else {
            throw VaultageError.invalidInput("The broker request fields were invalid.")
        }
        return try decode(type, from: text)
    }

    /// A bound well above any legitimate projection and far below anything that
    /// could be used to stream material across the boundary.
    public static let maximumPayloadBytes = 256 * 1024
}

/// The approval sheet, as data. This is exactly what `ApprovalDetails` carries
/// minus the `--run` injection disclosure, which is refused below.
public struct ApprovalWire: Codable, Sendable {
    public let project: String
    public let environment: String
    public let provider: String
    public let connection: String
    public let operation: String
    public let reason: String
    /// BL-069. The identity the broker resolved, so the sheet the client
    /// presents carries the same "Client:" line the broker composed. The client
    /// does not choose it and cannot alter what it means.
    public let client: ClientIdentity?
    /// BL-060. The grant-creation disclosure: scope, duration, expiry, the
    /// environment and operation labels, the production flag and the digest.
    /// Labels and counts only, like every other field here.
    public let grant: GrantDisclosure?
    /// BL-091. The provider resource sheet: three lines of copy, a trust class,
    /// an exact resource id and a digest. It crosses because the sheet is
    /// presented by the client process, and it must present the one the broker
    /// composed, not one it assembled itself. Every field is a bounded, closed-charset local string;
    /// no provider response text and no value reaches it.
    public let resourceOperation: ResourceOperationDisclosure?
    /// Contract version 13. A delivery's and a verify-deployed check's own
    /// disclosures, so the sheet the app draws for them over this boundary is
    /// the one it draws in process — its title, the destination, and the
    /// production warning that makes it critical — rather than a generic sheet
    /// that quietly lost them.
    public let credentialDelivery: CredentialDeliveryDisclosure?
    public let deployedVerification: DeployedVerificationDisclosure?
    /// Contract version 13. BL-074's two sheets cross too, now that
    /// `resolveProvisioningCreation` and `revokeProviderResource` are desktop
    /// flows over this boundary: the account, the policy template and the
    /// production warning the creation sheet must name, and the exact
    /// resource id the revocation sheet must name, arrive as the broker
    /// composed them.
    public let providerResourceCreation: ProviderResourceCreationDisclosure?
    public let providerResourceRevocation: ProviderResourceRevocationDisclosure?

    /// Returns `nil` for a `--run` injection disclosure. Local runtime delivery
    /// keeps custody of both the resolved command line and the credential in
    /// one process by design, so its disclosure has no reason to cross a
    /// process boundary and is refused here rather than filtered — a future
    /// caller that composed one would fail visibly instead of presenting a
    /// sheet that had quietly lost what it must name.
    ///
    /// BL-074's two sheets were refused the same way until contract 13 put
    /// the human steps of provisioning and the approved revocation over this
    /// boundary; they now cross whole, in their own fields.
    public init?(_ details: ApprovalDetails) {
        guard details.runtimeInjection == nil else { return nil }
        project = details.project
        environment = details.environment
        provider = details.provider
        connection = details.connection
        operation = details.operation
        reason = details.reason
        client = details.client
        grant = details.grant
        resourceOperation = details.resourceOperation
        credentialDelivery = details.credentialDelivery
        deployedVerification = details.deployedVerification
        providerResourceCreation = details.providerResourceCreation
        providerResourceRevocation = details.providerResourceRevocation
    }

    public var details: ApprovalDetails {
        ApprovalDetails(
            project: project,
            environment: environment,
            provider: provider,
            connection: connection,
            operation: operation,
            reason: reason,
            // A sheet that arrives without a resolved identity says
            // "unenrolled"; it never silently omits the line.
            client: client ?? .unenrolled(.notPresented),
            grant: grant,
            providerResourceCreation: providerResourceCreation,
            providerResourceRevocation: providerResourceRevocation,
            resourceOperation: resourceOperation,
            credentialDelivery: credentialDelivery,
            deployedVerification: deployedVerification
        )
    }
}

/// BL-069. The one value in this boundary that travels as a preimage.
///
/// It is the client's *own* enrollment authenticator, not a vault credential:
/// it never came from the Keychain, it never reaches a provider, and holding it
/// buys a name on an approval sheet and nothing else. It crosses because the
/// broker is the verifier and the store holds only SHA-256 hashes — sending a
/// digest instead would make the stored hash itself a usable bearer value, so
/// anyone who could read `metadata.json` could impersonate an enrolled client.
/// Hash-only storage is the property worth keeping; this crossing is its cost.
///
/// The recorded upgrade is a challenge–response over a key pair, where nothing
/// replayable sits in a file or crosses a boundary. It is not claimed here.
public struct ClientAuthenticationWire: Codable, Sendable {
    /// `nil` means "this client presented nothing", which is a legitimate and
    /// common state, not an error.
    public let credential: String?
    public init(credential: String?) { self.credential = credential }
}

/// Receipt recovery as counts only. The broker has already mirrored every
/// interrupted invocation into the local Activity projection inside its own
/// process; the identifiers of those invocations are not part of what a client
/// needs and therefore do not cross.
public struct RecoveryWire: Codable, Sendable {
    public let records: Int
    public let quarantinedTailBytes: Int
    public let malformedLines: Int
    public let pendingClosedAsUnknown: Int

    public init(_ recovery: ReceiptRecovery) {
        records = recovery.records
        quarantinedTailBytes = recovery.quarantinedTailBytes
        malformedLines = recovery.malformedLines
        pendingClosedAsUnknown = recovery.pendingClosedAsUnknown.count
    }

    /// Rebuilds the counts a client may act on. `pendingClosedAsUnknown` is
    /// deliberately left empty rather than reconstructed from a count, so no
    /// caller can mistake a number for a list of invocations it can inspect.
    public var recovery: ReceiptRecovery {
        var value = ReceiptRecovery()
        value.records = records
        value.quarantinedTailBytes = quarantinedTailBytes
        value.malformedLines = malformedLines
        return value
    }
}

/// BL-060. Revoking names one grant by identifier and nothing else.
public struct GrantIdentifierWire: Codable, Sendable {
    public let id: UUID
    public init(id: UUID) { self.id = id }
}

// MARK: - BL-099, contract version 9

/// The three remote-approval projections are defined in `VaultageCore`, beside
/// the rules that produce them, and aliased here so this file stays the single
/// list of what may cross. They are `Codable` and value-free by construction:
/// **no thumbprint, no signature and no decision body crosses** — §2.4's control
/// is that the pin is consulted on the custody side, and an app-side copy could
/// only ever be a hex string a compromised app could lie about.
public typealias PairedDeviceWire = RemotePairedDevice
public typealias RemoteDecisionOutcomeWire = RemoteDecisionOutcomeProjection
public typealias RemoteArmingDisclosureWire = RemoteArmingDisclosureProjection
/// The mirroring switch's whole state: the chosen position and, when it
/// exists, the consent record (a revision string, a date and the phone id that
/// raised the screen). No thumbprint, no signature, nothing from inside the
/// vault — it is the same value `RemoteMirroringConsent`'s copy already shows
/// the owner on screen, never the pin.
public typealias RemoteMirroringSettingWire = RemoteMirroringSetting

// MARK: BL-100 slice A — the custody surface's wire shapes (contract version 12)
//
// They are `VaultageCore`'s own projections, aliased here for the same reason
// `RemoteMirroringSettingWire` is: the shape belongs to the thing that builds
// it, and a second declaration is a second thing to keep in step. **Every one
// of them is counts, labels and identifiers** — no sealed record, no wrap row,
// no ciphertext and no enumeration of any of them, which is the bound §3.2's
// table states.
public typealias VaultWatermarkWire = VaultWatermarkProjection
public typealias VaultLivenessWire = VaultLivenessProjection
public typealias VaultFenceWire = VaultFenceProjection
public typealias VaultSurfaceWire = VaultSurfaceProjection
public typealias VaultTransferOutcomeWire = VaultTransferOutcomeProjection
public typealias VaultDeletionQueueCountWire = VaultDeletionQueueCountProjection
public typealias VaultDeletionQueueListWire = VaultDeletionQueueProjectionList
public typealias VaultApplyHeadRequestWire = VaultApplyHeadRequest
public typealias VaultWriteMetadataRequestWire = VaultWriteMetadataRequest
public typealias VaultEnqueueDeletionRequestWire = VaultEnqueueDeletionRequest
public typealias VaultRestoreDeletionRequestWire = VaultRestoreDeletionRequest
/// `openMetadataPlane` takes a list of vault ids and the names to render in the
/// one prompt it raises.
public struct VaultOpenPlaneRequestWire: Codable, Sendable, Equatable {
    public let vaultIDs: [UUID]
    public let displayNames: [String]
    public init(vaultIDs: [UUID], displayNames: [String]) {
        self.vaultIDs = vaultIDs
        self.displayNames = displayNames
    }
}

/// A reply that carries nothing but success, for the one selector that returns
/// **no value** by design — flow 7's entry point.
public struct VaultAcknowledgementWire: Codable, Sendable, Equatable {
    public let entered: Bool
    public init(entered: Bool) { self.entered = entered }
}

/// Failure projection: a fixed status plus one public sentence that has already
/// been through `Redactor`.
public struct BrokerFailureWire: Codable, Sendable {
    public let message: String
    public init(message: String) { self.message = message }
}

public enum BrokerErrorWire {
    public static func status(for error: Error) -> BrokerWireStatus {
        guard let error = error as? VaultageError else { return .failed }
        switch error {
        case .approvalDenied: return .approvalDenied
        case .policyDenied: return .policyDenied
        case .invalidInput: return .invalidPayload
        case .resultUnknown: return .resultUnknown
        default: return .failed
        }
    }

    /// Reconstructs a typed error on the client side from the value-free reply.
    /// An unknown or absent status fails closed as a denial, never as success.
    public static func error(status: BrokerWireStatus, message: String) -> VaultageError {
        switch status {
        case .success: return .transport("The broker reported success without a result.")
        case .incompatibleProtocol: return .unsupported("This Vaultage build cannot talk to its credential broker service.")
        case .invalidPayload: return .invalidInput(message)
        case .approvalDenied: return .approvalDenied
        case .policyDenied: return .policyDenied(message)
        case .resultUnknown: return .resultUnknown
        case .failed: return .transport(message)
        case .transportFailure: return .transport("The Vaultage credential broker service is unavailable.")
        }
    }
}

// MARK: - Contract version 13: the owner's desktop flows

/// One identifier: a rotation, or an environment to verify.
public struct DesktopIdentifierWire: Codable, Equatable, Sendable {
    public let id: UUID
    public init(id: UUID) { self.id = id }
}

/// `refreshInventory(connectionID:force:)`.
public struct InventoryRefreshRequestWire: Codable, Equatable, Sendable {
    public let connectionID: UUID
    public let force: Bool
    public init(connectionID: UUID, force: Bool) { self.connectionID = connectionID; self.force = force }
}

/// `bindInventoryResource(resourceID:environmentID:)`.
/// Contract version 13. The human's pick in a provisioning conversation: the
/// open request and the existing vault item chosen for it.
public struct ProvisioningSelectionWire: Codable, Equatable, Sendable {
    public let provisioningID: UUID
    public let vaultItemID: UUID
    public init(provisioningID: UUID, vaultItemID: UUID) { self.provisioningID = provisioningID; self.vaultItemID = vaultItemID }
}

/// Contract version 13. The human's authorization to create a provider
/// resource for an open request: the target account (and zone) and the label
/// the new vault item will carry. The broker validates both again.
public struct ProvisioningCreationWire: Codable, Equatable, Sendable {
    public let provisioningID: UUID
    public let target: CloudflareTokenTarget
    public let label: String
    public init(provisioningID: UUID, target: CloudflareTokenTarget, label: String) { self.provisioningID = provisioningID; self.target = target; self.label = label }
}

public struct InventoryBindRequestWire: Codable, Equatable, Sendable {
    public let resourceID: UUID
    public let environmentID: UUID
    public init(resourceID: UUID, environmentID: UUID) { self.resourceID = resourceID; self.environmentID = environmentID }
}


/// Protocol15 agent provisioning request: no credential or provider payload.
public struct ProvisioningRequestWire: Codable, Equatable, Sendable {
    public let projectID: UUID
    public let environmentID: UUID
    public let provider: String
    public let capability: String
    public let provisioningID: UUID?
    public init(_ request: ProvisioningRequest) {
        projectID = request.projectID; environmentID = request.environmentID
        provider = request.provider; capability = request.capability; provisioningID = request.provisioningID
    }
    public func validatedRequest() throws -> ProvisioningRequest {
        guard provider.utf8.count <= 64, capability.utf8.count <= 64,
              provider.range(of: "^[a-z0-9_.-]+$", options: .regularExpression) != nil,
              capability.range(of: "^[a-z0-9_.-]+$", options: .regularExpression) != nil else {
            throw VaultageError.invalidInput("Provider and capability must be short lowercase identifiers.")
        }
        return request
    }
    public var request: ProvisioningRequest {
        ProvisioningRequest(projectID: projectID, environmentID: environmentID, provider: provider, capability: capability, provisioningID: provisioningID)
    }
}
