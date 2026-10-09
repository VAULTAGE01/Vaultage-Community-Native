import Foundation

/// The custody seam introduced by BL-061.
///
/// Every caller — the `--mcp` subprocess, the `--run` launcher and the UI —
/// depends on this protocol rather than on a concrete broker, so the same code
/// paths run against either composition:
///
/// * **In-process** (`VaultageBroker`): the fallback used by self-tests, by
///   unsigned development builds, and by any build that cannot present a nested,
///   signed XPC service. Custody is the process boundary of the app itself.
/// * **XPC client** (`XPCBrokerClient`): selected only by a profile-authorized
///   signed build that actually carries the nested broker service. Keychain
///   reads, approval orchestration and the durable receipt log live in the
///   service process; the caller receives value-free projections.
///
/// The protocol deliberately exposes only projections that are already safe to
/// hand an MCP client. There is no member that returns, borrows or references a
/// credential, a Keychain account or a local file path, so no implementation of
/// this seam can be asked for one.
public protocol BrokerFacade: Sendable {
    /// BL-069. Presents this process's enrollment credential, if its MCP host
    /// set one, and returns the identity the broker resolved it to. The reply
    /// is a label for the approval sheet: it is not a capability, it is not
    /// cached as authority, and an unenrolled or revoked result changes nothing
    /// except what the human is told about who is asking.
    @discardableResult func identify(presenting credential: ClientCredential?) async -> ClientIdentity
    func status(includeBindings: Bool) async throws -> VaultageStatus
    func execute(_ request: ActionRequest) async throws -> ActionResult
    /// BL-073. The provisioning conversation. It is on this seam because it is
    /// agent-facing, and it is safe here for the same reason `status` is: every
    /// value it returns is an identifier, a label or a fixed instruction. The
    /// human steps it opens are resolved through desktop-only methods that are
    /// deliberately **not** on this protocol, so no MCP client, XPC message or
    /// grant can answer its own request.
    func provision(_ request: ProvisioningRequest) async throws -> ProvisioningOutcome
    /// BL-092. The cross-provider Resources inventory, read. It is on this seam
    /// because `vaultage_resources` calls it, and it is safe here for the same
    /// reason `status` is: every value it returns is an identifier, a label, a
    /// documented attribute or a fixed instruction, and it contacts no
    /// provider. The two things that *change* state — refreshing the cache and
    /// binding a row to an environment — are deliberately **not** on this
    /// protocol: they are on `VaultageBroker`, so no MCP client, XPC message or
    /// grant can make this Mac talk to a provider, or choose which zone its own
    /// next request acts on.
    func searchInventory(_ query: InventoryQuery) async throws -> InventoryPage
    /// D71. The agent's door to a delivery: `deliverCredential`'s own path —
    /// the check before the write, one native sheet on the Mac, the write, the
    /// check after it, the ledger row — with the agent's source rule (only a
    /// source the owner allowed for the binding) and the requester named.
    @discardableResult func deliverForAgent(_ request: CredentialDeliveryRequest) async throws -> CredentialDeliveryOutcome
    @discardableResult func recoverDurableReceipts() async -> ReceiptRecovery
    /// BL-060. Creates an auto-allow grant behind a native approval and OS
    /// authentication. It is on this seam because the grant, and the secret
    /// cache the grant arms, must live wherever custody lives.
    @discardableResult func createGrant(_ request: GrantRequest) async throws -> GrantSummary
    @discardableResult func revokeGrant(_ id: UUID) async throws -> GrantSummary
    /// Value-free projection for Activity: scope, coverage and remaining time.
    func listGrants() async throws -> [GrantSummary]
    /// Forgets every cached secret and any carried arming presence while
    /// leaving the grants armed as metadata. Returns the entries that remain
    /// cached afterwards — zero, or the lock did not take — and throws when
    /// the broker could not be reached, so no caller reports a lock it cannot
    /// see (audit H-04).
    @discardableResult func lockGrantSecrets() async throws -> Int
    /// BL-136 step 3. `vaultage_pair`: the first call issues a code, the
    /// second raises the pairing sheet on the Mac and, after Touch ID, binds
    /// the agent. It grants nothing.
    func pair(_ request: AgentPairingRequest) async throws -> AgentPairingOutcome
}

public extension BrokerFacade {
    func pair(_ request: AgentPairingRequest) async throws -> AgentPairingOutcome {
        throw VaultageError.unsupported("This Vaultage composition cannot pair an agent.")
    }
    /// Callers that have no credential to present — the desktop's own receipt
    /// recovery, tests — get the unenrolled default without restating it.
    @discardableResult func identify(presenting credential: ClientCredential?) async -> ClientIdentity { .unenrolled(.notPresented) }
    /// A facade that has not implemented grants refuses to create one and
    /// reports none. Failing closed here means a composition that cannot carry
    /// a grant never behaves as though it silently had.
    @discardableResult func createGrant(_ request: GrantRequest) async throws -> GrantSummary {
        throw VaultageError.unsupported("This Vaultage composition cannot create auto-allow grants.")
    }
    @discardableResult func revokeGrant(_ id: UUID) async throws -> GrantSummary {
        throw VaultageError.unsupported("This Vaultage composition cannot revoke auto-allow grants.")
    }
    func listGrants() async throws -> [GrantSummary] { [] }
    /// A facade with no cache has nothing to forget, and says so truthfully.
    @discardableResult func lockGrantSecrets() async throws -> Int { 0 }
    /// A facade that has not implemented provisioning says so, rather than
    /// pretending there is nothing to provision.
    func provision(_ request: ProvisioningRequest) async throws -> ProvisioningOutcome {
        throw VaultageError.unsupported("This Vaultage composition cannot run the provisioning conversation.")
    }
    /// A facade that has not implemented the inventory says so rather than
    /// reporting an empty one — an empty inventory and an unavailable one are
    /// different answers, and only one of them means "you have no resources".
    func searchInventory(_ query: InventoryQuery) async throws -> InventoryPage {
        throw VaultageError.unsupported("This Vaultage composition cannot read the resources inventory.")
    }
    /// A facade that has not implemented delivery says so.
    @discardableResult func deliverForAgent(_ request: CredentialDeliveryRequest) async throws -> CredentialDeliveryOutcome {
        throw VaultageError.unsupported("This Vaultage composition cannot deliver a credential.")
    }
}

extension VaultageBroker: BrokerFacade {}

/// The owner's flows in the app that need the broker's custody: the Resources
/// inventory's refresh and bind, credential delivery and verify-deployed, and
/// rotation (BL-092, BL-094).
///
/// They were reachable only on an in-process `VaultageBroker`, so a signed
/// build — which keeps custody in the nested broker service — refused every
/// one of them with a sentence about provisioning (found 2026-09-21, building
/// D71). Both compositions now carry them: `VaultageBroker` in process, and
/// `XPCBrokerClient` over the broker protocol's version 13.
///
/// **Not on `BrokerFacade`, and not called by the MCP server** — except that
/// a delivery has an agent's door of its own, `deliverForAgent`, on
/// `BrokerFacade` (D71). Over XPC any process with the app's signature can
/// reach these selectors — the desktop app and the `--mcp` process are the
/// same binary — exactly as, in process, any code in that process could reach
/// the `VaultageBroker` it holds. What keeps them the owner's is the same in
/// both: the MCP server's code calls none of them, and every one still raises
/// its own native sheet.
public protocol DesktopBrokerFacade: BrokerFacade {
    func refreshInventory(connectionID: UUID, force: Bool) async throws -> InventoryRefreshReport
    func bindInventoryResource(resourceID: UUID, environmentID: UUID) async throws -> InventoryBindOutcome
    @discardableResult func deliverCredential(_ request: CredentialDeliveryRequest) async throws -> CredentialDeliveryOutcome
    @discardableResult func verifyDeployedCredentials(environmentID: UUID) async throws -> DeployedVerificationReport
    func planRotation(_ request: CredentialRotationRequest) async throws -> CredentialRotation
    @discardableResult func runRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress
    @discardableResult func revokeRotatedCredential(_ rotationID: UUID) async throws -> CredentialRotationProgress
    @discardableResult func completeRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress
    @discardableResult func cancelRotation(_ rotationID: UUID) async throws -> CredentialRotationProgress
    /// BL-073/BL-074's human steps of a provisioning conversation, and the
    /// approved revocation of a provisioned resource. The broker re-resolves
    /// everything and raises its own sheet; the window contributes the pick.
    func resolveProvisioningSelection(_ provisioningID: UUID, vaultItemID: UUID) async throws -> ProvisioningOutcome
    func resolveProvisioningCreation(_ provisioningID: UUID, target: CloudflareTokenTarget, label: String) async throws -> ProvisioningOutcome
    func denyProvisioning(_ provisioningID: UUID) async throws
    func revokeProviderResource(_ provisionedResourceID: UUID) async throws -> ProviderResourceRevocation
    /// BL-136 step 5. Revokes an agent: its record, its Keychain binding and
    /// every grant keyed on it. The owner's, in Settings → Agents.
    @discardableResult func revokeAgent(_ clientID: UUID) async throws -> EnrolledClient
}

extension VaultageBroker: DesktopBrokerFacade {
    /// The app binds with the scope's default operations; the fuller form,
    /// with an explicit operation set, stays on `VaultageBroker`.
    public func bindInventoryResource(resourceID: UUID, environmentID: UUID) async throws -> InventoryBindOutcome {
        try await bindInventoryResource(resourceID: resourceID, environmentID: environmentID, operations: nil)
    }
}

