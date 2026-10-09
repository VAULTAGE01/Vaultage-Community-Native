import Foundation
import VaultageCore

// The generic, value-free custody protocol shared by both peers.
//
// Nothing here names a provider, a bundle identifier, a signing authority or a
// packaging artifact: it is the shape of the boundary, not the identity of the
// processes on either side of it. Peer identity lives in `BrokerContract.swift`,
// which is why this half can be exported to the open core and that half cannot.

/// Value-free reply status. Every failure crosses as one of these plus an
/// already-redacted public sentence; no provider body, path or credential
/// material is ever carried in a reply.
public enum BrokerWireStatus: Int32, Sendable {
    case success = 0
    case incompatibleProtocol = 1
    case invalidPayload = 2
    case approvalDenied = 3
    case policyDenied = 4
    case failed = 5
    case transportFailure = 6
    case resultUnknown = 7
}

/// **The role a client declares when it negotiates** (contract version 13).
///
/// The app window and the `--mcp` process are the same signed bundle, so the
/// code-signing requirement admits both to the same exported object. What
/// tells them apart is this declaration, made once at negotiation and fixed
/// for the connection: an `agent` connection is refused every one of the
/// owner's desktop flows (`BrokerDesktopSelector`) — the door that skips the
/// agent's source rule among them — however its process came to ask. It is
/// declared by Vaultage's own code in the calling process, never by an agent,
/// and it narrows only: a `desktop` connection reaches everything an `agent`
/// one does. Contract 12 had this separation because the service exported no
/// desktop flow at all; 13 exports them, and this keeps the MCP process where
/// 12 left it.
public enum BrokerConnectionRole: Int32, Sendable, CaseIterable {
    /// The `--mcp` process, serving an agent over stdio.
    case agent = 1
    /// The app window: the owner's flows as well.
    case desktop = 2

    public var reachesDesktopFlows: Bool { self == .desktop }
}

/// The selectors an `agent` connection is refused, by name, so the rule is
/// data a test reads against the protocol rather than a guard hidden in each
/// method. Every method of `DesktopBrokerFacade` is here and nothing else is.
public enum BrokerDesktopSelector: String, Sendable, CaseIterable {
    case refreshInventory, bindInventoryResource, deliverCredential, verifyDeployedCredentials
    case planRotation, runRotation, revokeRotatedCredential, completeRotation, cancelRotation
    case resolveProvisioningSelection, resolveProvisioningCreation, denyProvisioning, revokeProviderResource
    // Contract 14 (BL-136 step 5): the owner revokes a paired agent.
    case revokeAgent

    /// The Objective-C selector name the protocol carries for it.
    public var selectorName: String { "\(rawValue):withReply:" }
}

/// **Every custody selector, and who may call it** (audit H-06). One
/// default-deny table: a selector not listed here is not on the protocol (a
/// test enumerates the protocol and compares), and a selector an `agent`
/// connection may call is one of the nine below — the value-free reads, an
/// action under its own approval, grants, the lock, and the agent's own
/// delivery door. Everything else is the owner's: the desktop flows, the
/// remote-approval surface and the vault-custody surface.
public enum BrokerSelector: String, Sendable, CaseIterable {
    // What an agent's process is for.
    case identifyClient, fetchStatus, executeAction, recoverDurableReceipts
    case createGrant, revokeGrant, listGrants, lockGrantSecrets, deliverCredentialForAgent
    // Contract 14 (BL-136 step 3): the agent pairs itself, with the person at the Mac.
    case pairAgent, provision, searchInventory
    // The owner's desktop flows (`DesktopBrokerFacade`).
    case refreshInventory, bindInventoryResource, deliverCredential, verifyDeployedCredentials
    case planRotation, runRotation, revokeRotatedCredential, completeRotation, cancelRotation
    case resolveProvisioningSelection, resolveProvisioningCreation, denyProvisioning, revokeProviderResource
    case revokeAgent, attestFixture
    // The remote-approval surface (contract 9/10).
    case listPairedDevices, unpairDevice, applyRemoteDecision, armRemoteGrant, remoteArmingPrompt
    case remoteMirroringSetting, acknowledgeRemoteMirroringConsent, moveRemoteMirroring
    // The vault-custody surface (contract 11).
    case applyHead, stage, watermark, liveness, fenceState, renderList, openMetadataPlane, writeMetadata
    case enqueueLocalDeletion, listLocalDeletions, restoreLocalDeletion, restoreAllLocalDeletions

    /// Whether a connection that negotiated as `agent` may call it.
    public var agentMayCall: Bool {
        switch self {
        case .identifyClient, .fetchStatus, .executeAction, .recoverDurableReceipts,
             .createGrant, .revokeGrant, .listGrants, .lockGrantSecrets, .deliverCredentialForAgent,
             .pairAgent, .provision, .searchInventory:
            return true
        default:
            return false
        }
    }

    public func admits(_ role: BrokerConnectionRole) -> Bool {
        role == .desktop || agentMayCall
    }

    /// The Objective-C selector name the protocol carries for it.
    public var selectorName: String {
        switch self {
        case .fetchStatus: return "fetchStatusWithIncludeBindings:withReply:"
        case .recoverDurableReceipts, .listGrants, .lockGrantSecrets, .listPairedDevices, .remoteMirroringSetting:
            return "\(rawValue)WithReply:"
        default:
            return "\(rawValue):withReply:"
        }
    }
}

/// The two delivery selectors and the door each one is. The service's export
/// has one delivery body, keyed by this — so which door a request came through
/// is this table, pinned by a test, and not two near-identical methods one of
/// which could quietly call the other's broker method.
public enum BrokerDeliverySelector: String, Sendable, CaseIterable {
    case deliverCredential, deliverCredentialForAgent

    public var door: DeliveryDoor { self == .deliverCredential ? .owner : .agent }
    public var selectorName: String { "\(rawValue):withReply:" }
}

/// The custody interface. It carries UTF-8 JSON strings whose shapes are fixed
/// by `BrokerWire`: an action request of opaque identifiers, and
/// projections that are already permitted to reach an MCP client. No `Data`,
/// no Keychain persistent reference, no file path and no caller-chosen URL.
@objc public protocol VaultageBrokerXPCProtocol {
    /// `role` is `BrokerConnectionRole`'s raw value. A version this build does
    /// not speak, or a role it does not know, is refused here and the
    /// connection reaches nothing else. **Once.** A second negotiation on the
    /// same connection is refused and changes nothing (audit H-06): the role
    /// is fixed by the first, and a client that wants another opens another
    /// connection — which the service admits on its own signature again.
    func negotiateVersion(_ version: Int32, role: Int32, withReply reply: @escaping (Int32) -> Void)
    /// BL-069. Carries the client's own enrollment authenticator so the broker
    /// — which is the verifier, and the only process holding the hashes — can
    /// resolve it to an enrolled name. See `ClientAuthenticationWire` for why
    /// the preimage rather than a digest is what crosses, and why this is not
    /// a credential in the sense the rest of this boundary uses the word.
    /// **Once** per connection, like negotiation (audit H-06): the identity
    /// a connection presented is the identity every sheet on it names.
    func identifyClient(_ credentialJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func fetchStatus(includeBindings: Bool, withReply reply: @escaping (Int32, NSString?) -> Void)
    func executeAction(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func recoverDurableReceipts(withReply reply: @escaping (Int32, NSString?) -> Void)
    /// BL-060. Grant creation happens inside the broker because the approval,
    /// the OS authentication and the secret cache the grant arms all belong on
    /// the custody side. What crosses is a request of opaque identifiers and a
    /// duration, and a reply of labels and a countdown.
    func createGrant(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func revokeGrant(_ grantID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func listGrants(withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Lock. Clears the broker's cached secrets; the grants stay armed as
    /// metadata and re-arm with one Touch ID.
    func lockGrantSecrets(withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Contract 14 (BL-136 step 3). `vaultage_pair`'s two calls. The request is
    /// `AgentPairingRequest`; the reply is `AgentPairingOutcome`, whose `code`
    /// is set on the first call only — the one place the code leaves the
    /// broker.
    func pairAgent(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Contract 14 (BL-136 step 5). The owner revokes a paired agent: its
    /// record, its binding and every grant keyed on it. Desktop only.
    func revokeAgent(_ clientID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)

    // MARK: Contract version 13 — the owner's desktop flows
    //
    // `DesktopBrokerFacade`, one selector each; `BrokerDesktopSelector` lists
    // them. Every one raises its own native sheet on the custody side, and
    // every one is refused on a connection that negotiated as `agent`
    // (`BrokerConnectionRole`): the MCP server calls none of them and, over
    // this boundary, cannot.
    func refreshInventory(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func bindInventoryResource(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func deliverCredential(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func verifyDeployedCredentials(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func planRotation(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func runRotation(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func revokeRotatedCredential(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func completeRotation(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func cancelRotation(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// D71. The agent's door to a delivery (`BrokerFacade.deliverForAgent`):
    /// the same delivery as `deliverCredential`, with the agent's source rule
    /// and the requester named. Which door a request came through is the
    /// selector, chosen by Vaultage's own code in the calling process.
    func deliverCredentialForAgent(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// BL-073/BL-074's human steps of the provisioning conversation, and the
    /// separate approved revocation of a provisioned resource. Desktop flows
    /// like the ones above: each raises its own sheet — the creation and the
    /// revocation their own approval classes, whose disclosures now cross on
    /// `ApprovalWire` — and each is refused on an `agent` connection. The
    /// requests are `ProvisioningSelectionWire`, `ProvisioningCreationWire`
    /// and `DesktopIdentifierWire`.
    /// Test attestation returns only a Boolean; production always refuses.
    func attestFixture(_ projectID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Agent requests only opaque identifiers and receives value-free outcomes.
    /// Human selection/creation still requires the desktop-only selectors below.
    func provision(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Cached reads only; agents cannot refresh inventory or bind resources.
    func searchInventory(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func resolveProvisioningSelection(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func resolveProvisioningCreation(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func denyProvisioning(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    func revokeProviderResource(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)

    // MARK: BL-099 — remote approvals (contract version 9)

    /// **Pin management.** The paired phones, as labels and identifiers.
    /// Thumbprints do not cross: the app has no use for one it could not verify
    /// a signature with anyway, and §2.4's whole control is that the pin lives
    /// on the custody side.
    func listPairedDevices(withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Unpair, which stamps §4.6's durable kill switch on every grant that
    /// device created and records all five thumbprints in
    /// `everRevokedKeyThumbprints`. Not reversible by re-pairing.
    func unpairDevice(_ phoneDeviceID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// **Applying a verified remote decision**, exactly as a native one (§4.5).
    /// The twelve §4.3 checks run **inside the broker**, against the pin and the
    /// retained field lists, which are custody-side state — the app is not
    /// trusted to have verified anything and does not carry the signature.
    /// What crosses is the pending id; what comes back is what happened.
    func applyRemoteDecision(_ pendingID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// **The arming touch** (§4.7 layer 7). Raises one presence prompt bound to
    /// this grant, with the full `GrantDisclosure` the owner already approved,
    /// and arms it. Until this returns success the grant authorizes nothing.
    func armRemoteGrant(_ grantID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// The content the arming prompt must render, so the app presents what the
    /// broker composed rather than composing its own.
    ///
    /// **Named `…Prompt`, not `…Disclosure`, deliberately.** BL-062's surface
    /// assertion bans any selector containing `disclos` from this protocol, so
    /// that an MCP subprocess acting as an XPC client has nothing that looks
    /// like a reveal to call. This method returns labels an owner already
    /// approved and no value at all — but the ban is a blunt, name-based rule
    /// and blunt is what makes it hold, so the method takes the other name.
    func remoteArmingPrompt(_ grantID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)

    // MARK: BL-099 — the mirroring switch (contract version 10)

    /// What this Mac's "Approve on my phone" switch says right now, read from
    /// the same `MetadataStore` the broker publishes from — never from the
    /// caller. The reply is `RemoteMirroringSettingWire`.
    func remoteMirroringSetting(withReply reply: @escaping (Int32, NSString?) -> Void)
    /// §3.7's consent moment. `phoneDeviceID` crosses as a plain string, the
    /// same way `unpairDevice` names a pairing — it is a label the receipt
    /// already carries, not a credential. The reply is the updated
    /// `RemoteMirroringSettingWire`, landed on *When I'm away*, never *Always*.
    func acknowledgeRemoteMirroringConsent(_ phoneDeviceID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// The three-position control. `position` crosses as
    /// `RemoteMirrorEligibility.Position`'s own `rawValue` — `"off"`,
    /// `"when_away"` or `"always"` — and a string outside that closed set is
    /// refused as `invalidPayload` before it reaches the broker. The reply is
    /// the updated `RemoteMirroringSettingWire`.
    func moveRemoteMirroring(_ position: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)

    // MARK: BL-100 slice A — multi-device vault custody (contract version 11)

    // §3.2's table, slice A's rows. **There is no operation that returns a
    // sealed record, a wrap row, or raw store bytes to the app, and no
    // enumeration of either.** That is the bound — a container plus an RPC hop
    // is an indirection, and what bounds "read the sealed store from disk" is
    // what this interface returns, and what it **accepts**.
    //
    // The three spend points — `openItemKey`, `readKeychainAccount`,
    // `openVaultContentKey` — are deliberately **not** here. They are the
    // broker's closed internal surface: putting `openVaultContentKey` on this
    // protocol would give the app a way to ask for `VCK_v`, which contradicts
    // flow 7 having exactly one caller inside the broker.
    //
    // §7.3 part C's `pendingRun`, `deletionRun`, `foldExempt`, `confirm` and
    // `undo` are **BL-110's** and must not appear here: a builder satisfying a
    // presence-only floor would otherwise ship a method for a mechanism slice A
    // forbids them to build.

    /// §7.1 stage 2. The **broker** performs apply; the app hands over verified
    /// ciphertext it fetched and never decrypts. **No key, no presence, runs
    /// locked.** An arriving revision is stored beside the record's last
    /// revision that opened, never over it.
    func applyHead(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Transfer's staging path — ciphertext in, **no read-back**.
    func stage(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// `(keyGeneration, headSeq, headDigest)`, so the app knows what to fetch
    /// and what to anchor a backwards walk on. **Value-free.**
    func watermark(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// §3.3's C-2 screen — *"your iPhone last saw this Mac 3 days ago"*. The
    /// `acks` vector, value-free. Only the broker holds the head.
    func liveness(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// §3.3's accumulator: its elapsed time and the unsent-changes count, from
    /// **broker-owned** state the app cannot write.
    func fenceState(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// `item`, `folder` and `vault` projections only — labels, folder tree, item
    /// types, revisions, counts, attachment names and sizes, plus the count of
    /// applied records not yet folded in. **No `value` record, no wrap row, no
    /// ciphertext. Presence: none.**
    func renderList(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// §2.4.1's **flow 7**. The broker enters the flow itself when it needs
    /// `VCK_v`; this row exists so the app can ask for it **at a moment the owner
    /// expects a prompt**. Presence-gated, one prompt per vault, **no value
    /// returned**.
    func openMetadataPlane(_ vaultIDsJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// Seals a `vault`, `item` or `folder` record for sync. Needs `VCK_v`, so it
    /// runs **inside** flow 7, and the broker enters the flow if it is not
    /// already in one.
    func writeMetadata(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// §7.3 part A. **No presence** — nothing is destroyed and nothing leaves
    /// the device.
    func enqueueLocalDeletion(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// **Value-free projections** of the suppressed records — the same fields
    /// `renderList` returns, filtered to the queue, plus `queuedAt`.
    func listLocalDeletions(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// **Presence-gated**, on a context the restore path constructs for that
    /// call at reuse duration `0`, invalidated as soon as the evaluation returns
    /// and **before any queue entry is touched**. Not an `OwnerAuthentication`,
    /// takes none, yields no token, returns nothing spendable.
    func restoreLocalDeletion(_ requestJSON: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
    /// **One proof for the whole queue, however large it is.**
    func restoreAllLocalDeletions(_ vaultID: NSString, withReply reply: @escaping (Int32, NSString?) -> Void)
}

/// The reverse interface. The broker decides *whether* an approval is required
/// and *what* it must disclose; the client process owns the window server
/// connection and merely presents the sheet the broker composed. The reply is
/// one bit.
@objc public protocol VaultageApprovalXPCProtocol {
    func presentApproval(_ detailsJSON: NSString, withReply reply: @escaping (Bool) -> Void)
    /// Contract 14 (BL-136 step 3). The pairing sheet: `PairingSheetDetails`
    /// in, and what the person typed (`PairingSheetReply`) or nil for a
    /// dismissed sheet back. The code is typed, never shown.
    func presentPairing(_ detailsJSON: NSString, withReply reply: @escaping (NSString?) -> Void)
}
