import CryptoKit
import Foundation
import LocalAuthentication

/// BL-060 — scoped, time-boxed auto-allow grants.
///
/// This is the first thing in Vaultage that lets a provider action run without a
/// human looking at a sheet, so the whole file is written to be read as an
/// authorization model rather than a convenience.
///
/// **What a grant is.** A durable, local record that says: for this scope, for
/// these environments, for these exact bindings and the operations those
/// bindings already allow, until this instant, an action that is *byte-for-byte
/// the situation the human approved* may skip the approval sheet. Nothing else.
///
/// **What a grant is not.** It is not a credential, it does not widen any
/// binding, it does not survive a change to the records it covers, it cannot be
/// used by an unenrolled client, and it never removes a re-validation step, a
/// receipt, or a policy check. An auto-allowed action runs the identical code
/// path as an approved one with exactly one branch skipped: the sheet.
///
/// **The identity caution from BL-069 §9.** The moment a grant keys on an
/// enrolled client id, the bearer credential that lives in the MCP host's
/// environment becomes an authorization input for the first time. That is a real
/// widening and it is recorded, not hidden — see the evidence note. What this
/// file does about it: a grant never covers a production environment unless the
/// human included it with a warning, never covers the runtime-delivery
/// operation at all, never outlives a credential rotation or a revocation of the
/// client it names, and never survives any change to the covered records.

public enum GrantDuration: String, Codable, CaseIterable, Sendable {
    case oneDay, twoDays, sevenDays

    /// The three durations D6 fixed. There is deliberately no custom value: a
    /// free-form interval is one typo away from a grant nobody remembers making.
    public var seconds: TimeInterval {
        switch self {
        case .oneDay: 24 * 60 * 60
        case .twoDays: 2 * 24 * 60 * 60
        case .sevenDays: 7 * 24 * 60 * 60
        }
    }

    public var label: String {
        switch self {
        case .oneDay: "1 day"
        case .twoDays: "2 days"
        case .sevenDays: "7 days"
        }
    }
}

/// Scope, as a flat inspectable shape rather than an enum with payloads, for the
/// same reason `ClientIdentity` is flat: it crosses a boundary and is asserted
/// against a permitted key set.
///
/// A decoded value is never trusted to be coherent. `isWellFormed` is what every
/// decision consults, and an incoherent record simply never matches.
public struct GrantScope: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Hashable, Sendable, CaseIterable {
        /// D6's "this agent". Requires a durable enrolled client id (BL-069);
        /// a display name is not an identity.
        case client
        /// D6's "the project(s)".
        case projects
    }

    public let kind: Kind
    public let clientID: UUID?
    public let projectIDs: Set<UUID>

    public init(client id: UUID) { kind = .client; clientID = id; projectIDs = [] }
    public init(projects ids: Set<UUID>) { kind = .projects; clientID = nil; projectIDs = ids }

    public var isWellFormed: Bool {
        switch kind {
        case .client: clientID != nil && projectIDs.isEmpty
        case .projects: clientID == nil && !projectIDs.isEmpty && projectIDs.count <= Grant.maximumScopeProjects
        }
    }

    /// Canonical, order-independent fields for the digest. Each element is a
    /// field of its own and the project list states its length, so the encoding
    /// stays injective (RP-07).
    var canonicalFields: [String] {
        let projects = projectIDs.map(\.uuidString).sorted()
        return [kind.rawValue, clientID?.uuidString ?? "none", "\(projects.count)"] + projects
    }
}

/// One covered binding and the operations the grant may auto-allow on it. The
/// set is derived from the binding's own `allowedOperations` at creation, so a
/// grant can only ever narrow a binding, never widen one.
public struct GrantBinding: Codable, Hashable, Sendable {
    public let bindingID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let allowedOperations: Set<Operation>

    public init(bindingID: UUID, projectID: UUID, environmentID: UUID, allowedOperations: Set<Operation>) {
        self.bindingID = bindingID
        self.projectID = projectID
        self.environmentID = environmentID
        self.allowedOperations = allowedOperations
    }

    /// Canonical fields for the digest; see `CanonicalDigest` for why this is a
    /// field list rather than a joined string (RP-07).
    var canonicalFields: [String] {
        let operations = allowedOperations.map(\.rawValue).sorted()
        return ["binding", bindingID.uuidString, projectID.uuidString, environmentID.uuidString, "\(operations.count)"] + operations
    }
}

public struct Grant: Codable, Identifiable, Hashable, Sendable {
    /// Bumped whenever the *rules* in this file change. A grant created under an
    /// older revision stops authorizing the instant a new build runs, because a
    /// human approved the old rules and not the new ones.
    /// v3 (BL-091): mutations exist, and a grant must name one explicitly
    /// before it can cover it. Every v2 grant stops authorizing the instant
    /// this build runs, which is the correct outcome — a human approved a sheet
    /// that listed only reads, and the rules under it have changed.
    ///
    /// v4 (BL-099 / BL-095 §4.6, DB-H15): a grant can now be created by a phone,
    /// so it gains a deciding device, an arming stamp and a durable kill stamp,
    /// and `coveringDigest` gains an unconditional device section.
    /// **This is a real bump with a real cost**: every outstanding grant stops
    /// authorizing when this build runs, because a human approved the old rules.
    /// Version 3 of the protocol specified a bump "to v3" when the shipped value
    /// was already v3 — a no-op whose test asserted a constant equal to itself,
    /// which is §12 item 16's finding and the reason
    /// `grantsCreatedUnderV3StopAuthorizingAfterUpgrade` is written as a test
    /// that **can fail**.
    public static let currentPolicyRevision = "vaultage.autoallow.v4"
    public static let maximumGrants = 32
    public static let maximumScopeProjects = 16
    public static let maximumEnvironments = 32
    public static let maximumBindings = 64

    public let id: UUID
    public let scope: GrantScope
    /// The environments this grant covers. Kept explicitly as well as implied by
    /// `bindings`, and required to agree with them, so a hand-edited record that
    /// disagrees with itself is refused rather than resolved in someone's favour.
    public let environmentIDs: Set<UUID>
    public let bindings: [GrantBinding]
    /// Whether this grant actually covers a production environment — derived
    /// from the covered environments, not copied from the request's
    /// `includeProduction` permission (RP-06), so the stored record and the
    /// Activity row say exactly what the approval sheet showed. It is also in
    /// the digest, so promoting a covered environment to production ends the
    /// grant rather than silently widening it.
    public let includesProduction: Bool
    public let createdAt: Date
    public let duration: GrantDuration
    public let expiresAt: Date
    public var revokedAt: Date?
    public let policyRevision: String
    /// SHA-256 over every record this grant depends on: scope, the enrolled
    /// client's current credential hash, each binding and its operations, the
    /// connection and its plan/pause state, the vault item, its Keychain account
    /// and credential version, the provider contract revision and principal, and
    /// each environment's production flag. Any change to any of it denies.
    public let digest: String
    /// BL-095 §4.6. The roster device id of the phone whose signed decision
    /// created this grant. `nil` for a locally created grant, and decoded with
    /// `decodeIfPresent` exactly as `grantID` was on the receipt, so every grant
    /// written before this build decodes as local.
    public let decidingDeviceID: String?
    /// BL-095 §4.7 layer 7 / §11. When a **local presence proof** armed this
    /// grant. A remotely created grant commits with `armedAt == nil` and
    /// authorizes nothing until the owner touches the Mac once.
    ///
    /// Deliberately **not** in the digest: arming would otherwise invalidate the
    /// grant it arms.
    public var armedAt: Date?
    /// BL-095 Q17. A durable stamp written at the moment of unpairing or of
    /// verifying a DSRL entry — a fact recorded once, not a lookup.
    ///
    /// It survives re-pairing, which a digest-only denial does not: the `apv`
    /// key is a Secure Enclave key that unpairing does not destroy, so a second
    /// ceremony with the same phone reproduces the same thumbprint, the digest
    /// resolves again, and every grant that phone created would **resume
    /// authorizing** — containment becoming a pause. And the owner could not
    /// recognise the effect either: a digest-resolution failure surfaces as "a
    /// record this grant covers has changed", which is a message about records
    /// for an act about devices. Also **not** in the digest; the stamp is the
    /// authority.
    public var deviceKillSwitch: Date?

    /// BL-136 step 1 (D70 amendment 2). HMAC-SHA256 over this grant's identity
    /// and approved shape under a key only this Mac's signed Vaultage binaries
    /// hold (`GrantSigning`). Stamped at commit and at arming; a grant whose
    /// MAC is absent or wrong authorizes nothing, however good its `digest`.
    /// Absent from every grant written before schema 29, which is the point:
    /// such a grant, and any grant written by something other than the
    /// broker, is not one the owner approved under these rules.
    public var mac: String?

    public init(id: UUID = UUID(), scope: GrantScope, environmentIDs: Set<UUID>, bindings: [GrantBinding], includesProduction: Bool, createdAt: Date, duration: GrantDuration, expiresAt: Date, revokedAt: Date? = nil, policyRevision: String = Grant.currentPolicyRevision, digest: String, decidingDeviceID: String? = nil, armedAt: Date? = nil, deviceKillSwitch: Date? = nil, mac: String? = nil) {
        self.id = id
        self.scope = scope
        self.environmentIDs = environmentIDs
        self.bindings = bindings
        self.includesProduction = includesProduction
        self.createdAt = createdAt
        self.duration = duration
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.policyRevision = policyRevision
        self.digest = digest
        self.decidingDeviceID = decidingDeviceID
        self.armedAt = armedAt
        self.deviceKillSwitch = deviceKillSwitch
        self.mac = mac
    }

    /// `true` when a phone's signed decision created this grant.
    public var isRemote: Bool { decidingDeviceID != nil }

    /// §4.7 layer 7. A remote grant that has not been armed yet: it exists, it
    /// is well formed, and it authorizes **nothing**.
    public var isPendingArm: Bool { isRemote && armedAt == nil && deviceKillSwitch == nil }

    /// Everything that must hold before a grant is even looked at. A record that
    /// fails any of this never matches anything; it is not repaired.
    public var isWellFormed: Bool {
        guard scope.isWellFormed,
              policyRevision == Self.currentPolicyRevision,
              !bindings.isEmpty, bindings.count <= Self.maximumBindings,
              !environmentIDs.isEmpty, environmentIDs.count <= Self.maximumEnvironments,
              environmentIDs == Set(bindings.map(\.environmentID)),
              bindings.allSatisfy({ !$0.allowedOperations.isEmpty && $0.allowedOperations.allSatisfy(\.isAutoAllowable) }),
              Set(bindings.map(\.bindingID)).count == bindings.count,
              digest.count == 64,
              createdAt.timeIntervalSince1970.isFinite, expiresAt.timeIntervalSince1970.isFinite,
              expiresAt > createdAt
        else { return false }
        // The stated duration and the stored expiry must be the same fact. This
        // is what stops a lengthened `expiresAt` from quietly turning a one-day
        // grant the human approved into a seven-day one.
        return abs(expiresAt.timeIntervalSince(createdAt.addingTimeInterval(duration.seconds))) < 1
    }

    /// §4.6 consequence 2. A grant created by a phone authorizes nothing until
    /// the owner touches the Mac once, and stops authorizing for good the moment
    /// that phone is unpaired or a verified revocation names it.
    ///
    /// A **local** grant is unchanged: `decidingDeviceID == nil` short-circuits
    /// both clauses, which is why the device section of the digest is
    /// unconditional with sentinels rather than conditional — existing local
    /// grants survive by a stated rule instead of by accident.
    public func isUsable(at instant: Date) -> Bool {
        guard isWellFormed, revokedAt == nil, instant >= createdAt, instant < expiresAt else { return false }
        return decidingDeviceID == nil || (armedAt != nil && deviceKillSwitch == nil)
    }

    public func remainingSeconds(at instant: Date) -> Int {
        guard isUsable(at: instant) else { return 0 }
        return max(0, Int(expiresAt.timeIntervalSince(instant)))
    }

    /// D19 / RP-01. How long provider verification counts as current while this
    /// grant is running.
    ///
    /// RP-01 found that a grant the sheet promised for days stopped authorizing
    /// about fifteen minutes later, because `requireCurrentVerification` demands
    /// evidence younger than `ConnectionVerification.maxAge` on every action and
    /// nothing in Vaultage refreshes that evidence in the background. The owner
    /// ruled (D19) for the best experience that is technically and securely
    /// sound: while a grant is active *and covers the request*, the freshness
    /// ceiling is the grant's own remaining duration, so the verification the
    /// human had in front of them when they authorised the grant stays current
    /// for exactly as long as the grant they authorised. Background
    /// re-verification stays off: nothing here re-contacts a provider.
    ///
    /// Three conditions, all required, all fail-closed:
    ///
    /// * the grant must be usable at `instant` — well formed, unrevoked,
    ///   started and unexpired;
    /// * the evidence must not be future-dated;
    /// * the evidence must have been *current under the ordinary 15-minute rule
    ///   at the moment the grant was created*. A grant cannot resurrect
    ///   verification that was already stale when the human approved it, so the
    ///   window this opens is only ever the one the human was looking at.
    ///
    /// Returning `nil` means "no ceiling of mine applies", and the caller falls
    /// back to the 15-minute rule. Nothing here can shorten that rule: the
    /// returned instant is combined with it by `permits(_:item:provider:at:freshUntil:)`
    /// taking the later of the two.
    ///
    /// This changes *when evidence goes stale*. It changes nothing else: the
    /// covering digest is still re-proved three times per action against freshly
    /// loaded state, so a rotated credential, a re-pointed or widened binding, a
    /// paused plan, a promoted environment, a revoked client and a revoked grant
    /// each still end the grant immediately.
    public func verificationFreshnessCeiling(for evidence: ConnectionVerification, at instant: Date) -> Date? {
        guard isUsable(at: instant),
              evidence.verifiedAt.timeIntervalSince1970.isFinite,
              evidence.verifiedAt <= instant,
              evidence.verifiedAt.addingTimeInterval(ConnectionVerification.maxAge) >= createdAt
        else { return nil }
        return expiresAt
    }

    /// The digest over the records this grant covers, computed from the state it
    /// is handed. Throws when a covered record is missing, which is itself a
    /// denial: a grant cannot cover something that no longer exists.
    /// BL-099 / §4.6 consequence 1 and §12 item 18. The signature gains
    /// `decidingDeviceID`; the pinned thumbprint and `pinGeneration` are
    /// resolved from `state`, which is why §2.4's pin records live in
    /// `VaultageMetadata` — `coveringDigest` is a pure function of `state` and
    /// must stay one (Q17 item 2).
    public static func coveringDigest(scope: GrantScope, environmentIDs: Set<UUID>, bindings: [GrantBinding], includesProduction: Bool, decidingDeviceID: String? = nil, in state: VaultageMetadata) throws -> String {
        // RP-07. Every field below is length-prefixed by `CanonicalDigest`, and
        // each list states its own length, so the encoding is injective: a
        // provider-supplied field cannot absorb a separator and impersonate
        // several fields or several records. Field order is fixed here and
        // records are sorted, so the same covered set always encodes alike.
        var fields: [String] = ["vaultage.grant.covering"]
        fields.append(contentsOf: ["policy", currentPolicyRevision])
        fields.append(contentsOf: ["scope"] + scope.canonicalFields)
        fields.append(contentsOf: ["production", "\(includesProduction)"])
        let sortedEnvironments = environmentIDs.map(\.uuidString).sorted()
        fields.append(contentsOf: ["environments", "\(sortedEnvironments.count)"] + sortedEnvironments)
        // A client-scoped grant is bound to that client's *current* credential
        // hash, so rotating or re-issuing the credential ends the grant. The hash
        // is already the only credential-derived value Vaultage stores, and it
        // never leaves this computation.
        if scope.kind == .client {
            guard let clientID = scope.clientID,
                  let client = state.enrolledClients.first(where: { $0.id == clientID }),
                  client.isActive
            else { throw VaultageError.policyDenied("The client this grant names is no longer enrolled.") }
            fields.append(contentsOf: ["client", client.id.uuidString, client.credentialHash])
        } else {
            fields.append(contentsOf: ["client", "none", "none"])
        }
        let sortedBindings = bindings.sorted(by: { $0.bindingID.uuidString < $1.bindingID.uuidString })
        fields.append(contentsOf: ["bindings", "\(sortedBindings.count)"])
        for grantBinding in sortedBindings {
            guard let binding = state.bindings.first(where: { $0.id == grantBinding.bindingID }),
                  binding.projectID == grantBinding.projectID,
                  binding.environmentID == grantBinding.environmentID,
                  grantBinding.allowedOperations.isSubset(of: binding.allowedOperations),
                  let project = state.projects.first(where: { $0.id == binding.projectID }),
                  let environment = state.environments.first(where: { $0.id == binding.environmentID }),
                  environment.projectID == project.id,
                  let connection = state.connections.first(where: { $0.id == binding.connectionID }),
                  let item = state.vaultItems.first(where: { $0.id == connection.vaultItemID }),
                  MetadataRemoval.deletionReservation(forVaultItem: item.id, in: state) == nil
            else { throw VaultageError.policyDenied("A record this grant covers has changed or no longer exists.") }
            let evidence = connection.verification
            // `verifiedAt` is deliberately absent, and D19 settled why. Nothing
            // refreshes provider verification in the background; the only
            // writer is a human clicking "Re-verify". Folding the timestamp
            // into the digest would therefore make every grant stop matching
            // the moment the human re-verified *in a way they cannot diagnose*
            // — a digest mismatch reads as "a record you approved changed".
            // Currency is decided live instead, by
            // `requireCurrentVerification`, which runs on every auto-allowed
            // action three times against freshly loaded state; under D19 its
            // ceiling for a covered action is this grant's own remaining
            // duration (`verificationFreshnessCeiling(for:at:)`), and the
            // credential version this evidence attests *is* in the digest
            // below, so a rotation still ends the grant. What the human is told
            // is `GrantDisclosure.verificationCeilingSentence`.
            let operations = binding.allowedOperations.map(\.rawValue).sorted()
            fields.append(contentsOf: grantBinding.canonicalFields)
            fields.append(contentsOf: ["ops", "\(operations.count)"] + operations)
            fields.append(contentsOf: ["connection", connection.id.uuidString, connection.provider.rawValue, connection.state.rawValue])
            fields.append(contentsOf: ["plan", connection.pauseReason?.rawValue ?? "active", "\(state.freeActiveConnectionIDs.contains(connection.id))"])
            fields.append(contentsOf: ["item", item.id.uuidString, item.keychainAccount, item.credentialVersion?.uuidString ?? "none"])
            fields.append(contentsOf: ["evidence", evidence?.providerContractRevision ?? "none", evidence?.principalID ?? "unknown", evidence?.credentialVersion.uuidString ?? "none"])
            fields.append(contentsOf: ["environment", environment.id.uuidString, "\(environment.isProduction)"])
        }
        // §4.6 consequence 1. **Unconditional**, with sentinels for a local
        // grant, so the field list keeps the fixed arity `CanonicalDigest` was
        // written for. Version 3 left it conditional, which gives the digest
        // variable arity and makes existing local grants survive *by accident*
        // rather than by a stated rule.
        //
        // The thumbprint is the primary key of this section and the id is kept
        // for display (DB-L13): `decidingDeviceID` is a control-plane-assigned
        // UUID, while what a revocation kills is a key.
        fields.append(contentsOf: deviceSectionFields(decidingDeviceID: decidingDeviceID, in: state))
        return CanonicalDigest.hex(fields)
    }

    /// `["device", decidingDeviceID ?? "none", pairedApvThumbprint ?? "none", "\(pinGeneration)"]`.
    ///
    /// A local grant emits `"none", "none", "0"`. Generation `0` is the sentinel
    /// for "no pin": a real `pinGeneration` starts at 1 on the first ceremony,
    /// so no pinned device can collide with it.
    ///
    /// A deciding device with **no pin record** also emits the sentinels, which
    /// is correct and is not a hole: §4.3 step 2 has already refused an unpaired
    /// deciding device before any digest is computed, and a grant whose phone is
    /// later unpaired is ended by the durable `deviceKillSwitch` stamp rather
    /// than by this digest.
    static func deviceSectionFields(decidingDeviceID: String?, in state: VaultageMetadata) -> [String] {
        guard let decidingDeviceID,
              let pin = state.devicePairings.first(where: { $0.phoneDeviceID == decidingDeviceID && $0.isWellFormed })
        else { return ["device", decidingDeviceID ?? "none", "none", "0"] }
        return ["device", decidingDeviceID, pin.apvThumbprint, "\(pin.pinGeneration)"]
    }

    func recomputedDigest(in state: VaultageMetadata) throws -> String {
        try Self.coveringDigest(scope: scope, environmentIDs: environmentIDs, bindings: bindings, includesProduction: includesProduction, decidingDeviceID: decidingDeviceID, in: state)
    }
}

/// What the human is asked to create.
public struct GrantRequest: Codable, Hashable, Sendable {
    public let scope: GrantScope
    public let environmentIDs: Set<UUID>
    public let duration: GrantDuration
    /// Must be set explicitly, by a separate control, to cover a production
    /// environment. A request that names a production environment without it is
    /// refused rather than silently narrowed, so the human is never told a grant
    /// covers something it does not.
    public let includeProduction: Bool
    /// BL-091. The mutations this grant covers, named one by one.
    ///
    /// This is the whole of the grant-model change, and it is a narrowing, not
    /// a widening. Before BL-091 every operation a binding allowed was a read,
    /// so `prepare` could safely take the binding's whole allowed set. Now a
    /// binding can allow `cloudflare.dns_record.create`, and inheriting it
    /// would mean a human who ticked "auto-allow reads for this project" had
    /// silently also authorised unattended DNS creation.
    ///
    /// So the rule is: a **read** is covered by being in the binding; a
    /// **mutation** is covered only by being named here *and* being one that
    /// `ApprovalRequirement` says a grant may ever cover — which, per D34 and
    /// BL-091, is ordinary-trust create and update and nothing else. A delete,
    /// anything production-affecting and anything admin is refused here rather
    /// than dropped, for the same reason `includeProduction` refuses: a
    /// silently narrowed grant tells the human something untrue.
    ///
    /// Because an operation determines its own resource kind, naming the
    /// operation is also what scopes the grant to that resource kind.
    public let includedMutations: Set<Operation>

    public init(scope: GrantScope, environmentIDs: Set<UUID>, duration: GrantDuration, includeProduction: Bool = false, includedMutations: Set<Operation> = []) {
        self.scope = scope
        self.environmentIDs = environmentIDs
        self.duration = duration
        self.includeProduction = includeProduction
        self.includedMutations = includedMutations
    }
}

/// Exactly what the approval sheet states, as data. Labels and counts only.
public struct GrantDisclosure: Codable, Hashable, Sendable {
    /// The one sentence D6 requires the sheet to carry.
    public static let autoAllowSentence = "Matching actions will run without a prompt until this grant expires."
    /// A separate line, only when the grant covers a production environment.
    public static let productionWarning = "WARNING: this grant includes a production environment. Production actions will run without a prompt."
    /// BL-091. A separate line, only when the grant covers a mutation. It names
    /// what a mutation grant can and cannot reach, because "auto-allow" reads
    /// very differently once the verb is "create".
    public static let mutationWarning = "WARNING: this grant covers the changes listed below, not only reads. They will run without a prompt. Deleting anything, and every production-affecting change, still asks every time and always names the exact resource id — no grant can cover those."
    /// D19, owner decision of 2026-09-11, resolving RP-01. A covered action
    /// still requires provider verification evidence, and nothing in Vaultage
    /// refreshes that evidence in the background — only the human clicking
    /// "Re-verify" does. What D19 changed is how long the evidence counts as
    /// current: while this grant is active and covers the action, the ceiling
    /// is the grant's own remaining duration instead of fifteen minutes, so the
    /// duration on the sheet is the duration the human gets. Outside a grant,
    /// and for any action a grant does not cover, the fifteen-minute rule is
    /// unchanged. Background re-verification remains deliberately unbuilt.
    public static let verificationCeilingSentence = "A covered action also needs this connection's verification, and while this grant runs that verification stays current for the whole duration above — so the duration is what you get, not a ceiling you have to keep topping up. Outside this grant, verification counts as current for 15 minutes. Vaultage still never re-verifies on its own, and rotating the credential, changing the binding, or revoking the grant ends it immediately."

    public let scopeLabel: String
    public let durationLabel: String
    public let expiresAt: Date
    public let environmentLabels: [String]
    public let operationLabels: [String]
    public let includesProduction: Bool
    public let productionEnvironmentLabels: [String]
    /// BL-091. The mutations this grant would cover, each as "verb · resource ·
    /// operation id", and the resource kinds they reach. Empty for a
    /// reads-only grant, which is what every grant was before this ticket.
    public let mutationLabels: [String]
    public let mutationResourceKinds: [String]
    public let digest: String

    public init(scopeLabel: String, durationLabel: String, expiresAt: Date, environmentLabels: [String], operationLabels: [String], includesProduction: Bool, productionEnvironmentLabels: [String], mutationLabels: [String] = [], mutationResourceKinds: [String] = [], digest: String) {
        self.scopeLabel = scopeLabel
        self.durationLabel = durationLabel
        self.expiresAt = expiresAt
        self.environmentLabels = environmentLabels
        self.operationLabels = operationLabels
        self.includesProduction = includesProduction
        self.productionEnvironmentLabels = productionEnvironmentLabels
        self.mutationLabels = mutationLabels
        self.mutationResourceKinds = mutationResourceKinds
        self.digest = digest
    }
}

/// A prepared, not-yet-approved grant: the resolved coverage plus the disclosure
/// the sheet will state and the digest both sides must agree on.
public struct GrantDraft: Sendable {
    public let scope: GrantScope
    public let environmentIDs: Set<UUID>
    public let bindings: [GrantBinding]
    public let includesProduction: Bool
    public let duration: GrantDuration
    public let digest: String
    public let disclosure: GrantDisclosure
    /// BL-099 §4.6. `nil` for the local path, which is every caller before this
    /// ticket; the remote path names the phone whose signed decision this draft
    /// resolves, so the digest carries the device section that ends the grant
    /// when that pin changes.
    public var decidingDeviceID: String?
}

/// The value-free projection Activity renders: who, what, and how long is left.
public struct GrantSummary: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let scopeLabel: String
    public let clientName: String?
    public let projectNames: [String]
    public let environmentLabels: [String]
    public let operations: [String]
    public let includesProduction: Bool
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let isActive: Bool
    public let remainingSeconds: Int
    /// BL-136 step 1. Whether the record's MAC verifies — false for a grant
    /// from before the stamp existed and for one written by anything but the
    /// broker. Such a grant authorizes nothing and is shown as not honoured.
    public let isVerified: Bool

    public init(id: UUID, scopeLabel: String, clientName: String?, projectNames: [String], environmentLabels: [String], operations: [String], includesProduction: Bool, createdAt: Date, expiresAt: Date, revokedAt: Date?, isActive: Bool, remainingSeconds: Int, isVerified: Bool = true) {
        self.id = id
        self.scopeLabel = scopeLabel
        self.clientName = clientName
        self.projectNames = projectNames
        self.environmentLabels = environmentLabels
        self.operations = operations
        self.includesProduction = includesProduction
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.isActive = isActive
        self.remainingSeconds = remainingSeconds
        self.isVerified = isVerified
    }

    /// The countdown, as the human reads it. A grant that is not active says why
    /// rather than showing a zero.
    public var remainingLabel: String {
        if revokedAt != nil { return "Revoked" }
        // A record with time left that the broker will not honour — no stamp,
        // or not the broker's — says so; one that has run out is just expired.
        if !isVerified && remainingSeconds > 0 { return "Not honoured" }
        guard isActive else { return "Expired" }
        let hours = remainingSeconds / 3600
        if hours >= 24 { return "\(hours / 24)d \(hours % 24)h left" }
        if hours >= 1 { return "\(hours)h \((remainingSeconds % 3600) / 60)m left" }
        return "\(max(1, remainingSeconds / 60))m left"
    }
}

/// Preparation, matching, revocation and projection. Pure functions over
/// metadata, so every rule in this file is exercised by the self-test suite
/// without a Keychain, a file, an approval sheet or a Touch ID prompt.
public enum GrantPolicy {
    // MARK: Preparation

    /// Resolves a request into the exact coverage it would grant, or throws.
    ///
    /// Called twice per creation: once to compose the sheet, once after OS
    /// authentication to prove nothing moved underneath it.
    public static func prepare(_ request: GrantRequest, in state: VaultageMetadata, now: Date = Date(), decidingDeviceID: String? = nil) throws -> GrantDraft {
        guard request.scope.isWellFormed else {
            throw VaultageError.invalidInput("A grant needs either one enrolled client or at least one project.")
        }
        guard !request.environmentIDs.isEmpty, request.environmentIDs.count <= Grant.maximumEnvironments else {
            throw VaultageError.invalidInput("A grant covers between one and \(Grant.maximumEnvironments) environments.")
        }
        guard state.grants.filter({ $0.revokedAt == nil }).count < Grant.maximumGrants else {
            throw VaultageError.policyDenied("This Vaultage install already holds the maximum number of grants. Revoke one first.")
        }
        // BL-091. A requested mutation that no grant may ever cover is refused
        // here, not dropped: the human must not be shown a sheet that lists a
        // delete and then be given a grant that silently excludes it.
        for mutation in request.includedMutations {
            guard mutation.taxonomy.kind != .read else {
                throw VaultageError.invalidInput("\(mutation.rawValue) is a read; reads are covered by the binding and do not need to be named.")
            }
            guard mutation.approvalRequirement.requiresExplicitGrantInclusion else {
                throw VaultageError.policyDenied("\(mutation.rawValue) always asks for approval and names the exact resource; no grant can cover it.")
            }
        }

        var clientName: String?
        if request.scope.kind == .client {
            guard let clientID = request.scope.clientID,
                  let client = state.enrolledClients.first(where: { $0.id == clientID }), client.isActive
            else { throw VaultageError.policyDenied("Auto-allow for an agent requires an enrolled, active client.") }
            clientName = client.displayName
        }

        var environments: [Environment] = []
        for id in request.environmentIDs.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard let environment = state.environments.first(where: { $0.id == id }) else {
                throw VaultageError.invalidInput("A selected environment no longer exists.")
            }
            // Production is excluded unless explicitly included. Refusing rather
            // than dropping is the fail-closed choice: a silently narrowed grant
            // would tell the human something untrue about what they approved.
            if environment.isProduction, !request.includeProduction {
                throw VaultageError.policyDenied("Auto-allow excludes production environments. Include production explicitly to cover \(environment.name).")
            }
            if request.scope.kind == .projects, !request.scope.projectIDs.contains(environment.projectID) {
                throw VaultageError.invalidInput("A selected environment is not in the selected projects.")
            }
            environments.append(environment)
        }

        let environmentIDs = Set(environments.map(\.id))
        var bindings: [GrantBinding] = []
        for binding in state.bindings where environmentIDs.contains(binding.environmentID) {
            guard let environment = environments.first(where: { $0.id == binding.environmentID }),
                  environment.projectID == binding.projectID else { continue }
            // A grant can only narrow: the operation set starts as the binding's
            // own allowed set, minus anything that is not auto-allowable at all,
            // minus — BL-091 — every mutation the request did not name. A read
            // is covered by being in the binding; a mutation is covered only by
            // being asked for.
            let operations = binding.allowedOperations.filter {
                guard $0.isAutoAllowable else { return false }
                guard $0.taxonomy.kind != .read else { return true }
                return request.includedMutations.contains($0)
            }
            guard !operations.isEmpty else { continue }
            bindings.append(GrantBinding(bindingID: binding.id, projectID: binding.projectID, environmentID: binding.environmentID, allowedOperations: operations))
        }
        guard !bindings.isEmpty else {
            throw VaultageError.invalidInput("The selected environments have no bindings that can be auto-allowed.")
        }
        guard bindings.count <= Grant.maximumBindings else {
            throw VaultageError.policyDenied("A single grant may cover at most \(Grant.maximumBindings) bindings. Narrow the selection.")
        }
        // Environments whose bindings were all filtered out are not claimed.
        let coveredEnvironmentIDs = Set(bindings.map(\.environmentID))
        let covered = environments.filter { coveredEnvironmentIDs.contains($0.id) }

        // RP-06. One fact, derived from what the grant actually covers, used by
        // the sheet, the stored record and the digest alike. `includeProduction`
        // on the *request* is a permission to cover production, not a statement
        // that production is covered: ticking it while selecting only
        // non-production environments used to leave the sheet correctly silent
        // about production while the committed grant and its Activity row both
        // claimed `includesProduction == true`. The durable record must say what
        // the human was shown.
        let includesProduction = covered.contains(where: \.isProduction)
        // Derived from what the grant actually covers, exactly as
        // `includesProduction` is: a requested mutation that no covered binding
        // allows is not claimed on the sheet.
        let coveredMutations = Set(bindings.flatMap(\.allowedOperations)).filter { $0.taxonomy.kind != .read }
        let digest = try Grant.coveringDigest(scope: request.scope, environmentIDs: coveredEnvironmentIDs, bindings: bindings, includesProduction: includesProduction, decidingDeviceID: decidingDeviceID, in: state)
        let disclosure = GrantDisclosure(
            scopeLabel: scopeLabel(request.scope, clientName: clientName, in: state),
            durationLabel: request.duration.label,
            // The sheet states the expiry it would produce; the stored value is
            // stamped from the same clock at commit.
            expiresAt: now.addingTimeInterval(request.duration.seconds),
            environmentLabels: covered.map { label(for: $0, in: state) }.sorted(),
            operationLabels: Set(bindings.flatMap(\.allowedOperations)).map(\.rawValue).sorted(),
            includesProduction: includesProduction,
            productionEnvironmentLabels: covered.filter(\.isProduction).map { label(for: $0, in: state) }.sorted(),
            mutationLabels: coveredMutations.map { "\($0.verbLabel) · \($0.taxonomy.resource.label) · \($0.rawValue)" }.sorted(),
            mutationResourceKinds: Set(coveredMutations.map(\.taxonomy.resource.label)).sorted(),
            digest: digest
        )
        return GrantDraft(scope: request.scope, environmentIDs: coveredEnvironmentIDs, bindings: bindings, includesProduction: includesProduction, duration: request.duration, digest: digest, disclosure: disclosure, decidingDeviceID: decidingDeviceID)
    }

    // MARK: Matching

    /// The only function that can cause a sheet to be skipped.
    ///
    /// Every condition is required; there is no precedence, no partial match and
    /// no "closest" grant. Returning `nil` means the ordinary per-action approval
    /// runs, which is the behaviour of every build before this ticket.
    public static func authorizingGrant(for request: ActionRequest, presented: ClientIdentity, in state: VaultageMetadata, now: Date, signer: any GrantSigning) -> Grant? {
        // 1. Auto-allow requires an enrolled, currently-active client — for a
        //    project-scoped grant too. BL-060's acceptance criteria say an
        //    unenrolled client cannot use a grant, and that is the stricter
        //    reading of D6, so it is the one implemented. `current` re-resolves
        //    against metadata, so a revoked client loses its grants immediately.
        // 0. Audit H-08. A file below this Mac's revocation anchor has been
        //    rolled back to before a revocation: nothing in it authorizes.
        guard signer.isCurrent(state) else { return nil }
        let client = ClientEnrollment.current(presented, in: state)
        guard client.isEnrolled, let clientID = client.id else { return nil }
        //    Audit H-02. And one whose identity a grant may rest on: a client
        //    enrolled with the legacy bearer — readable by any same-user
        //    process, replayable through the genuine `--mcp` binary — is
        //    named on sheets but never auto-allowed, project-scoped grants
        //    included. Only a paired instance (BL-136 step 3) is.
        guard state.enrolledClients.first(where: { $0.id == clientID })?.isGrantEligible == true else { return nil }
        // 2. The operation must be one that may ever be auto-allowed.
        guard request.operation.isAutoAllowable else { return nil }
        // BL-091, belt and braces. `isAutoAllowable` already excludes every
        // delete and every production-affecting mutation, so neither of these
        // can fire from a well-formed request — they are here so that a future
        // mis-classification produces a refusal rather than an auto-allow.
        guard request.operation.taxonomy.kind != .delete else { return nil }
        guard request.resourceMutation?.confirmDelete != true else { return nil }
        // 3. The environment must exist, so its production flag is a fact.
        guard let environment = state.environments.first(where: { $0.id == request.environmentID }),
              environment.projectID == request.projectID else { return nil }

        for grant in state.grants.prefix(Grant.maximumGrants) {
            guard grant.isUsable(at: now) else { continue }
            switch grant.scope.kind {
            case .client: guard grant.scope.clientID == clientID else { continue }
            case .projects: guard grant.scope.projectIDs.contains(request.projectID) else { continue }
            }
            guard grant.environmentIDs.contains(request.environmentID) else { continue }
            guard !environment.isProduction || grant.includesProduction else { continue }
            guard let covered = grant.bindings.first(where: { $0.bindingID == request.bindingID }),
                  covered.projectID == request.projectID,
                  covered.environmentID == request.environmentID,
                  covered.allowedOperations.contains(request.operation) else { continue }
            // 4. Nothing the human approved may have moved. A missing record
            //    throws out of the digest and is treated as a mismatch.
            guard let digest = try? grant.recomputedDigest(in: state), digest == grant.digest else { continue }
            // 5. BL-136 step 1. The record is the broker's: its MAC verifies
            //    under the key only this Mac's signed binaries hold. A grant
            //    written into metadata by anything else — however correct its
            //    digest — is skipped here, silently, like any other mismatch.
            guard signer.verifies(grant) else { continue }
            return grant
        }
        return nil
    }

    // MARK: Lifecycle

    /// §4.7 layer 7. A grant created by a phone commits **`pendingArm`** —
    /// `armedAt == nil` — and authorizes nothing until the owner touches the Mac
    /// once. A locally created grant is armed by the presence proof that created
    /// it, which is what `armedAt: now` records for the local path.
    ///
    /// Layer 7 is the condition on which §4.7 ships, and the honest account of
    /// it is two compatible facts. **It preserves `02-ARCHITECTURE.md` §6's
    /// limit, mechanically and verifiably**: that prohibition is about *writes*,
    /// a grant with `armedAt == nil` authorizes nothing, and arming requires a
    /// local presence proof — so the first production write after a remote
    /// production grant is preceded by a human at the Mac, whether or not that
    /// human reads the prompt. **And it is a formality as a detection layer**:
    /// an owner who approved on their phone minutes ago and then walks to their
    /// Mac is in the most congruent possible state for approving the prompt that
    /// greets them. Its value is containment — a thief who defeats Face ID on a
    /// stolen phone gets a grant record that never arms — and it is **not**
    /// counted as detection anywhere.
    public static func commit(_ draft: GrantDraft, now: Date, in state: inout VaultageMetadata, signer: any GrantSigning) throws -> Grant {
        var grant = Grant(
            scope: draft.scope,
            environmentIDs: draft.environmentIDs,
            bindings: draft.bindings,
            includesProduction: draft.includesProduction,
            createdAt: now,
            duration: draft.duration,
            expiresAt: now.addingTimeInterval(draft.duration.seconds),
            digest: draft.digest,
            decidingDeviceID: draft.decidingDeviceID,
            armedAt: draft.decidingDeviceID == nil ? now : nil
        )
        guard grant.isWellFormed else {
            throw VaultageError.policyDenied("Vaultage refused to store a grant it could not validate.")
        }
        // BL-136 step 1. The MAC is what makes this the broker's grant rather
        // than a record anything could have written.
        grant.mac = try signer.mac(for: grant)
        // Long-dead records are pruned here rather than on read, so Activity
        // keeps recent history without the store growing without bound.
        state.grants.removeAll { $0.expiresAt.addingTimeInterval(30 * 24 * 60 * 60) < now }
        state.grants.append(grant)
        guard state.grants.count <= Grant.maximumGrants else {
            throw VaultageError.policyDenied("This Vaultage install already holds the maximum number of grants. Revoke one first.")
        }
        return grant
    }

    @discardableResult
    public static func revoke(_ id: UUID, now: Date, in state: inout VaultageMetadata, signer: any GrantSigning) throws -> Grant {
        guard let index = state.grants.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That grant no longer exists.")
        }
        state.grants[index].revokedAt = state.grants[index].revokedAt ?? now
        // BL-136 step 1. `revokedAt` is under the MAC, so the revocation is
        // re-stamped: deleting the key from the file afterwards leaves a
        // record that verifies under neither stamp.
        state.grants[index].mac = try signer.mac(for: state.grants[index])
        // Audit H-08: one more revocation this Mac has written.
        state.revocationGeneration += 1
        return state.grants[index]
    }

    // MARK: Projection

    /// `verify` is the broker's `GrantSigning.verifies` where the key is; a
    /// process without the key passes what it can tell — that a stamp exists —
    /// and the broker's answer is the one that decides.
    public static func summaries(in state: VaultageMetadata, now: Date, verify: (Grant) -> Bool) -> [GrantSummary] {
        state.grants.map { grant in
            let verified = verify(grant)
            let clientName = grant.scope.clientID.flatMap { id in
                state.enrolledClients.first(where: { $0.id == id })?.displayName
            }
            let projectIDs: Set<UUID> = grant.scope.kind == .projects
                ? grant.scope.projectIDs
                : Set(grant.bindings.map(\.projectID))
            return GrantSummary(
                id: grant.id,
                scopeLabel: scopeLabel(grant.scope, clientName: clientName, in: state),
                clientName: clientName,
                projectNames: projectIDs.compactMap { id in state.projects.first(where: { $0.id == id })?.name }.sorted(),
                environmentLabels: grant.environmentIDs.compactMap { id in
                    state.environments.first(where: { $0.id == id }).map { label(for: $0, in: state) }
                }.sorted(),
                operations: Set(grant.bindings.flatMap(\.allowedOperations)).map(\.rawValue).sorted(),
                includesProduction: grant.includesProduction,
                createdAt: grant.createdAt,
                expiresAt: grant.expiresAt,
                revokedAt: grant.revokedAt,
                // A grant the broker would refuse is not active, whatever its
                // dates say — the upgrade case (no stamp yet) and the forgery
                // case look the same to the owner: "not honoured".
                isActive: verified && grant.isUsable(at: now),
                remainingSeconds: grant.remainingSeconds(at: now),
                isVerified: verified
            )
        }
        .sorted { left, right in
            if left.isActive != right.isActive { return left.isActive }
            return left.expiresAt > right.expiresAt
        }
    }

    /// Active grants only — what an Activity "auto-allow is armed" section shows.
    public static func activeSummaries(in state: VaultageMetadata, now: Date, verify: (Grant) -> Bool) -> [GrantSummary] {
        summaries(in: state, now: now, verify: verify).filter(\.isActive)
    }

    // MARK: Labels

    static func label(for environment: Environment, in state: VaultageMetadata) -> String {
        let project = state.projects.first(where: { $0.id == environment.projectID })?.name ?? "Unknown project"
        return "\(project) / \(environment.name)"
    }

    static func scopeLabel(_ scope: GrantScope, clientName: String?, in state: VaultageMetadata) -> String {
        switch scope.kind {
        case .client:
            return "This agent: \(clientName ?? "unknown client")"
        case .projects:
            let names = scope.projectIDs.compactMap { id in state.projects.first(where: { $0.id == id })?.name }.sorted()
            return names.isEmpty ? "Selected projects" : "Projects: \(names.joined(separator: ", "))"
        }
    }
}

/// The OS authentication step D6 requires for grant creation.
///
/// It is a seam so the self-tests can run the whole creation path deterministically
/// without a biometric prompt. There is deliberately no way to configure which
/// implementation a shipping build uses: `VaultageBroker` defaults to the real
/// one and only a test can pass another.
public protocol OwnerAuthenticating: Sendable {
    /// - Parameter accounts: the exact Keychain accounts this authentication
    ///   may later be carried into (BL-062 follow-up). Pass the empty set when
    ///   the authentication gates a *decision* rather than a read: the result
    ///   is then unbound and can unlock nothing, which is what grant creation
    ///   wants when its covered items cannot be resolved.
    func authenticateOwner(reason: String, unlocking accounts: Set<String>) async throws -> OwnerAuthentication

    /// The same evaluation with an explicit **Touch ID reuse duration**
    /// (BM-L2).
    ///
    /// §2.2 and appendix §4 both say the arming touch's reuse duration stays
    /// `0`, and `RemoteArmingCeremony.reuseDurationSeconds = 0` was a constant
    /// nothing applied: every evaluation got `OwnerAuthentication.keychainReuseDuration`,
    /// which is 60. Practical exposure was small — `RemoteArmingCeremony.arm`
    /// invalidates in a `defer` — but PF-9 makes "how long is this instance
    /// carried" the whole control, and a 60-second reusable instance is not the
    /// one the document specifies.
    ///
    /// The default forwards to the two-argument form, so a conformer that has
    /// no `LAContext` — every test stub — needs no edit, and the one
    /// implementation that has one honours it.
    func authenticateOwner(reason: String, unlocking accounts: Set<String>, reuseDuration: TimeInterval) async throws -> OwnerAuthentication
}

extension OwnerAuthenticating {
    public func authenticateOwner(reason: String, unlocking accounts: Set<String>, reuseDuration: TimeInterval) async throws -> OwnerAuthentication {
        try await authenticateOwner(reason: reason, unlocking: accounts)
    }
}

public struct LocalOwnerAuthentication: OwnerAuthenticating {
    public init() {}

    @discardableResult
    public func authenticateOwner(reason: String, unlocking accounts: Set<String>) async throws -> OwnerAuthentication {
        try await authenticateOwner(reason: reason, unlocking: accounts, reuseDuration: OwnerAuthentication.keychainReuseDuration)
    }

    @discardableResult
    public func authenticateOwner(reason: String, unlocking accounts: Set<String>, reuseDuration: TimeInterval) async throws -> OwnerAuthentication {
        let context = LAContext()
        // BL-062 follow-up. Set explicitly rather than left at the platform
        // default, and held to `OwnerAuthentication.lifetime` rather than to
        // the OS maximum, so the window in which this evaluation can satisfy a
        // Keychain read is the same 60 seconds every other gate on this path
        // already enforces. The clamp is defensive: the OS rejects a longer
        // value, and a future OS with a shorter maximum should shorten us too.
        context.touchIDAuthenticationAllowableReuseDuration = min(
            reuseDuration,
            LATouchIDAuthenticationMaximumAllowableReuseDuration
        )
        // `.deviceOwnerAuthentication` is Touch ID (or Watch) with the login
        // password as the OS-controlled fallback — the same user-presence class
        // the Keychain items themselves are protected with. Requiring biometrics
        // alone would lock the feature out of Macs without a Touch Bar or
        // Touch ID keyboard.
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw VaultageError.policyDenied("This Mac cannot authenticate the owner, so auto-allow grants are unavailable.")
        }
        let approved: Bool = await withCheckedContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
                continuation.resume(returning: success)
            }
        }
        guard approved else {
            context.invalidate()
            throw VaultageError.approvalDenied
        }
        return OwnerAuthentication(authenticatedAt: Date(), accounts: accounts, carrier: OwnerAuthenticationContext(context))
    }
}

/// The in-memory secret cache that makes a grant window useful.
///
/// **It never touches disk.** Entries are `VaultSecret`s, which own one manually
/// managed allocation that is `mlock`'d where the OS allows and zeroed with
/// `memset_s` when the last reference goes away — so removing an entry here
/// zeroes the bytes rather than leaving them in freed heap memory.
///
/// **Where it lives, exactly (RP-02).** One cache per *broker service process*,
/// never one per connection and never one per `VaultageBroker`. A broker is
/// handed the cache its process owns; `BrokerServiceComposition` is the only
/// thing that constructs one outside a test:
///
/// * in the **in-process composition**, the process is the `--mcp` subprocess
///   (or the desktop app). `BrokerServiceComposition.processWide` owns the
///   cache, so every broker the process vends — the MCP server's and the
///   receipt-recovery one — shares it, and it dies when the process does.
/// * in the **XPC composition** (BL-061), the process is the nested broker
///   service. The listener delegate holds one composition and every inbound
///   connection's `BrokerExport` takes its broker from it, so the cache spans
///   concurrent connections, outlives any single MCP session, and dies with the
///   service.
///
/// Two consequences follow from "per process", and both are the point:
///
/// * `clear()` — the `lockGrantSecrets()` control — forgets the secrets of
///   *every* connection in that process, including an MCP session the human is
///   not looking at. A lock that cleared only the caller's cache would be a
///   lock that does not lock.
/// * cached bytes can live for the whole grant window rather than for one MCP
///   session, which is the exposure BL-060 §9.6 describes. It is bounded in
///   practice by RP-01's verification ceiling and by `purge`/`invalidate`.
///
/// Either way a grant survives a restart **only as metadata**: the first
/// matching action afterwards finds no cached value, reads the Keychain once
/// with one Touch ID, and re-arms the window.
public actor GrantSecretCache {
    public static let maximumEntries = 32
    /// BL-136 step 4 (D70 amendment 2): one arming lasts at most this long —
    /// one host instance, twelve hours, the model 1Password uses for its CLI.
    public static let sessionCeiling: TimeInterval = 12 * 60 * 60

    private struct Entry {
        let secret: VaultSecret
        let grantID: UUID
        let credentialVersion: UUID?
        let expiresAt: Date
    }

    /// Keyed by Keychain account, which is what a read is actually for.
    private var entries: [String: Entry] = [:]

    public init() {}

    /// Returns a cached value only for the same grant, the same account and the
    /// same credential version, and only while the grant window is open. Any
    /// mismatch drops the entry rather than reusing it.
    public func secret(account: String, grantID: UUID, credentialVersion: UUID?, now: Date) -> VaultSecret? {
        purge(now: now)
        guard let entry = entries[account] else { return nil }
        guard entry.grantID == grantID, entry.credentialVersion == credentialVersion, entry.expiresAt > now else {
            entries.removeValue(forKey: account)
            return nil
        }
        return entry.secret
    }

    public func store(_ secret: VaultSecret, account: String, grantID: UUID, credentialVersion: UUID?, expiresAt: Date, now: Date) {
        purge(now: now)
        guard expiresAt > now else { return }
        // A bounded cache: an install with more accounts than this simply reads
        // the Keychain again rather than growing without limit.
        if entries[account] == nil, entries.count >= Self.maximumEntries { return }
        entries[account] = Entry(secret: secret, grantID: grantID, credentialVersion: credentialVersion, expiresAt: expiresAt)
    }

    /// Revocation. Every value cached under the revoked grant is dropped, which
    /// zeroes it.
    public func invalidate(grantID: UUID) {
        for (account, entry) in entries where entry.grantID == grantID {
            entries.removeValue(forKey: account)
        }
    }

    /// Expiry.
    public func purge(now: Date) {
        for (account, entry) in entries where entry.expiresAt <= now {
            entries.removeValue(forKey: account)
        }
    }

    /// Lock, and the explicit "forget everything" control.
    public func clear() {
        entries.removeAll()
    }

    /// Test-visible size. It returns a count, never a value.
    public func entryCount() -> Int { entries.count }
    public func holdsAccount(_ account: String) -> Bool { entries[account] != nil }
}
