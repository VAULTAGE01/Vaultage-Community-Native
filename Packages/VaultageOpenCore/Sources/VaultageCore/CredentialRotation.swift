import Foundation

// BL-094 / owner decision D36, guarantee 3 — rotation with overlap.
//
// > Rotate = create new, deliver to every environment that uses it, verify
// > each, then revoke the old; never revoke first. A partially delivered
// > rotation is visible and resumable.
//
// This file is the state machine and nothing else: no route, no credential, no
// approval, no I/O. `VaultageBroker.rotateCredential` drives it, and every
// decision it makes is a pure function here, so a self-test can interrupt the
// rotation after any step and ask the model what it would do next without a
// Keychain, a provider or a clock.
//
// **The invariant.** `mayRevokeOldCredential` is the one question the whole
// ticket turns on, and it is a single expression: the old credential may be
// revoked only when the plan has at least one step and *every* step is
// `verified`. It is not enough for a step to be `delivered` — the write was
// accepted but the destination's name list has not confirmed it — and a step
// that failed is not a step that can be skipped. Every path that revokes goes
// through this function; nothing else may set `oldRevokedAt`.
//
// **Why a persisted plan rather than a loop.** An interruption is not an
// exception here, it is the expected case: a rotation raises one native
// approval per delivery, and the human may quit the app between two of them.
// So the plan is computed once, written down, and each step's outcome is
// persisted before the next one begins. Resuming is re-running the same
// function against the same record; a step that is already `verified` is
// skipped, and the count of remaining steps is what the UI shows.
//
// **Rotation never mints.** The new value arrives as a vault item that already
// exists — pasted by the human, or created by BL-074's `createProviderResource`
// in its own approval, under its own class. Minting a credential is
// `nativeApprovalOnly` and is deliberately not something another flow can
// perform on its way through: a rotation that could mint would be a rotation
// that could create authority without the sheet that exists to authorize it.

// MARK: - Where the new value came from

public enum RotationValueOrigin: String, Codable, Sendable, CaseIterable {
    /// The human put a new value in the vault themselves.
    case pasted
    /// BL-074 created it at the provider, in its own approval, before the
    /// rotation started. The rotation records which, so the final step can say
    /// "Revoke at {provider}" with confidence about what exists there.
    case provisioned

    public var label: String {
        switch self {
        case .pasted: "Pasted into the vault"
        case .provisioned: "Created at the provider by Vaultage"
        }
    }
}

// MARK: - The machine

public enum RotationState: String, Codable, Sendable, CaseIterable {
    /// The plan exists. Nothing has been delivered.
    case preparing
    /// At least one step has been attempted. Some destinations still hold the
    /// old value, and the old credential must keep working.
    case delivering
    /// Every step is delivered **and** verified. This is the only state from
    /// which the old credential may be revoked.
    case delivered
    /// The old credential has been revoked locally. What is at the provider is
    /// unchanged until the human revokes it there too.
    case oldRevokedLocally = "old-revoked-locally"
    /// Finished: delivered, verified, old one revoked locally, and the human
    /// has either revoked at the provider or said they are done.
    case completed
    /// The human stopped it. A cancelled rotation leaves every delivered step
    /// delivered — the new value is at those destinations and works — and
    /// never revokes the old one.
    case cancelled

    /// Whether this rotation is still asking the human for something.
    public var isOpen: Bool { self != .completed && self != .cancelled }

    public var label: String {
        switch self {
        case .preparing: "Ready to start"
        case .delivering: "Delivering"
        case .delivered: "Delivered and verified"
        case .oldRevokedLocally: "Old credential revoked in Vaultage"
        case .completed: "Complete"
        case .cancelled: "Cancelled"
        }
    }
}

public enum RotationStepState: String, Codable, Sendable, CaseIterable {
    /// Not attempted, or attempted and rolled back to try again.
    case pending
    /// The provider accepted the write; the destination has not been listed
    /// since. **Not a state from which the old credential may be revoked.**
    case delivered
    /// The write was accepted and a later name list reported the destination.
    case verified
    /// The last attempt failed. It is retried, not skipped.
    case failed

    public var label: String {
        switch self {
        case .pending: "Not delivered yet"
        case .delivered: "Delivered, not yet verified"
        case .verified: "Delivered and verified"
        case .failed: "Failed"
        }
    }
}

/// One destination a rotation has to reach.
public struct RotationStep: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    /// The ledger row this step replaces. It is the reason the step exists:
    /// a rotation delivers to every destination the ledger says the old
    /// credential feeds, and to nothing else.
    public let ledgerRowID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let environmentName: String
    public let bindingID: UUID
    public let destination: DeliveryDestination
    /// **CC-H6.** The field of the new credential this step delivers, copied
    /// from the ledger row it replaces.
    ///
    /// A rotation replaces what is at a destination with the same *kind* of
    /// thing: if production's `TWILIO_AUTH_TOKEN` was fed by the Auth token
    /// field, the step that replaces it delivers the new credential's Auth
    /// token — not its Account SID, and not the envelope. Carrying it on the
    /// step rather than deriving it at each turn is what makes a rotation
    /// resumed tomorrow deliver what the plan said today.
    ///
    /// A `var` for one reason: `CredentialRotationStore.normalize` repairs it
    /// back to the ledger row's own field, because the row is the record of
    /// what is actually deployed and a step is a plan to replace it.
    public var sourceField: CompositeCredentialField?
    public var state: RotationStepState
    public var deliveredAt: Date?
    public var verifiedAt: Date?
    /// The last failure, already redacted. Nil once the step succeeds.
    public var failure: String?
    /// How many times this step has been attempted, so a rotation that cannot
    /// make progress says so instead of looping.
    public var attempts: Int

    public init(
        id: UUID = UUID(),
        ledgerRowID: UUID,
        projectID: UUID,
        environmentID: UUID,
        environmentName: String,
        bindingID: UUID,
        destination: DeliveryDestination,
        sourceField: CompositeCredentialField? = nil,
        state: RotationStepState = .pending,
        deliveredAt: Date? = nil,
        verifiedAt: Date? = nil,
        failure: String? = nil,
        attempts: Int = 0
    ) {
        self.id = id
        self.ledgerRowID = ledgerRowID
        self.projectID = projectID
        self.environmentID = environmentID
        self.environmentName = environmentName
        self.bindingID = bindingID
        self.destination = destination
        self.sourceField = sourceField
        self.state = state
        self.deliveredAt = deliveredAt
        self.verifiedAt = verifiedAt
        self.failure = failure
        self.attempts = attempts
    }

    public static let maximumAttempts = 5

    /// The sentence the resumable list shows for this step. It names the field
    /// where there is one, so two steps of one pair are two visibly different
    /// lines rather than the same line twice.
    public var summary: String {
        let field = sourceField.map { " (\($0.defaultLabel))" } ?? ""
        return "\(destination.sheetLine)\(field) — \(environmentName) — \(state.label)"
    }
}

/// One rotation, with overlap.
public struct CredentialRotation: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    /// The vault item being rotated away from.
    public let oldVaultItemID: UUID
    /// Its fingerprint at the moment the plan was made, so a plan cannot be
    /// silently re-pointed at a different credential by an edit between two
    /// steps.
    public let oldFingerprint: String
    /// The vault item holding the new value. It exists before the rotation
    /// starts: rotation never mints.
    public let newVaultItemID: UUID
    public let newFingerprint: String
    public let origin: RotationValueOrigin
    /// The provider of the store the first step delivers into — **not** the
    /// issuer of the credential being rotated. A Stripe key delivered into
    /// Vercel has `provider == .vercel` here and is revoked at Stripe, so the
    /// revoke step never reads this: it names the issuer, derived at display
    /// time by `RotationMachine.issuer(of:in:)`. Kept as it is because it is
    /// persisted, and changing what it means would be a schema question.
    public let provider: Provider
    /// What to call the credential on the progress sheet.
    public let label: String
    public let startedAt: Date
    public var steps: [RotationStep]
    public var state: RotationState
    /// When Vaultage marked the old credential revoked locally. It can only be
    /// set through `RotationMachine.revokeOldCredential`, which refuses unless
    /// every step is verified.
    public var oldRevokedAt: Date?
    /// When the human said they had revoked it at the provider, or that they
    /// were done. Vaultage never claims a provider-side revocation it did not
    /// perform.
    public var completedAt: Date?
    public var cancelledAt: Date?
    /// The last failure, already redacted.
    public var lastFailure: String?

    public init(
        id: UUID = UUID(),
        oldVaultItemID: UUID,
        oldFingerprint: String,
        newVaultItemID: UUID,
        newFingerprint: String,
        origin: RotationValueOrigin,
        provider: Provider,
        label: String,
        startedAt: Date,
        steps: [RotationStep],
        state: RotationState = .preparing,
        oldRevokedAt: Date? = nil,
        completedAt: Date? = nil,
        cancelledAt: Date? = nil,
        lastFailure: String? = nil
    ) {
        self.id = id
        self.oldVaultItemID = oldVaultItemID
        self.oldFingerprint = oldFingerprint
        self.newVaultItemID = newVaultItemID
        self.newFingerprint = newFingerprint
        self.origin = origin
        self.provider = provider
        self.label = label
        self.startedAt = startedAt
        self.steps = steps
        self.state = state
        self.oldRevokedAt = oldRevokedAt
        self.completedAt = completedAt
        self.cancelledAt = cancelledAt
        self.lastFailure = lastFailure
    }

    public static let maximumSteps = 100
    public static let maximumRotations = 50

    public var verifiedSteps: [RotationStep] { steps.filter { $0.state == .verified } }
    public var remainingSteps: [RotationStep] { steps.filter { $0.state != .verified } }
    /// The next step to run: the first that is not verified, and that has not
    /// exhausted its attempts.
    public var nextStep: RotationStep? {
        steps.first { $0.state != .verified && $0.attempts < RotationStep.maximumAttempts }
    }

    /// The progress sentence: "2 of 5 destinations delivered and verified."
    public var progressSummary: String {
        "\(verifiedSteps.count) of \(steps.count) \(steps.count == 1 ? "destination" : "destinations") delivered and verified."
    }
}

/// A rotation decoded leniently: one unreadable record is dropped, not the file.
struct DecodedCredentialRotation: Decodable {
    let value: CredentialRotation?
    init(from decoder: Decoder) throws {
        value = try? CredentialRotation(from: decoder)
    }
}

// MARK: - The rules

public enum RotationMachine {

    /// **The invariant.** The old credential may be revoked only when the plan
    /// has at least one step and every step is verified.
    ///
    /// Stated once, as one expression, and called from every path that could
    /// revoke. "Delivered" is deliberately not enough: the provider accepted a
    /// write, and until the destination's name list reports the entry we do not
    /// know the deployment can see it. Revoking on "delivered" is precisely the
    /// revoked-before-delivered condition the ticket forbids.
    public static func mayRevokeOldCredential(_ rotation: CredentialRotation) -> Bool {
        guard !rotation.steps.isEmpty else { return false }
        guard rotation.state != .cancelled else { return false }
        return rotation.steps.allSatisfy { $0.state == .verified }
    }

    /// Why revoking is not offered yet, in words, or nil when it is.
    public static func revocationBlockedReason(_ rotation: CredentialRotation) -> String? {
        if rotation.steps.isEmpty {
            return "This rotation has no destinations, so there is nothing to overlap and nothing to revoke."
        }
        if rotation.state == .cancelled { return "This rotation was cancelled." }
        let outstanding = rotation.remainingSteps
        guard !outstanding.isEmpty else { return nil }
        let delivered = outstanding.filter { $0.state == .delivered }.count
        let failed = outstanding.filter { $0.state == .failed }.count
        let pending = outstanding.count - delivered - failed
        var parts: [String] = []
        if pending > 0 { parts.append("\(pending) not delivered yet") }
        if delivered > 0 { parts.append("\(delivered) delivered but not verified") }
        if failed > 0 { parts.append("\(failed) failed") }
        return "The old credential stays valid until every destination is delivered and verified: \(parts.joined(separator: ", ")). Revoking now would take production down."
    }

    /// The state a rotation is in, derived from its steps. Pure, and the only
    /// thing allowed to move `state` between `preparing`, `delivering` and
    /// `delivered` — the terminal three are set by the acts that cause them.
    public static func derivedState(_ rotation: CredentialRotation) -> RotationState {
        switch rotation.state {
        case .oldRevokedLocally, .completed, .cancelled: return rotation.state
        case .preparing, .delivering, .delivered: break
        }
        guard !rotation.steps.isEmpty else { return .preparing }
        if rotation.steps.allSatisfy({ $0.state == .verified }) { return .delivered }
        if rotation.steps.allSatisfy({ $0.state == .pending && $0.attempts == 0 }) { return .preparing }
        return .delivering
    }

    /// Records that one step's write was accepted. It does **not** verify it:
    /// a delivered step is one the old credential must keep covering.
    public static func markDelivered(_ rotation: inout CredentialRotation, stepID: UUID, at instant: Date) {
        guard let index = rotation.steps.firstIndex(where: { $0.id == stepID }) else { return }
        rotation.steps[index].state = .delivered
        rotation.steps[index].deliveredAt = instant
        rotation.steps[index].failure = nil
        rotation.state = derivedState(rotation)
    }

    /// Records that a name list reported the destination after the write. This
    /// is the only transition into `verified`.
    public static func markVerified(_ rotation: inout CredentialRotation, stepID: UUID, at instant: Date) {
        guard let index = rotation.steps.firstIndex(where: { $0.id == stepID }) else { return }
        // A step can only be verified after it has been delivered. Verifying a
        // pending step would mean "the name is there" was read as "the new
        // value is there", which is exactly the confusion that makes an early
        // revoke possible.
        guard rotation.steps[index].state == .delivered else { return }
        rotation.steps[index].state = .verified
        rotation.steps[index].verifiedAt = instant
        rotation.steps[index].failure = nil
        rotation.state = derivedState(rotation)
    }

    /// Records a failed attempt. The step stays in the plan and is retried; it
    /// is never dropped, because a dropped step is a destination still running
    /// on a credential somebody is about to revoke.
    public static func markFailed(_ rotation: inout CredentialRotation, stepID: UUID, reason: String) {
        guard let index = rotation.steps.firstIndex(where: { $0.id == stepID }) else { return }
        rotation.steps[index].state = .failed
        rotation.steps[index].failure = Redactor.safeError(reason)
        rotation.state = derivedState(rotation)
        rotation.lastFailure = Redactor.safeError(reason)
    }

    /// Counts one attempt, before it is made. Persisting the attempt first is
    /// what stops a crash loop from retrying forever.
    public static func countAttempt(_ rotation: inout CredentialRotation, stepID: UUID) {
        guard let index = rotation.steps.firstIndex(where: { $0.id == stepID }) else { return }
        rotation.steps[index].attempts += 1
        if rotation.state == .preparing { rotation.state = .delivering }
    }

    /// Revokes the old credential locally, or refuses.
    ///
    /// The only transition into `oldRevokedLocally`, and it asks
    /// `mayRevokeOldCredential` first. A caller that ignores the returned
    /// `false` changes nothing.
    @discardableResult
    public static func revokeOldCredential(_ rotation: inout CredentialRotation, at instant: Date) -> Bool {
        guard mayRevokeOldCredential(rotation) else { return false }
        rotation.oldRevokedAt = instant
        rotation.state = .oldRevokedLocally
        return true
    }

    /// The human has revoked at the provider, or has said they are done with
    /// the ↗ step. Only reachable once the old credential is revoked locally.
    @discardableResult
    public static func complete(_ rotation: inout CredentialRotation, at instant: Date) -> Bool {
        guard rotation.state == .oldRevokedLocally, rotation.oldRevokedAt != nil else { return false }
        rotation.completedAt = instant
        rotation.state = .completed
        return true
    }

    /// Stops a rotation. Delivered destinations keep the new value — it works,
    /// and un-delivering would be a second production change nobody asked for —
    /// and the old credential is never revoked.
    @discardableResult
    public static func cancel(_ rotation: inout CredentialRotation, at instant: Date) -> Bool {
        guard rotation.state.isOpen, rotation.oldRevokedAt == nil else { return false }
        rotation.cancelledAt = instant
        rotation.state = .cancelled
        return true
    }

    /// Where the rotated-out credential was **issued** — so where it has to be
    /// revoked.
    ///
    /// The old vault item's own provider when it names one; failing that, the
    /// provider Vaultage created it at, when a BL-074 provisioned resource
    /// records that item; otherwise nil — a secret pasted without a provider,
    /// or an item that no longer exists. Never the provider of a store the
    /// credential was delivered into: a Stripe key delivered into Vercel or
    /// GitHub is revoked at Stripe, and a rotation's `provider` (the first
    /// destination's) would send the person to the wrong place. Derived at
    /// display time from records that already exist, so nothing new is
    /// persisted.
    public static func issuer(of rotation: CredentialRotation, in state: VaultageMetadata) -> Provider? {
        if let provider = state.vaultItems.first(where: { $0.id == rotation.oldVaultItemID })?.provider { return provider }
        return state.provisionedResources.first(where: { $0.vaultItemID == rotation.oldVaultItemID })?.provider
    }

    /// The words the final step offers: Vaultage revokes locally and then
    /// points at the issuer rather than pretending it revoked there. When the
    /// issuer is not known it says so, with no arrow, because there is no page
    /// it can honestly link to.
    public static func providerRevocationPrompt(issuer: Provider?) -> String {
        guard let issuer else { return "Revoke it where it was issued" }
        return "Revoke at \(issuer.title) ↗"
    }

    /// Why the provider step is the person's, naming the issuer when it is
    /// known and saying plainly when it is not.
    public static func providerRevocationExplanation(issuer: Provider?) -> String {
        let revoked = "Vaultage has marked the old credential revoked here and stopped using it."
        let why = "because a credential you created outside Vaultage may be in use by something Vaultage cannot see."
        guard let issuer else {
            return "\(revoked) It is still valid wherever it was issued until you revoke it there. Vaultage does not know which service issued it, so it cannot point you there, and it will not revoke it for you on this path, \(why)"
        }
        return "\(revoked) It is still valid at \(issuer.title) until you revoke it there — Vaultage will not do that for you on this path, \(why)"
    }
}

// MARK: - The repair pass

public enum CredentialRotationStore {
    /// The schema-16 migration and the repair pass, in one function, run on
    /// every decode. Idempotent, and it only ever narrows.
    ///
    /// The one rule that is not a shape check: **a rotation may never decode
    /// into a revoked-before-delivered state.** A record that claims
    /// `oldRevokedAt` while a step is unverified is not repaired by dropping
    /// the step — that would make the claim true by deleting the evidence — it
    /// is repaired by dropping the revocation and putting the rotation back
    /// into `delivering`, which is the state that is actually safe.
    public static func normalize(_ state: inout VaultageMetadata) {
        let environments = Dictionary(uniqueKeysWithValues: state.environments.map { ($0.id, $0) })
        let rowIDs = Set(state.deployedCredentials.map(\.id))
        // CC-H6. The ledger row is the record of what is deployed; a step is a
        // plan to replace it. So the step's field is repaired to the row's
        // rather than trusted from the file, and a hand-edited plan cannot make
        // a rotation deliver the other half of a credential into a destination
        // the human never approved for it.
        let rowFields = Dictionary(uniqueKeysWithValues: state.deployedCredentials.map { ($0.id, $0.sourceField) })

        var kept: [CredentialRotation] = []
        var seen: Set<UUID> = []
        for rotation in state.rotations.sorted(by: { $0.startedAt > $1.startedAt }) {
            guard kept.count < CredentialRotation.maximumRotations else { break }
            guard !seen.contains(rotation.id) else { continue }
            guard rotation.startedAt.timeIntervalSince1970.isFinite else { continue }
            guard DeployedCredentialLedger.isCanonicalFingerprint(rotation.oldFingerprint),
                  DeployedCredentialLedger.isCanonicalFingerprint(rotation.newFingerprint) else { continue }
            guard rotation.oldVaultItemID != rotation.newVaultItemID else { continue }
            guard rotation.steps.count <= CredentialRotation.maximumSteps else { continue }
            var repaired = rotation
            // A step whose ledger row or environment is gone has nothing left
            // to deliver to. Dropping it is safe *because* the destination it
            // named is no longer recorded as carrying the old credential.
            repaired.steps = rotation.steps.filter { step in
                guard rowIDs.contains(step.ledgerRowID) else { return false }
                guard let environment = environments[step.environmentID], environment.projectID == step.projectID else { return false }
                guard step.destination.isWellFormed else { return false }
                return true
            }
            // Per-step coherence: a timestamp that contradicts its state is
            // dropped, not trusted.
            for index in repaired.steps.indices {
                repaired.steps[index].sourceField = rowFields[repaired.steps[index].ledgerRowID] ?? nil
                if repaired.steps[index].state == .pending || repaired.steps[index].state == .failed {
                    repaired.steps[index].verifiedAt = nil
                }
                if repaired.steps[index].state != .verified { repaired.steps[index].verifiedAt = nil }
                if repaired.steps[index].state == .pending { repaired.steps[index].deliveredAt = nil }
                repaired.steps[index].attempts = max(0, min(repaired.steps[index].attempts, RotationStep.maximumAttempts))
                repaired.steps[index].failure = repaired.steps[index].failure.map(Redactor.safeError)
            }
            repaired.lastFailure = repaired.lastFailure.map(Redactor.safeError)
            // The invariant, enforced on the way in. A file that claims the old
            // credential was revoked while a destination is unverified is a
            // file that cannot have been written by this machine; the
            // revocation is dropped rather than the evidence.
            if repaired.oldRevokedAt != nil, !RotationMachine.mayRevokeOldCredential(repaired) {
                repaired.oldRevokedAt = nil
                repaired.completedAt = nil
                repaired.state = .delivering
            }
            if repaired.state == .completed, repaired.oldRevokedAt == nil { repaired.state = .delivering }
            if repaired.state == .oldRevokedLocally, repaired.oldRevokedAt == nil { repaired.state = .delivering }
            if repaired.state == .cancelled, repaired.cancelledAt == nil { repaired.state = .delivering }
            if repaired.state != .cancelled { repaired.cancelledAt = nil }
            if repaired.state != .completed { repaired.completedAt = nil }
            // Everything else is derived, so a hand-edited `state` cannot
            // claim more progress than the steps show.
            if repaired.state == .preparing || repaired.state == .delivering || repaired.state == .delivered {
                repaired.state = RotationMachine.derivedState(repaired)
            }
            seen.insert(repaired.id)
            kept.append(repaired)
        }
        state.rotations = kept.sorted { $0.startedAt > $1.startedAt }
    }

    /// The open rotation for one vault item, if any. A credential has at most
    /// one rotation in flight: a second would mean two overlaps racing to
    /// decide when the old value stops being needed.
    public static func openRotation(forOldItem itemID: UUID, in state: VaultageMetadata) -> CredentialRotation? {
        state.rotations.first { $0.oldVaultItemID == itemID && $0.state.isOpen }
    }

    public static func openRotations(in state: VaultageMetadata) -> [CredentialRotation] {
        state.rotations.filter { $0.state.isOpen }
    }
}
