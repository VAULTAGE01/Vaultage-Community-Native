import Foundation

/// BL-099 — §4.6 and §4.7 layer 7: the arming touch, the durable kill stamp, and
/// the disclosure the arming prompt carries.
///
/// These are the three pieces of the `Grant` change that are *behaviour* rather
/// than *shape*. The shape — `decidingDeviceID`, `armedAt`, `deviceKillSwitch`,
/// the unconditional device section and `currentPolicyRevision` — is in
/// `Grant.swift` beside the model it changes.
extension GrantPolicy {
    /// §4.7 layer 7. The owner touches the Mac once and the grant begins
    /// authorizing.
    ///
    /// The prompt this follows carries the **full `GrantDisclosure`** — the same
    /// coverage §3.3.1 digests — and defaults to **"Not now"** (Q16). Taking the
    /// presence proof is the caller's; what this function owns is the three
    /// rules a later reader would get wrong:
    ///
    /// * a **local** grant has nothing to arm, and asking to arm one is a
    ///   programming error rather than a no-op;
    /// * a **killed** grant never arms, because the stamp is the authority and
    ///   arming must not be a way around it;
    /// * **re-arming does not extend anything.** `armedAt` is stamped once;
    ///   `expiresAt` is what the owner approved and is never touched here.
    @discardableResult
    public static func arm(_ id: UUID, now: Date, in state: inout VaultageMetadata, signer: any GrantSigning) throws -> Grant {
        guard let index = state.grants.firstIndex(where: { $0.id == id }) else {
            throw VaultageError.invalidInput("That grant no longer exists.")
        }
        // BL-136 step 1. The arming touch stamps a grant; it must never be the
        // first stamp. A pending record the broker did not write — whatever
        // it covers, however good its digest — is refused here, before the
        // owner's touch can launder it into a signed grant.
        guard signer.verifies(state.grants[index]) else {
            throw VaultageError.policyDenied("That grant is not one this Mac recorded, so it cannot be armed.")
        }
        guard state.grants[index].decidingDeviceID != nil else {
            throw VaultageError.invalidInput("That grant was created on this Mac and is already armed.")
        }
        guard state.grants[index].deviceKillSwitch == nil else {
            throw VaultageError.policyDenied("That grant ended when its device was unpaired or revoked, and arming cannot bring it back.")
        }
        guard state.grants[index].revokedAt == nil else {
            throw VaultageError.policyDenied("That grant was revoked.")
        }
        if state.grants[index].armedAt == nil { state.grants[index].armedAt = now }
        // BL-136 step 1. `armedAt` is under the MAC, so arming re-stamps it —
        // and a pending grant whose `armedAt` was written by hand verifies
        // under neither stamp.
        state.grants[index].mac = try signer.mac(for: state.grants[index])
        return state.grants[index]
    }

    /// §4.6 consequence 3 / Q17. **The kill is a durable stamp, not a
    /// digest-only denial.**
    ///
    /// Called in the same metadata update as an unpairing or as the verification
    /// of a DSRL entry, exactly as `revokeGrant` already walks the list. Two
    /// reasons the digest alone was not enough. First, **it is reversible**: the
    /// `apv` key is a Secure Enclave key that unpairing does not destroy, so a
    /// second ceremony with the same phone reproduces the same thumbprint, the
    /// digest resolves again, and every grant that phone created resumes
    /// authorizing — containment becoming a pause. Second, **the owner could not
    /// recognise the effect**: a digest-resolution failure surfaces as "a record
    /// this grant covers has changed or no longer exists", a message about
    /// records for an act about devices. With the stamp, Activity says "ended
    /// when you unpaired Eden's iPhone".
    ///
    /// Returns the grants it stamped, so the caller can drop their cached
    /// secrets in the same breath (`GrantSecretCache.invalidate`) and name them
    /// in a receipt.
    @discardableResult
    public static func stampDeviceKillSwitch(forDeviceID deviceID: String, now: Date, in state: inout VaultageMetadata, signer: any GrantSigning) -> [UUID] {
        var stamped: [UUID] = []
        for index in state.grants.indices where state.grants[index].decidingDeviceID == deviceID && state.grants[index].deviceKillSwitch == nil {
            state.grants[index].deviceKillSwitch = now
            // BL-136 step 1. The kill switch is under the MAC (removing it
            // from the file would otherwise revive the grant after a re-pair).
            // A record that cannot be stamped is left as it was: it already
            // authorizes nothing.
            state.grants[index].mac = try? signer.mac(for: state.grants[index])
            stamped.append(state.grants[index].id)
        }
        return stamped
    }

    /// The coverage the arming prompt states, rebuilt from the stored grant.
    ///
    /// **The prompt carries the full `GrantDisclosure`** (Q16), not a summary of
    /// it: the owner is being asked to start something they approved on another
    /// device minutes ago, and the one thing that makes that meaningful is
    /// seeing the same coverage again. Labels are resolved from live records; the
    /// counts and the four sentences come from the grant itself.
    public static func armingDisclosure(for grant: Grant, in state: VaultageMetadata) -> GrantDisclosure {
        let environments = grant.environmentIDs.compactMap { id in state.environments.first { $0.id == id } }
        let clientName = grant.scope.clientID.flatMap { id in state.enrolledClients.first { $0.id == id }?.displayName }
        let operations = Set(grant.bindings.flatMap(\.allowedOperations))
        let mutations = operations.filter { $0.taxonomy.kind != .read }
        return GrantDisclosure(
            scopeLabel: scopeLabel(grant.scope, clientName: clientName, in: state),
            durationLabel: grant.duration.label,
            expiresAt: grant.expiresAt,
            environmentLabels: environments.map { label(for: $0, in: state) }.sorted(),
            operationLabels: operations.map(\.rawValue).sorted(),
            includesProduction: grant.includesProduction,
            productionEnvironmentLabels: environments.filter(\.isProduction).map { label(for: $0, in: state) }.sorted(),
            mutationLabels: mutations.map { "\($0.verbLabel) · \($0.taxonomy.resource.label) · \($0.rawValue)" }.sorted(),
            mutationResourceKinds: Set(mutations.map(\.taxonomy.resource.label)).sorted(),
            digest: grant.digest
        )
    }

    /// §4.7 layer 5b's local banner, as data.
    ///
    /// **On applying a production-covering grant the Mac raises a persistent,
    /// dismissal-required banner at next unlock** naming the grant, its
    /// environments, its expiry and the deciding device, with a Revoke button.
    /// It replaces reliance on layer 5, which is control-plane-mediated and
    /// therefore detective only against an honest relay (A25).
    public struct ProductionBanner: Equatable, Sendable {
        public let grantID: UUID
        public let environmentLabels: [String]
        public let expiresAt: Date
        public let decidingDeviceName: String
        public let isArmed: Bool
    }

    public static func productionBanner(for grant: Grant, in state: VaultageMetadata) -> ProductionBanner? {
        guard grant.includesProduction, let deviceID = grant.decidingDeviceID else { return nil }
        let environments = grant.environmentIDs
            .compactMap { id in state.environments.first { $0.id == id } }
            .filter(\.isProduction)
        // Rendered from the **local pairing record**, never from the roster's
        // `name` at render time (§4.8) — and through the Class B rule, so a
        // record an earlier build wrote cannot put a bidi override or a 4 KiB
        // invisible-separator run into the production banner (BM-H4).
        let name = RemoteDevicePairingPolicy.renderableDeviceName(for: deviceID, in: state)
        return ProductionBanner(
            grantID: grant.id,
            environmentLabels: environments.map { label(for: $0, in: state) }.sorted(),
            expiresAt: grant.expiresAt,
            decidingDeviceName: name,
            isArmed: grant.armedAt != nil
        )
    }
}
