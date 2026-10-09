import Foundation

/// BL-099 — **the two commit-time comparisons, in order, inside one
/// `metadata.updateResult`** (§3.3.1.1, residual 4, DB-H33).
///
/// Version 5 said both "it is never the number the phone signed" and "the
/// commit-time re-compare compares the signed offered coverage", which cannot
/// both be true of one comparison; a builder implementing the second writes
/// `confirmed.digest == signedOfferedCoverageDigest` and it never matches. There
/// are **two** facts to establish and version 5 named one:
///
/// 1. **The offer has not moved since 9c.** Recompute `offeredCoverageDigest`
///    under the lock and compare it to the **signed** value — a second 9c, now
///    atomic with the write. A mismatch is `digest_mismatch`.
/// 2. **The committed coverage is what the owner's choices resolve to.** Compute
///    `coveringDigest` fresh, with the real device section and
///    `includedMutations` as signed. **There is no draft to compare it against,
///    and that is deliberate**: `coveringDigest` throws on a missing or changed
///    covered record, and that throw *is* the record-state denial, with the
///    message the local path already gives.
///
/// **The local path keeps its existing draft re-compare unchanged**
/// (`Broker.swift:559`). The remote path's absence of one is deliberate and is
/// compensated by (1).
public enum RemoteGrantCommit {
    public struct Refusal: LocalizedError, Equatable {
        public let reason: RemoteRefusalReason
        public let message: String
        public var errorDescription: String? { message }
    }

    /// Builds the `GrantRequest` the remote path hands to `prepare`.
    ///
    /// **`environmentIDs` comes from the narrowed set, never from live state**
    /// (ticket gap 7, DB-H37). The narrowing is appendix row P0's, already run
    /// at check 8 over the **retained** offer — which is what the owner was
    /// shown and signed — so the arming prompt and the receipt describe exactly
    /// the set the owner saw. `prepare` **throws** where version 6 assumed it
    /// filters (`Grant.swift:509-511` for projects, `:506-508` for production),
    /// so handing it the offered set with a narrowed project set would throw at
    /// commit on the default path.
    public static func request(from decision: RemoteAcceptedDecision) throws -> GrantRequest {
        let payload = decision.payload
        let scope: GrantScope
        switch payload.scope {
        case .client:
            guard let raw = payload.scopeClientId, let clientID = UUID(uuidString: raw) else {
                throw Refusal(reason: .digestMismatch, message: "A client-scoped decision named no enrolled client.")
            }
            scope = GrantScope(client: clientID)
        case .projects:
            let ids = Set(payload.scopeProjectIds.compactMap(UUID.init(uuidString:)))
            guard !ids.isEmpty else {
                throw Refusal(reason: .digestMismatch, message: "A project-scoped decision named no projects.")
            }
            scope = GrantScope(projects: ids)
        case .once:
            throw Refusal(reason: .digestMismatch, message: "An allow-once decision creates no grant.")
        }
        guard let duration = GrantDuration(rawValue: payload.duration.rawValue) else {
            throw Refusal(reason: .digestMismatch, message: "A grant-creating decision carried no duration.")
        }
        let mutations = Set(payload.includedMutations.compactMap(Operation.init(rawValue:)))
        guard mutations.count == payload.includedMutations.count else {
            throw Refusal(reason: .digestMismatch, message: "A decision named a mutation this build does not compile.")
        }
        return GrantRequest(
            scope: scope,
            environmentIDs: decision.narrowedEnvironmentIDs,
            duration: duration,
            includeProduction: payload.includeProduction,
            includedMutations: mutations
        )
    }

    /// Runs both comparisons and commits, in that order.
    ///
    /// Call inside `metadata.updateResult`, so (1) is atomic with the write it
    /// guards. The `decisionId` is burned by the caller **before** this runs, in
    /// the same locked section (§4.3 check 5).
    @discardableResult
    public static func commit(
        _ decision: RemoteAcceptedDecision,
        offer: RemoteOfferedCoverage.Offer,
        now: Date,
        in state: inout VaultageMetadata,
        signer: any GrantSigning
    ) throws -> Grant {
        // (1) The offer has not moved since 9c. A second 9c, atomic with the
        //     write.
        guard let signedDigest = RemoteDecisionVerification.signedOfferedCoverageDigest(in: decision.verifiedVersion.fields) else {
            throw Refusal(reason: .digestMismatch, message: "The retained field list carries no offered-coverage digest.")
        }
        let recomputed: String
        do {
            recomputed = try RemoteOfferedCoverage.digest(offer, in: state, now: now)
        } catch {
            // An offer that no longer resolves at all has certainly moved.
            throw Refusal(reason: .digestMismatch, message: "The coverage this request offered no longer resolves.")
        }
        guard recomputed == signedDigest else {
            throw Refusal(reason: .digestMismatch, message: "The coverage this request offered changed between publication and commit.")
        }

        // (2) The committed coverage is what the owner's choices resolve to.
        //     Computed fresh, with the real device section and the signed
        //     mutations, and **with no draft comparison**: `prepare` and
        //     `coveringDigest` throw on a missing or changed covered record, and
        //     that throw is the record-state denial.
        let draft = try GrantPolicy.prepare(
            try request(from: decision),
            in: state,
            now: now,
            decidingDeviceID: decision.payload.decidingDeviceId
        )
        let grant = try GrantPolicy.commit(draft, now: now, in: &state, signer: signer)
        // §4.7 layer 7, asserted at the point of commit rather than trusted:
        // a remote grant lands `pendingArm` and authorizes nothing.
        guard grant.isPendingArm, !grant.isUsable(at: now) else {
            throw Refusal(reason: .digestMismatch, message: "A remotely created grant did not commit unarmed.")
        }
        return grant
    }
}
