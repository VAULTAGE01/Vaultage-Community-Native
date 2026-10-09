import CryptoKit
import Foundation

/// BL-099 — **the twelve checks the Mac runs before applying a decision**
/// (§4.3, appendix §2), as one pure function.
///
/// Ordered. All fail closed. **Stop at the first failure.** The order is not
/// cosmetic: check 2 — is this deciding device locally paired and unrevoked — is
/// the only check that survives a compromised relay and needs no network, so it
/// runs before the roster is consulted at all.
///
/// **Everything here is decided from local records and the appendix's
/// preimages.** The Mac never accepts a digest from the wire, never resolves a
/// key from the roster, and never rebuilds the preimage it verifies against
/// from live state — it verifies against the field list it **retained** at
/// publication (§3.2, DB-C5), because `presence` and the five display fields are
/// values that will have moved by the time the owner signs. Rebuilding would
/// turn verification into a search over candidate preimages.

// MARK: - Reason codes

/// The appendix's §3, split the way the appendix splits it.
public enum RemoteRefusalReason: String, Equatable, Sendable, CaseIterable {
    // Local-only refusals — **never on the wire**.
    case unknownPending = "unknown_pending"
    case decidingDeviceUnrecognised = "deciding_device_unrecognised"
    case rosterUnavailable = "roster_unavailable"
    case decisionReplayed = "decision_replayed"
    case presenceUnavailable = "presence_unavailable"
    case coverageEmpty = "coverage_empty"
    // Cancel reasons that are also refusal reasons.
    case requestChanged = "request_changed"
    case digestMismatch = "digest_mismatch"
    case decisionStale = "decision_stale"

    /// The five §3 names as **local-only**: they say something about local state
    /// and must not reach the relay.
    public static let localOnly: Set<RemoteRefusalReason> = [
        .unknownPending, .decidingDeviceUnrecognised, .rosterUnavailable, .decisionReplayed, .presenceUnavailable
    ]

    /// What the Mac posts to the relay, or `nil` when nothing is posted.
    ///
    /// **`coverage_empty` goes out as `request_changed`, never as
    /// `digest_mismatch`** (version 8, NEW-M1): it is reachable with no attacker
    /// at all — tick one production-only project, decline production — and the
    /// phone must read *"the projects you chose don't cover anything in this
    /// request"* rather than tampering copy.
    public var wireCancelReason: RemoteCancelReason? {
        switch self {
        case .requestChanged, .coverageEmpty: .requestChanged
        case .digestMismatch: .digestMismatch
        case .decisionStale: .decisionStale
        case .unknownPending, .decidingDeviceUnrecognised, .rosterUnavailable, .decisionReplayed, .presenceUnavailable: nil
        }
    }

    /// Every refusal reaches the agent as `approval_denied`, unchanged from
    /// `09-ENGINEERING-CONTRACTS.md` §1. The distinction here is what the *owner*
    /// and the *phone* are told, not what the agent is.
    public var agentFacingOutcome: String { "approval_denied" }
}

// MARK: - §4.4's durable replay cache

/// One burned `decisionId`.
public struct RemoteDecisionReplayEntry: Codable, Hashable, Sendable {
    public let decisionID: String
    public let burnedAt: Date
    public init(decisionID: String, burnedAt: Date) {
        self.decisionID = decisionID
        self.burnedAt = burnedAt
    }
}

/// §4.4. Capacity **512**, pruned at **24 hours**, checked-and-inserted
/// atomically **before any effect**, and durable — it lives in
/// `VaultageMetadata`, so it survives a restart. Together with the Worker's
/// `UNIQUE(pending_id)` it is the second of two independent single-use records,
/// which is what let §4.4 lengthen a signature's validity from version 2's
/// 120 seconds — a window that denied every remote approval whose Mac had slept
/// — to the pending's own remaining life.
public enum RemoteDecisionReplayCache {
    public static let capacity = 512
    public static let pruneAfterSeconds: TimeInterval = 24 * 60 * 60

    public static func contains(_ decisionID: String, in state: VaultageMetadata) -> Bool {
        state.remoteDecisionReplays.contains { $0.decisionID == decisionID }
    }

    /// Returns `false` when the id was already burned, in which case nothing is
    /// written. The check and the insert are one operation on purpose: the
    /// caller runs it inside the metadata lock, before any effect.
    @discardableResult
    public static func burn(_ decisionID: String, now: Date, in state: inout VaultageMetadata) -> Bool {
        prune(now: now, in: &state)
        guard !contains(decisionID, in: state) else { return false }
        state.remoteDecisionReplays.append(RemoteDecisionReplayEntry(decisionID: decisionID, burnedAt: now))
        if state.remoteDecisionReplays.count > capacity {
            state.remoteDecisionReplays.sort { $0.burnedAt < $1.burnedAt }
            state.remoteDecisionReplays.removeFirst(state.remoteDecisionReplays.count - capacity)
        }
        return true
    }

    public static func prune(now: Date, in state: inout VaultageMetadata) {
        state.remoteDecisionReplays.removeAll { now.timeIntervalSince($0.burnedAt) > pruneAfterSeconds }
    }
}

// MARK: - §2.3 / §4.3 check 4's roster

/// What the Mac has cached of the account's device roster.
///
/// **The roster has no authority** (§2.3). It is a freshness and revocation
/// *hint*, the transport by which a newly enrolled device's thumbprints reach
/// the other device before the ceremony confirms them, and the display list on
/// the Devices screen. No key is ever used because the roster contains it.
/// §4.4's decision validity, as a number the check reads rather than a property
/// the signer asserts (BM-M2).
public enum RemoteDecisionValidity {
    /// `decision.expiresAt = min(issuedAt + 900, pending.expiresAt)`, and check
    /// 6 recomputes the first term rather than trusting the result.
    public static let maximumSeconds = 900
}

public struct RemoteRosterCache: Codable, Hashable, Sendable {
    public static let stalenessSeconds: TimeInterval = 24 * 60 * 60

    public let issuedAt: Date
    public let fetchedAt: Date
    public let digest: String
    /// **Check 4 case (b)**, carried on the cache because that is where it is
    /// observed: `refreshRoster()` saw the account's `roster_issued_at` move
    /// **backwards**. A roster that goes back in time is a rollback — an
    /// attempt to un-revoke a device — not a hiccup, and unlike (a) and (c) it
    /// is not cured by waiting. Set by `RemoteRosterRefresher`, cleared only by
    /// a roster that is at least as new as the watermark.
    public let issuedAtRegressed: Bool

    public init(issuedAt: Date, fetchedAt: Date, digest: String, issuedAtRegressed: Bool = false) {
        self.issuedAt = issuedAt
        self.fetchedAt = fetchedAt
        self.digest = digest
        self.issuedAtRegressed = issuedAtRegressed
    }
}

// MARK: - The inputs

/// The offer the Mac published, as check 7 needs it. Taken from the retained
/// field list's own summary rather than re-derived, which is what makes "the
/// owner is bounded by what they were shown" a property rather than a hope.
public struct RemoteDecisionOffer: Hashable, Sendable {
    public let summaryClass: RemoteApprovalClass
    public let offeredScopes: Set<String>
    public let offeredDurations: Set<String>
    public let offeredProjectIDs: Set<String>
    public let offeredProduction: Bool
    public let offeredMutations: Set<String>
    public let choiceIDs: Set<String>
    public let agentClientID: String?
    /// Every environment the offer covers, before any narrowing.
    public let offeredEnvironmentIDs: Set<UUID>

    public init(summaryClass: RemoteApprovalClass, offeredScopes: Set<String>, offeredDurations: Set<String>, offeredProjectIDs: Set<String>, offeredProduction: Bool, offeredMutations: Set<String>, choiceIDs: Set<String>, agentClientID: String?, offeredEnvironmentIDs: Set<UUID>) {
        self.summaryClass = summaryClass
        self.offeredScopes = offeredScopes
        self.offeredDurations = offeredDurations
        self.offeredProjectIDs = offeredProjectIDs
        self.offeredProduction = offeredProduction
        self.offeredMutations = offeredMutations
        self.choiceIDs = choiceIDs
        self.agentClientID = agentClientID
        self.offeredEnvironmentIDs = offeredEnvironmentIDs
    }
}

/// Everything §4.3 reads, gathered by the broker and handed to one pure
/// function.
public struct RemoteDecisionVerificationInput: Sendable {
    public let signed: RemoteSignedDecision
    public let pending: RemotePendingPublication
    public let offer: RemoteDecisionOffer
    public let macDeviceID: String
    public let accountSubject: String
    public let roster: RemoteRosterCache?
    public let now: Date
    /// Step 9b's comparison target: the field list rebuilt from **live**
    /// records, for the recipient named by the verified `decidingDeviceId`.
    /// `nil` skips 9b, which only a test does.
    public let liveRebuiltFields: [String]?
    /// Step 9c's recomputation, for `class: grant` only.
    public let recomputedOfferedCoverageDigest: String?
    /// Step 10's re-proof of `brokerRequestDigest` against freshly loaded state.
    public let reprovedBrokerRequestDigest: String?

    public init(signed: RemoteSignedDecision, pending: RemotePendingPublication, offer: RemoteDecisionOffer, macDeviceID: String, accountSubject: String, roster: RemoteRosterCache?, now: Date, liveRebuiltFields: [String]? = nil, recomputedOfferedCoverageDigest: String? = nil, reprovedBrokerRequestDigest: String? = nil) {
        self.signed = signed
        self.pending = pending
        self.offer = offer
        self.macDeviceID = macDeviceID
        self.accountSubject = accountSubject
        self.roster = roster
        self.now = now
        self.liveRebuiltFields = liveRebuiltFields
        self.recomputedOfferedCoverageDigest = recomputedOfferedCoverageDigest
        self.reprovedBrokerRequestDigest = reprovedBrokerRequestDigest
    }
}

/// What survives all twelve checks.
public struct RemoteAcceptedDecision: Sendable {
    public let payload: RemoteDecisionPayload
    public let pairing: DevicePairingRecord
    /// The version the signature actually verified against, which is the object
    /// the owner read.
    public let verifiedVersion: RemoteRetainedVersion
    /// Appendix row P0's result. **Checks 8, 8a and 9c and the `GrantRequest`
    /// handed to `prepare` all use this, never the offered set.**
    public let narrowedEnvironmentIDs: Set<UUID>
    public let rosterDigest: String?
}

public enum RemoteDecisionVerificationOutcome: Sendable {
    case accepted(RemoteAcceptedDecision)
    case refused(RemoteRefusal)
}

public struct RemoteRefusal: Equatable, Sendable {
    /// Which numbered check refused, as the appendix labels it — `"2"`, `"8a"`,
    /// `"9b"`. Recorded so a receipt and a bug report name the same step.
    public let check: String
    public let reason: RemoteRefusalReason
    public var wireCancelReason: RemoteCancelReason? { reason.wireCancelReason }

    public init(check: String, reason: RemoteRefusalReason) {
        self.check = check
        self.reason = reason
    }
}

// MARK: - The twelve checks

public enum RemoteDecisionVerification {
    /// §4.3, in order, all fail-closed, stopping at the first failure.
    ///
    /// The replay cache is **not** touched here: check 5 only *reads* it. The
    /// insert happens in the caller's `metadata.updateResult`, before any
    /// effect, because the check and the effect have to be in one locked section
    /// and a pure function cannot hold a lock.
    public static func verify(_ input: RemoteDecisionVerificationInput, in state: VaultageMetadata) -> RemoteDecisionVerificationOutcome {
        let signed = input.signed
        let nowEpoch = Int(input.now.timeIntervalSince1970)

        // 1. The pending exists locally, **is `Pending`**, and `pendingId`
        //    matches. The appendix says `Pending`, singular, and this admitted
        //    three states (BM-M1). Because the replay cache is keyed on
        //    `decisionId` and not on `pendingId`, a second decision with a fresh
        //    id then passed checks 1 and 5 and applied — so §1's actor table put
        //    "decide twice" in the phone's **Cannot** column while only the
        //    Worker's `UNIQUE(pending_id)` carried it, and §4.4's *two*
        //    independent single-use records were one. `decided` and `delivered`
        //    are the control plane's last words about a pending that has been
        //    answered; a Mac that has seen either has nothing left to decide.
        guard input.pending.state == .pending else {
            return .refused(RemoteRefusal(check: "1", reason: .unknownPending))
        }

        // 2. `decidingDeviceId` is **locally paired** and not revoked by any
        //    active DSRL entry. *Evaluated before the roster, and the only check
        //    that survives a compromised control plane.*
        guard RemoteDevicePairingPolicy.isServedAndPaired(signed.decidingDeviceId, in: state),
              let pairing = RemoteDevicePairingPolicy.pairing(for: signed.decidingDeviceId, in: state)
        else {
            return .refused(RemoteRefusal(check: "2", reason: .decidingDeviceUnrecognised))
        }

        // 3. The verifying key is the **pinned** `apv` key; the wire
        //    `apvThumbprint` must equal it. The wire copy exists only so a
        //    mismatch produces a clear error rather than a signature failure.
        guard let verifyingKey = pairing.apvVerifyingKey, signed.apvThumbprint == pairing.apvThumbprint else {
            return .refused(RemoteRefusal(check: "3", reason: .decidingDeviceUnrecognised))
        }

        // 4. The roster rule, stated once. A decision is refused on roster
        //    grounds **only** if (a) no roster has ever been seen, (b)
        //    `roster_issued_at` moved backwards, or (c) the cached roster is
        //    older than 24 hours. **A `refreshRoster()` failure is not a
        //    refusal**: version 5's "succeeded and within 300 s" handed the
        //    relay its cheapest denial — `503` the entitlement route and the Mac
        //    reads it as its own failure.
        guard let roster = input.roster else {
            return .refused(RemoteRefusal(check: "4", reason: .rosterUnavailable))
        }
        guard !roster.issuedAtRegressed else {
            return .refused(RemoteRefusal(check: "4", reason: .rosterUnavailable))
        }
        guard input.now.timeIntervalSince(roster.fetchedAt) <= RemoteRosterCache.stalenessSeconds else {
            return .refused(RemoteRefusal(check: "4", reason: .rosterUnavailable))
        }

        // 5. `decisionId` is not in the replay cache.
        guard !RemoteDecisionReplayCache.contains(signed.decisionId, in: state) else {
            return .refused(RemoteRefusal(check: "5", reason: .decisionReplayed))
        }

        // 6. `issuedAt ≤ now + 60` and `now < min(issuedAt + 900, decision
        //    expiresAt, pending expiresAt)`.
        //
        //    **§4.4's 900 seconds is a check the Mac runs, not a property of the
        //    decision** (BM-M2). `decision.expiresAt = min(issuedAt + 900,
        //    pending.expiresAt)` is inside the signed preimage, so a relay
        //    cannot move it — but the *phone* writes it, and it can write
        //    anything. Before this, the only bound was the pending's own TTL,
        //    which caps at 900 s today by coincidence rather than by rule:
        //    §3.5's ceiling is 15 minutes and `provisioning_selection` already
        //    reaches it, so the moment a class gets a longer TTL the rule stops
        //    holding.
        guard signed.issuedAt <= nowEpoch + 60,
              nowEpoch < min(signed.issuedAt + RemoteDecisionValidity.maximumSeconds, signed.expiresAt, input.pending.expiresAt)
        else {
            return .refused(RemoteRefusal(check: "6", reason: .decisionStale))
        }

        // 7. Everything the owner chose is inside what they were offered.
        let offer = input.offer
        guard offer.offeredScopes.contains(signed.scope.rawValue) else {
            return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
        }
        // `duration ∈ offeredDurations`, **or `"none"` when `scope == once`**.
        if signed.scope == .once {
            guard signed.duration == RemoteDecisionDuration.none else {
                return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
            }
        } else {
            guard offer.offeredDurations.contains(signed.duration.rawValue) else {
                return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
            }
        }
        if let choice = signed.choiceId {
            guard offer.choiceIDs.contains(choice) else {
                return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
            }
        }
        // **Compared as UUIDs, not as strings.** `UUID.uuidString` is
        // upper-case and a hand-written literal is usually lower-case, so a
        // string comparison would refuse a perfectly well-formed decision for a
        // rendering choice — a `digest_mismatch`, which is tampering copy, over
        // letter case. The value the phone signed is still exactly the value it
        // sent; what is not semantic is the case of a hexadecimal identifier.
        let offeredProjects = Set(offer.offeredProjectIDs.compactMap(UUID.init(uuidString:)))
        let chosenProjects = Set(signed.scopeProjectIds.compactMap(UUID.init(uuidString:)))
        guard chosenProjects.count == signed.scopeProjectIds.count, chosenProjects.isSubset(of: offeredProjects) else {
            return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
        }
        if signed.scope == .client {
            guard let chosen = signed.scopeClientId.flatMap(UUID.init(uuidString:)),
                  let offered = offer.agentClientID.flatMap(UUID.init(uuidString:)),
                  chosen == offered
            else { return .refused(RemoteRefusal(check: "7", reason: .digestMismatch)) }
        } else if let raw = signed.scopeClientId {
            // A non-client scope may still name the agent — `allow.once` does —
            // but it may not name a *different* one.
            guard let chosen = UUID(uuidString: raw), chosen == offer.agentClientID.flatMap(UUID.init(uuidString:)) else {
                return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
            }
        }
        guard Set(signed.includedMutations).isSubset(of: offer.offeredMutations) else {
            return .refused(RemoteRefusal(check: "7", reason: .digestMismatch))
        }

        // 7a. Every included mutation still satisfies
        //     `ApprovalRequirement.of(_).requiresExplicitGrantInclusion`
        //     against live records.
        for raw in signed.includedMutations {
            guard let operation = Operation(rawValue: raw), operation.approvalRequirement.requiresExplicitGrantInclusion else {
                return .refused(RemoteRefusal(check: "7a", reason: .digestMismatch))
            }
        }

        // 8. **Production, against the NARROWED set. The pre-filter runs here,
        //    before the test** (version 8, NEW-H4). Version 7 described the
        //    filter as running at request-build time, so a builder implementing
        //    the checks in order tested the *offered* set and refused every
        //    "decline production on a production-capable offer" with
        //    `digest_mismatch` — the exact failure DB-H37 exists to close.
        let narrowed = RemoteOfferedCoverage.narrowed(
            offeredEnvironmentIDs: offer.offeredEnvironmentIDs,
            scopeKind: signed.scope,
            scopeProjectIDs: Set(signed.scopeProjectIds.compactMap(UUID.init(uuidString:))),
            includeProduction: signed.includeProduction,
            in: state
        )
        if signed.includeProduction {
            guard offer.summaryClass == .grant, offer.offeredProduction, signed.duration == .oneDay else {
                return .refused(RemoteRefusal(check: "8", reason: .digestMismatch))
            }
            guard let typed = signed.typedEnvironmentName,
                  resolvesToExactlyOneProductionEnvironment(typed, within: narrowed, in: state)
            else {
                return .refused(RemoteRefusal(check: "8", reason: .digestMismatch))
            }
        } else {
            // Version 4's extra rule "a name equal to the sensitivity value is
            // refused" is **dropped**: it made an environment genuinely named
            // "production" unapprovable.
            guard signed.typedEnvironmentName == nil else {
                return .refused(RemoteRefusal(check: "8", reason: .digestMismatch))
            }
            // Which it cannot, because the pre-filter removed them — asserted
            // rather than assumed.
            guard !narrowed.contains(where: { id in state.environments.first { $0.id == id }?.isProduction == true }) else {
                return .refused(RemoteRefusal(check: "8", reason: .digestMismatch))
            }
        }

        // 8a. **An empty narrowed set is a plain refusal, not a security
        //     refusal** (version 8, NEW-M1). Reachable with no attacker: an
        //     offer covers a production-only project and a non-production one,
        //     the owner ticks the first and declines production — both
        //     explicitly permitted by checks 7 and 8 — and the filter yields
        //     nothing.
        guard !narrowed.isEmpty else {
            return .refused(RemoteRefusal(check: "8a", reason: .coverageEmpty))
        }

        // 9a. **Verify** against the **retained** field list for the phone named
        //     by check 2, **newest-first**, capped at 16 and evicted
        //     oldest-first.
        guard let signatureBytes = signed.signatureBytes,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
        else {
            return .refused(RemoteRefusal(check: "9a", reason: .digestMismatch))
        }
        let versions = input.pending.retained.versionsNewestFirst(for: signed.decidingDeviceId)
        var verified: RemoteRetainedVersion?
        var verifiedIndex = -1
        for (index, version) in versions.enumerated() {
            let payload = signed.payload(
                accountSubject: input.accountSubject, macDeviceId: input.macDeviceID,
                summaryDigest: version.summaryDigest, approvalRequestDigest: version.approvalRequestDigest
            )
            let preimage = RemoteApprovalDigests.decisionPreimage(payload)
            // §4.1's domain separation, checked **before any curve operation**.
            guard RemoteApprovalDigests.hasDecisionDomainPrefix(preimage) else { continue }
            if verifyingKey.isValidSignature(signature, for: preimage) {
                verified = version
                verifiedIndex = index
                break
            }
        }
        guard let verifiedVersion = verified else {
            // A failure against **every** retained version is a security
            // refusal.
            return .refused(RemoteRefusal(check: "9a", reason: .digestMismatch))
        }
        guard verifiedIndex == 0 else {
            // A verify against an **older** entry is an ordinary
            // `request_changed` — the owner signed the copy their phone had
            // already fetched, with no attacker present — not tampering copy.
            return .refused(RemoteRefusal(check: "9a", reason: .requestChanged))
        }

        // 9b. **Compare.** *Then* rebuild from live records and compare field by
        //     field. Differences confined to the five display fields are
        //     `request_changed`; differences in `brokerRequestDigest`, the scope
        //     fields, the offer set or the class section are `digest_mismatch`.
        if let live = input.liveRebuiltFields, live != verifiedVersion.fields {
            let classification = classifyFieldDrift(retained: verifiedVersion.fields, live: live)
            return .refused(RemoteRefusal(check: "9b", reason: classification))
        }

        // 9c. **The offer has not grown** (grant only; checklist 1, DB-C6/H29).
        //     **Growth is `digest_mismatch`.** Record-state drift is **not
        //     evaluated here at all** — a rotated credential, a re-verified
        //     connection, a paused plan — because none of it is in the identity
        //     digest; it denies at commit through `createGrant`'s existing
        //     re-compare.
        if offer.summaryClass == .grant {
            guard let recomputed = input.recomputedOfferedCoverageDigest,
                  let signedDigest = signedOfferedCoverageDigest(in: verifiedVersion.fields)
            else {
                return .refused(RemoteRefusal(check: "9c", reason: .digestMismatch))
            }
            guard recomputed == signedDigest else {
                return .refused(RemoteRefusal(check: "9c", reason: .digestMismatch))
            }
        }

        // 10. The broker re-proves `brokerRequestDigest` against freshly loaded
        //     state — the same three-times-per-action re-proof the local path
        //     already does. **A failure is `request_changed`** (version 7,
        //     appendix mismatch 6: the appendix was ahead of the body here and
        //     the body adopted its answer).
        if let reproved = input.reprovedBrokerRequestDigest {
            guard let retainedDigest = brokerRequestDigest(in: verifiedVersion.fields), reproved == retainedDigest else {
                return .refused(RemoteRefusal(check: "10", reason: .requestChanged))
            }
        }

        // 11. Only then is the decision applied — subject to §11's answer, which
        //     for release one is (b).
        return .accepted(RemoteAcceptedDecision(
            payload: signed.payload(
                accountSubject: input.accountSubject, macDeviceId: input.macDeviceID,
                summaryDigest: verifiedVersion.summaryDigest, approvalRequestDigest: verifiedVersion.approvalRequestDigest
            ),
            pairing: pairing,
            verifiedVersion: verifiedVersion,
            narrowedEnvironmentIDs: narrowed,
            rosterDigest: roster.digest
        ))
    }

    // MARK: Step 8's name comparison

    /// §4.3 step 8: `typedEnvironmentName` **resolves to exactly one environment
    /// in the narrowed set for which `Environment.isProduction` is true**, under
    /// **NFC + trim + case-insensitive** comparison (§3.3 item 1c).
    ///
    /// "Exactly one" is the operative word: two production environments whose
    /// names differ only in case would make the typed name ambiguous, and an
    /// ambiguous production grant is not one the owner can have meant.
    public static func resolvesToExactlyOneProductionEnvironment(_ typed: String, within narrowed: Set<UUID>, in state: VaultageMetadata) -> Bool {
        let needle = normalizedEnvironmentName(typed)
        guard !needle.isEmpty else { return false }
        let matches = state.environments.filter { environment in
            narrowed.contains(environment.id)
                && environment.isProduction
                && normalizedEnvironmentName(environment.name) == needle
        }
        return matches.count == 1
    }

    public static func normalizedEnvironmentName(_ value: String) -> String {
        value.precomposedStringWithCanonicalMapping
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    // MARK: Step 9b's classification (DB-M8)

    /// The **five display fields** whose drift is `request_changed` rather than
    /// tampering: `projectName`, `environmentName`, `connectionLabel`,
    /// `principalHint`, `resourceLabel`. They are deliberately **not** excluded
    /// from the digest to make this go away — they are what the owner read,
    /// which is DB-C1's whole point.
    ///
    /// Their positions in P4's body are fixed by the manifest, which is what
    /// makes "confined to the display fields" a decidable statement rather than
    /// a guess.
    public static let displayFieldIndices: Set<Int> = [
        // body index, counting from the field after the count:
        // 0 class · 1 pendingId · 2 accountSubject · 3 macDeviceId · 4 agentState
        // 5 agentLabel · 6 agentClientId · 7 provider · 8 connectionLabel
        // 9 principalHint · 10 projectName · 11 environmentName · 12 sensitivity
        8, 9, 10, 11,
        // 13 "isProduction" · 14 value · 15 operation · 16 verb · 17 effect
        // 18 trustClass · 19 resourceLabel
        19
    ]

    static func classifyFieldDrift(retained: [String], live: [String]) -> RemoteRefusalReason {
        // A different arity is never "a label moved": it is a different object.
        guard retained.count == live.count else { return .digestMismatch }
        var driftedIndices: Set<Int> = []
        for index in retained.indices where retained[index] != live[index] {
            // Index 0 is the domain tag and 1 is the count; the body starts at 2.
            guard index >= 2 else { return .digestMismatch }
            driftedIndices.insert(index - 2)
        }
        // `presence` and `openPendingCount` are publish-time snapshots and are
        // expected to move, but they are *inside the seal*, so a live rebuild
        // that disagrees about them is not evidence of anything and must not
        // read as tampering either. They are classified with the display fields.
        let benign = displayFieldIndices.union(presenceSnapshotIndices(in: retained))
        return driftedIndices.isSubset(of: benign) ? .requestChanged : .digestMismatch
    }

    /// The value fields of the `"presence"` and `"openPendingCount"` groups,
    /// located by their labels rather than by a counted offset, because the
    /// offer lists before them are variable length.
    static func presenceSnapshotIndices(in fields: [String]) -> Set<Int> {
        var indices: Set<Int> = []
        for (index, field) in fields.enumerated() where field == "presence" || field == "openPendingCount" {
            guard index + 1 < fields.count, index >= 2 else { continue }
            indices.insert(index + 1 - 2)
        }
        return indices
    }

    // MARK: Reading the retained field list

    /// The `offeredCoverageDigest` the owner signed, read out of the retained
    /// field list rather than recomputed — it is the one field of the manifest
    /// the phone cannot derive (§3.3 rule 1's carve-out), so the signed copy is
    /// the only copy.
    public static func signedOfferedCoverageDigest(in fields: [String]) -> String? {
        guard let recipient = fields.lastIndex(of: "recipient"), recipient >= 1 else { return nil }
        return fields[recipient - 1]
    }

    /// `brokerRequestDigest` sits immediately before `issuedAt` and
    /// `expiresAt`, after `brokerDigestKind`, and is the only 64-hex field in
    /// that position.
    public static func brokerRequestDigest(in fields: [String]) -> String? {
        guard let custody = fields.lastIndex(of: "custodyClass"), custody + 3 < fields.count else { return nil }
        return fields[custody + 3]
    }
}
