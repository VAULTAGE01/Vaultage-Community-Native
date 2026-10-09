import Foundation

/// BL-099 slice 2 step (d) — **applying a verified remote decision exactly as a
/// native one**, and the arming touch that follows a grant.
///
/// §4.5's rule is one sentence and the whole design rests on it: *a verified
/// remote decision is applied by the same code that applies a native one*.
/// Anything else and there are two authorization paths, one of which nobody
/// looks at. So this file does not decide anything — §4.3's twelve checks
/// already did — and it does not create a second way to make a grant.
/// `RemoteGrantCommit` is the same `GrantPolicy.prepare` / `GrantPolicy.commit`
/// the sheet uses. What this file owns is the **ordering** around them, which is
/// where a remote decision differs from a native one:
///
/// * the `decisionId` is burned **before any effect**, in the same locked
///   section as the write it guards (§4.3 check 5);
/// * the first decision wins, so a local answer taken while a remote one is in
///   flight burns the remote one rather than applying both (A17);
/// * a grant lands `pendingArm` and authorizes nothing until the owner is next
///   present (§4.7 layer 7);
/// * and every receipt names the **deciding device**.

// MARK: - What applying produced

public enum RemoteApplication: Sendable, Equatable {
    /// `scope == once`. Exactly what a native "Allow once" produces: this one
    /// invocation proceeds and nothing is stored that outlives it.
    case allowedOnce(decisionID: String)
    /// A D19 grant, committed **unarmed**.
    case grantedPendingArm(grantID: UUID)
    /// The owner said no, from the phone. A denial is receipted like an
    /// approval (D38).
    case denied(decisionID: String)
    /// One of the twelve checks refused, or the commit did.
    case refused(RemoteRefusal)

    public var refusal: RemoteRefusal? {
        if case let .refused(refusal) = self { return refusal }
        return nil
    }
}

/// What the Mac writes about a remote decision, in the shape the receipt store
/// and the Activity view read.
///
/// **The deciding device is a receipt field, not a sentence.** §4.6 requires
/// receipts to name it, and the name is resolved from the **local pairing
/// record** rather than from the roster (§4.8): a relay that renames a device
/// must not be able to change what the owner's own history says happened.
public struct RemoteDecisionRecord: Sendable, Equatable {
    public let decisionID: String
    public let pendingID: String
    public let decidingDeviceID: String
    public let decidingDeviceName: String
    public let verdict: RemoteDecisionVerdict
    public let at: Date
    /// `nil` for a denial and for allow-once.
    public let grantID: UUID?
    /// Set when the decision covered production, so Activity can flag it
    /// "production · remote" (D38).
    public let coveredProduction: Bool

    public init(decisionID: String, pendingID: String, decidingDeviceID: String, decidingDeviceName: String, verdict: RemoteDecisionVerdict, at: Date, grantID: UUID?, coveredProduction: Bool) {
        self.decisionID = decisionID
        self.pendingID = pendingID
        self.decidingDeviceID = decidingDeviceID
        self.decidingDeviceName = decidingDeviceName
        self.verdict = verdict
        self.at = at
        self.grantID = grantID
        self.coveredProduction = coveredProduction
    }

    /// The Activity line. Bounded, value-free, and derived from the pin.
    public var activitySentence: String {
        let device = decidingDeviceName
        return switch verdict {
        case .allow: coveredProduction
            ? "Approved on \(device) · production · remote"
            : "Approved on \(device) · remote"
        case .deny: "Declined on \(device) · remote"
        }
    }
}

// MARK: - Applying

public enum RemoteDecisionApplication {
    /// Applies a verified decision inside one metadata update.
    ///
    /// **Call this from inside `metadata.updateResult`.** The `inout` is not a
    /// convenience: check 5's insert and the effect it guards have to be the
    /// same locked section, or two concurrent fetches of the same decision both
    /// pass check 5 and both apply.
    ///
    /// `offer` is the coverage offer the pending published, which
    /// `RemoteGrantCommit` re-resolves under the lock.
    public static func apply(
        _ decision: RemoteAcceptedDecision,
        pendingID: String,
        offer: RemoteOfferedCoverage.Offer,
        now: Date,
        in state: inout VaultageMetadata,
        signer: any GrantSigning
    ) -> (RemoteApplication, RemoteDecisionRecord?) {
        let payload = decision.payload

        // Check 5's write half. **Before any effect**, and it is an insert that
        // fails if the id is already present, never a read followed by a write.
        guard RemoteDecisionReplayCache.burn(payload.decisionId, now: now, in: &state) else {
            return (.refused(RemoteRefusal(check: "5", reason: .decisionReplayed)), nil)
        }

        // BM-H4. `decision.pairing` came from `RemoteDevicePairingPolicy.pairing(for:)`
        // at check 2, so its name is already Class B-validated; stating the rule
        // here as well is what keeps the Activity line and the audit event's
        // `result` inside it if that ever stops being true.
        let deviceName = RemoteDevicePairingPolicy.renderableDeviceName(decision.pairing, fallback: payload.decidingDeviceId)
        func record(_ verdict: RemoteDecisionVerdict, grantID: UUID?, production: Bool) -> RemoteDecisionRecord {
            RemoteDecisionRecord(
                decisionID: payload.decisionId,
                pendingID: pendingID,
                decidingDeviceID: payload.decidingDeviceId,
                decidingDeviceName: deviceName,
                verdict: verdict,
                at: now,
                grantID: grantID,
                coveredProduction: production
            )
        }

        guard payload.decision == .allow else {
            // A denial is terminal and is receipted like an approval (D38). It
            // creates nothing, so there is nothing to roll back.
            return (.denied(decisionID: payload.decisionId), record(.deny, grantID: nil, production: false))
        }

        guard payload.scope != .once else {
            // **Exactly what a native Allow once produces.** No grant, no stored
            // authority, one invocation proceeds. The burned id is what makes it
            // once rather than once-per-fetch.
            return (.allowedOnce(decisionID: payload.decisionId), record(.allow, grantID: nil, production: false))
        }

        do {
            let grant = try RemoteGrantCommit.commit(decision, offer: offer, now: now, in: &state, signer: signer)
            return (.grantedPendingArm(grantID: grant.id), record(.allow, grantID: grant.id, production: grant.includesProduction))
        } catch let refusal as RemoteGrantCommit.Refusal {
            return (.refused(RemoteRefusal(check: "11", reason: refusal.reason)), nil)
        } catch {
            // `prepare` and `coveringDigest` throw `policyDenied` on a covered
            // record that has changed or gone. That throw **is** the record-state
            // denial, and it reaches the phone as `request_changed` rather than
            // as tampering copy.
            return (.refused(RemoteRefusal(check: "11", reason: .requestChanged)), nil)
        }
    }

    /// **A17 — the first decision wins.** A local answer taken while a remote
    /// one is in flight burns the remote `decisionId` so the fetch that arrives
    /// a moment later cannot apply it, and the pending is cancelled with
    /// `decided_locally`.
    ///
    /// Burning an id the Mac has not verified is safe and is the point: the
    /// cache is single-use storage, not an authorization input, and the only
    /// thing burning does is ensure at-most-once.
    @discardableResult
    public static func burnForLocalDecision(_ decisionID: String, now: Date, in state: inout VaultageMetadata) -> Bool {
        RemoteDecisionReplayCache.burn(decisionID, now: now, in: &state)
    }
}

// MARK: - §4.7 layer 7 — the arming touch

/// **One `LAContext` per approval** (§2.2, appendix §4; PF-9).
///
/// The platform-facts spike established PF-9 positively: one evaluated
/// `LAContext` serves **N** operations and a **second key**. That is a fact
/// about the OS, and it is the reason the rule has to be a **code discipline**
/// rather than something the OS enforces — on the phone, one evaluation covers
/// exactly the `apv` decision signature and the `sigw` proof of that one POST,
/// and nothing stops it covering more except the code choosing not to.
///
/// The Mac's half of the same discipline is here. The arming touch is one
/// evaluation, bound to one grant, with **reuse duration 0**, invalidated
/// immediately after, and it authorizes exactly the arming — never a Keychain
/// read taken in the same breath.
public struct RemoteArmingCeremony: Sendable {
    /// What the prompt says. The reason string **names the act**, per §2.2: the
    /// owner must be able to tell an arming touch from a credential read, since
    /// they look identical at the sensor.
    public static func reason(for disclosure: GrantDisclosure, decidingDeviceName: String) -> String {
        "Start the approval you made on \(decidingDeviceName): \(disclosure.scopeLabel), \(disclosure.durationLabel)."
    }

    /// The two things one arming evaluation may cover, named so the list can be
    /// asserted. **It is a closed set of two**, and the assertion that it has
    /// not grown is the whole of what "a code discipline, not an OS control"
    /// can be checked by.
    public enum CoveredOperation: String, CaseIterable, Sendable {
        /// The phone's `apv` signature over the decision (§4.1).
        case decisionSignature = "apv"
        /// The phone's `sigw` DPoP proof of the one POST that carries it (§6.2).
        case decisionPost = "sigw"
    }

    public static let coveredByOneApproval = Set(CoveredOperation.allCases)

    /// §2.2's reuse rule, as a number, so nothing re-derives it.
    public static let reuseDurationSeconds: TimeInterval = 0

    /// Whether an `OwnerAuthentication` may be used to arm this grant.
    ///
    /// **Bound to the grant, and inside its window.** An unbound authentication
    /// — the one a reveal takes — is explicitly not enough: arming is a distinct
    /// act with its own disclosure, and reusing an unrelated touch for it is the
    /// thing PF-9 makes possible and this rule forbids.
    public static func authenticationPermitsArming(_ authentication: OwnerAuthentication?, grantID: UUID, now: Date) -> Bool {
        guard let authentication else { return false }
        return authentication.isValid(for: armingAccount(grantID), at: now)
    }

    /// The synthetic account name an arming evaluation is bound to. It is not a
    /// Keychain account and never reaches `SecItem*`: it exists so
    /// `OwnerAuthentication`'s existing binding check can express "this touch
    /// was for arming *this* grant".
    public static func armingAccount(_ grantID: UUID) -> String {
        "vaultage.arm.\(grantID.uuidString.lowercased())"
    }

    /// Arms, if and only if the owner just proved presence for **this** grant.
    ///
    /// The presence probe is consulted first for the same reason §5.6 does:
    /// there is no point raising a prompt that cannot appear, and
    /// `presence_unavailable` is a better answer than a silent failure.
    public static func arm(
        grantID: UUID,
        authentication: OwnerAuthentication?,
        presence: RemotePresence,
        now: Date,
        in state: inout VaultageMetadata,
        signer: any GrantSigning
    ) throws -> Grant {
        guard presence.canPromptForPresence else {
            throw VaultageError.approvalDenied
        }
        guard authenticationPermitsArming(authentication, grantID: grantID, now: now) else {
            throw VaultageError.approvalDenied
        }
        defer { authentication?.invalidate() }
        return try GrantPolicy.arm(grantID, now: now, in: &state, signer: signer)
    }
}

// MARK: - The projections the XPC boundary carries (contract version 9)

/// One paired phone, as the Devices screen renders it.
///
/// **No thumbprint crosses.** §2.4's control is that the pin lives on the
/// custody side and is consulted there; an app-side copy could only be used to
/// display a hex string, and a hex string the app could display is one a
/// compromised app could compare against and lie about. The name is the pin
/// record's, never the roster's (§4.8).
public struct RemotePairedDevice: Codable, Sendable, Equatable {
    public let phoneDeviceID: String
    public let deviceName: String
    public let pairedAt: Date
    public let pinGeneration: Int
    /// Grants this device created that are alive, and how many of them are
    /// still waiting for the arming touch.
    public let liveGrantCount: Int
    public let pendingArmCount: Int

    public init(phoneDeviceID: String, deviceName: String, pairedAt: Date, pinGeneration: Int, liveGrantCount: Int, pendingArmCount: Int) {
        self.phoneDeviceID = phoneDeviceID
        self.deviceName = deviceName
        self.pairedAt = pairedAt
        self.pinGeneration = pinGeneration
        self.liveGrantCount = liveGrantCount
        self.pendingArmCount = pendingArmCount
    }
}

/// What applying a verified remote decision did.
///
/// **A refusal crosses as a check number and a reason code**, never as the
/// decision that was refused: §3's local-only reasons say something about local
/// state, and the app renders an owner sentence from the code rather than being
/// handed one composed around the input. `wireCancelReason` is what the broker
/// posted to the relay, if anything, and is here so Activity can say what the
/// phone was told.
public struct RemoteDecisionOutcomeProjection: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case allowedOnce, grantedPendingArm, denied, refused, noDecisionYet
    }

    public let kind: Kind
    public let grantID: UUID?
    /// The appendix's own label — `"2"`, `"8a"`, `"9b"` — so a receipt and a bug
    /// report name the same step.
    public let refusedAtCheck: String?
    public let refusalReason: String?
    public let wireCancelReason: String?
    public let decidingDeviceID: String?
    public let decidingDeviceName: String?
    public let coveredProduction: Bool

    public init(kind: Kind, grantID: UUID? = nil, refusedAtCheck: String? = nil, refusalReason: String? = nil, wireCancelReason: String? = nil, decidingDeviceID: String? = nil, decidingDeviceName: String? = nil, coveredProduction: Bool = false) {
        self.kind = kind
        self.grantID = grantID
        self.refusedAtCheck = refusedAtCheck
        self.refusalReason = refusalReason
        self.wireCancelReason = wireCancelReason
        self.decidingDeviceID = decidingDeviceID
        self.decidingDeviceName = decidingDeviceName
        self.coveredProduction = coveredProduction
    }

    /// A refusal, projected. **The decision body does not cross** — only the
    /// check number and the reason code, so the app renders an owner sentence
    /// from the code rather than being handed one composed around the input.
    public init(refusal: RemoteRefusal) {
        self.init(
            kind: .refused,
            refusedAtCheck: refusal.check,
            refusalReason: refusal.reason.rawValue,
            wireCancelReason: refusal.wireCancelReason?.rawValue
        )
    }

    /// What applying produced, joined to what was recorded about it.
    public init(_ application: RemoteApplication, record: RemoteDecisionRecord?) {
        switch application {
        case .allowedOnce:
            self.init(kind: .allowedOnce, decidingDeviceID: record?.decidingDeviceID, decidingDeviceName: record?.decidingDeviceName)
        case let .grantedPendingArm(grantID):
            self.init(kind: .grantedPendingArm, grantID: grantID, decidingDeviceID: record?.decidingDeviceID, decidingDeviceName: record?.decidingDeviceName, coveredProduction: record?.coveredProduction ?? false)
        case .denied:
            self.init(kind: .denied, decidingDeviceID: record?.decidingDeviceID, decidingDeviceName: record?.decidingDeviceName)
        case let .refused(refusal):
            self.init(refusal: refusal)
        }
    }
}

/// The arming prompt's content: the **full** `GrantDisclosure` (Q16), the
/// deciding device's name, and the reason string the prompt must carry.
public struct RemoteArmingDisclosureProjection: Codable, Sendable, Equatable {
    public let grantID: UUID
    public let scopeLabel: String
    public let durationLabel: String
    public let expiresAt: Date
    public let environmentLabels: [String]
    public let operationLabels: [String]
    public let mutationLabels: [String]
    public let includesProduction: Bool
    public let productionEnvironmentLabels: [String]
    public let decidingDeviceName: String
    public let promptReason: String
    /// The default button is **"Not now"** (Q16). Carried rather than assumed,
    /// so the app cannot quietly make the affirmative the default.
    public let defaultsToDecline: Bool

    public init(grantID: UUID, scopeLabel: String, durationLabel: String, expiresAt: Date, environmentLabels: [String], operationLabels: [String], mutationLabels: [String], includesProduction: Bool, productionEnvironmentLabels: [String], decidingDeviceName: String, promptReason: String, defaultsToDecline: Bool = true) {
        self.grantID = grantID
        self.scopeLabel = scopeLabel
        self.durationLabel = durationLabel
        self.expiresAt = expiresAt
        self.environmentLabels = environmentLabels
        self.operationLabels = operationLabels
        self.mutationLabels = mutationLabels
        self.includesProduction = includesProduction
        self.productionEnvironmentLabels = productionEnvironmentLabels
        self.decidingDeviceName = decidingDeviceName
        self.promptReason = promptReason
        self.defaultsToDecline = defaultsToDecline
    }

    public init(grantID: UUID, disclosure: GrantDisclosure, decidingDeviceName: String) {
        self.init(
            grantID: grantID,
            scopeLabel: disclosure.scopeLabel,
            durationLabel: disclosure.durationLabel,
            expiresAt: disclosure.expiresAt,
            environmentLabels: disclosure.environmentLabels,
            operationLabels: disclosure.operationLabels,
            mutationLabels: disclosure.mutationLabels,
            includesProduction: disclosure.includesProduction,
            productionEnvironmentLabels: disclosure.productionEnvironmentLabels,
            decidingDeviceName: decidingDeviceName,
            promptReason: RemoteArmingCeremony.reason(for: disclosure, decidingDeviceName: decidingDeviceName)
        )
    }
}
