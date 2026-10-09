import Foundation

/// BL-099 slice 2 step (d) — **the broker's half of the remote-approval
/// surface** (§12 item 21): pin management, remote-decision application and the
/// arming touch.
///
/// **Why these live in the broker and not in the app.** The twelve §4.3 checks
/// run against the pin records and the retained field lists, which are custody
/// state; the arming touch is an OS authentication; and the grant it arms holds
/// the secret cache. Every one of those is on this side of the XPC boundary
/// already, and putting any part of the verification on the other side would
/// make the app a participant in an authorization decision it is explicitly not
/// trusted with. So what crosses inbound is a **pending id**, and what crosses
/// back is what happened — never a signature, never a thumbprint, never the
/// decision body.

/// The network half, injected so the broker's rules are testable without a
/// Worker and so the product can hand it a `DeviceAccountClient`.
public protocol RemoteApprovalCoordinating: Sendable {
    /// Fetches the stored decision for one pending. `nil` while it is still
    /// open (`204`).
    func fetchDecision(pendingID: String) async throws -> RemoteSignedDecision?
    /// The offer that pending published, as check 7 needs it, alongside the
    /// coverage offer §3.3.1.1 re-resolves at commit.
    func pending(_ pendingID: String) async -> (RemotePendingPublication, RemoteDecisionOffer, RemoteOfferedCoverage.Offer)?
    /// The roster cache check 4 reads. **A refresh failure is not a refusal**,
    /// so this returns what is cached rather than fetching.
    func rosterCache() async -> RemoteRosterCache?
    /// §3.2 / §6.2 — `POST /api/approvals`, **and** the Mac's own record of the
    /// open pending with its per-recipient retained field lists.
    ///
    /// One call rather than two, deliberately (BL-099 slice 3 step (a)): a
    /// publication that reached the relay and was not retained locally cannot be
    /// verified at check 9a, and one retained but never published is a pending
    /// the phone will never see. A conformer that can do only one of the two
    /// must throw rather than do half.
    func publish(_ envelope: RemotePublicationEnvelope, recording pending: RemotePendingPublication) async throws

    /// §6.3's per-account open-pending count, as the Mac last observed it.
    /// A publish-time snapshot digested into the summary (§3.3) and a routing
    /// hint in the header — **never an authorization input** — and, since
    /// BM-M3, §3.7's own publication ceiling, which is a different kind of use:
    /// it decides whether to *publish*, never whether to *authorize*.
    func openPendingCount() async -> Int

    /// §3.7's second ceiling: how many pendings are open for **this agent
    /// client**. Four, against the account's eight.
    ///
    /// The default answers the account-wide count, which is the fail-closed
    /// direction — it can only make the per-client ceiling bite sooner, never
    /// later — so a conformer that cannot distinguish clients refuses too much
    /// rather than too little. A conformer that can should override it.
    func openPendingCount(forAgentClientID clientID: String?) async -> Int

    /// §3.7's **third** ceiling: how many **connect requests** are open for the
    /// account. Two, against the account's eight pendings.
    ///
    /// It is a separate seam and not a filter over `openPendingCount()` because
    /// §3.7's clause counts a different thing: a connect request is an open
    /// pending *and* it is one of at most two connect requests, and BM-M3
    /// deliberately left this number unimplemented rather than approximate it
    /// by the account-wide count.
    ///
    /// **The default is the account-wide pending count**, which is an upper
    /// bound — every open connect request is an open pending — so a conformer
    /// that cannot distinguish them refuses too much rather than too little. It
    /// is aggressive on purpose: at a ceiling of 2 against 8, the default makes
    /// a Mac with two ordinary pendings refuse a connect, which is a bad
    /// product behaviour and a safe one. **The wiring slice must override it**;
    /// this default exists so that not overriding it is visible as a refusal
    /// rather than invisible as an unbounded publisher.
    func openConnectRequestCount() async -> Int

    /// §3.8 — posted immediately on verification, before applying.
    func cancel(pendingID: String, reason: RemoteCancelReason) async
    /// §3.7.1.
    func presence() -> RemotePresence
    /// This Mac's device id and the account subject, as the device session
    /// knows them. They are **not** in `VaultageMetadata` — the device identity
    /// belongs to `AccountClient` — and P4, P6 and P7 all carry them, so the
    /// coordinator is where they come from rather than a fifth copy.
    func deviceIdentity() async -> (macDeviceID: String, accountSubject: String)?
}

extension RemoteApprovalCoordinating {
    public func openPendingCount(forAgentClientID clientID: String?) async -> Int {
        await openPendingCount()
    }

    public func openConnectRequestCount() async -> Int {
        await openPendingCount()
    }
}

extension VaultageBroker {
    /// Wires the remote-approval surface. `nil` — the default — is a broker
    /// with no remote approvals at all, which is what every existing test and
    /// every unpaired Mac is.
    public func configureRemoteApprovals(_ coordinator: (any RemoteApprovalCoordinating)?) {
        remoteApprovals = coordinator
    }

    // MARK: Pin management

    /// The paired phones, with what each one is currently responsible for.
    ///
    /// The counts are what make the Devices screen honest about unpairing:
    /// §4.6's kill switch is durable and irreversible, so the owner is entitled
    /// to know how many live grants they are about to end.
    public func listPairedDevices() async throws -> [RemotePairedDevice] {
        let state = try await metadata.load()
        let now = self.now()
        return state.devicePairings
            .sorted { $0.pairedAt < $1.pairedAt }
            .map { pin in
                let grants = state.grants.filter { $0.decidingDeviceID == pin.phoneDeviceID && $0.deviceKillSwitch == nil && $0.revokedAt == nil && $0.expiresAt > now && grantSigner.verifies($0) }
                return RemotePairedDevice(
                    phoneDeviceID: pin.phoneDeviceID,
                    // BM-H4: Class B-validated, or the id. The Devices screen is
                    // §2.3 item (c) and the roster is served by the party this
                    // design treats as hostile.
                    deviceName: RemoteDevicePairingPolicy.renderableDeviceName(pin, fallback: pin.phoneDeviceID),
                    pairedAt: pin.pairedAt,
                    pinGeneration: pin.pinGeneration,
                    liveGrantCount: grants.count,
                    pendingArmCount: grants.filter { $0.armedAt == nil }.count
                )
            }
    }

    /// Unpair. **Stamps §4.6's durable kill switch** on every grant that device
    /// created, so re-pairing the same phone does not bring the grants back
    /// (Q17, DB-M18): the stamp is durable and survives a second ceremony, which
    /// is precisely why it exists rather than a digest-only denial.
    ///
    /// **An unpair is not a revocation, and does not write the never-cleared
    /// sets** (§2.4 rule 3, §2.6 rule 5). Those two sets are §2.6's, written at
    /// the moment a device-signed revocation *verifies*, and §2.4 rule 6 reads
    /// them to make a revocation irreversible. Writing them here made an
    /// ordinary unpair terminal — permanently barring that handset from pairing
    /// with this Mac again, under a fresh device id too, because the five
    /// thumbprints were recorded — while the sheet the owner clicks says *"it
    /// will have to be paired from the beginning"* and the Devices row renders
    /// *"re-paired (generation N)"*, a state the write made unreachable. The
    /// most likely reason anyone touches that button is to troubleshoot.
    /// `RemoteDevicePairingPolicy.unpair`'s own contract said so three files up
    /// the call stack; this is now the same statement in both places.
    @discardableResult
    public func unpairDevice(_ phoneDeviceID: String) async throws -> [UUID] {
        let now = self.now()
        let (stamped, generation) = try await metadata.updateResult { state -> ([UUID], Int) in
            guard state.devicePairings.contains(where: { $0.phoneDeviceID == phoneDeviceID }) else {
                throw VaultageError.invalidInput("That device is not paired with this Mac.")
            }
            let killed = GrantPolicy.stampDeviceKillSwitch(forDeviceID: phoneDeviceID, now: now, in: &state, signer: grantSigner)
            state.devicePairings.removeAll { $0.phoneDeviceID == phoneDeviceID }
            // Audit H-08: unpairing is a revocation the anchor counts, whether
            // or not a grant was killed by it.
            state.revocationGeneration += 1
            return (killed, state.revocationGeneration)
        }
        try grantSigner.raiseRevocationWatermark(to: generation)
        // The grants are dead as metadata; their cached secrets die in the same
        // breath, or the window they opened outlives the stamp.
        for id in stamped { await grantCache.invalidate(grantID: id) }
        try? await audit.append(AuditEvent(
            operation: "remote.device.unpair",
            decision: .approved,
            result: stamped.isEmpty
                ? "Unpaired a device. It had no live grants."
                : "Unpaired a device and ended \(stamped.count) grant\(stamped.count == 1 ? "" : "s") it had created."
        ))
        return stamped
    }

    // MARK: Applying a verified remote decision

    /// §4.3 then §4.5: verify, cancel, apply — in that order.
    ///
    /// **The cancel is issued on verification, before applying** (Q11 item 3),
    /// so the gap between the decision write and the cancel is not correlated
    /// with the outcome. A relay timing the two learns that a decision was
    /// verified, which it already knew, and nothing about what it said.
    public func applyRemoteDecision(pendingID: String) async throws -> RemoteDecisionOutcomeProjection {
        // Audit H-08: a rolled-back file has lost revocations and replay
        // tombstones; no remote decision is applied against it.
        let current = try await metadata.load()
        guard grantSigner.isCurrent(current) else {
            throw VaultageError.policyDenied("Local metadata is older than this Mac's last revocation. Restore the current file, or revoke again, before applying a remote decision.")
        }
        guard let coordinator = remoteApprovals else {
            throw VaultageError.invalidInput("Remote approvals are not configured on this Mac.")
        }
        guard let (pending, offer, coverageOffer) = await coordinator.pending(pendingID) else {
            return RemoteDecisionOutcomeProjection(refusal: RemoteRefusal(check: "1", reason: .unknownPending))
        }
        guard let identity = await coordinator.deviceIdentity() else {
            return RemoteDecisionOutcomeProjection(refusal: RemoteRefusal(check: "1", reason: .unknownPending))
        }
        guard let signed = try await coordinator.fetchDecision(pendingID: pendingID) else {
            return RemoteDecisionOutcomeProjection(kind: .noDecisionYet)
        }

        let state = try await metadata.load()
        let now = self.now()
        let outcome = RemoteDecisionVerification.verify(RemoteDecisionVerificationInput(
            signed: signed,
            pending: pending,
            offer: offer,
            macDeviceID: identity.macDeviceID,
            accountSubject: identity.accountSubject,
            roster: await coordinator.rosterCache(),
            now: now
        ), in: state)

        switch outcome {
        case let .refused(refusal):
            if let reason = refusal.wireCancelReason {
                await coordinator.cancel(pendingID: pendingID, reason: reason)
            }
            try? await audit.append(AuditEvent(
                operation: "remote.decision.refused",
                decision: .blocked,
                result: "A remote decision was refused at check \(refusal.check) (\(refusal.reason.rawValue))."
            ))
            return RemoteDecisionOutcomeProjection(refusal: refusal)

        case let .accepted(accepted):
            // Immediately, and before applying.
            await coordinator.cancel(pendingID: pendingID, reason: .decidedRemotely)
            let applied = try await metadata.updateResult { state -> (RemoteApplication, RemoteDecisionRecord?) in
                RemoteDecisionApplication.apply(accepted, pendingID: pendingID, offer: coverageOffer, now: now, in: &state, signer: self.grantSigner)
            }
            if let record = applied.1 {
                try? await audit.append(AuditEvent(
                    operation: "remote.decision.applied",
                    decision: record.verdict == .allow ? .approved : .denied,
                    result: record.activitySentence,
                    decidingDeviceID: record.decidingDeviceID,
                    decidingDeviceName: record.decidingDeviceName
                ))
            }
            return RemoteDecisionOutcomeProjection(applied.0, record: applied.1)
        }
    }

    // MARK: The arming touch

    /// The disclosure the arming prompt must render — composed **here**, so the
    /// app presents what the broker built rather than building its own.
    public func remoteArmingDisclosure(grantID: UUID) async throws -> RemoteArmingDisclosureProjection {
        let state = try await metadata.load()
        guard let grant = state.grants.first(where: { $0.id == grantID }) else {
            throw VaultageError.invalidInput("That grant no longer exists.")
        }
        guard let deviceID = grant.decidingDeviceID else {
            throw VaultageError.invalidInput("That grant was created on this Mac and is already armed.")
        }
        // BM-H4. This name becomes the `localizedReason` of the
        // LocalAuthentication prompt `armRemoteGrant` raises — §4.7 layer 7, the
        // one sentence the owner reads while deciding whether to start a
        // production grant, and the moment PF-9 says one evaluation becomes a
        // capability. It is Class B-validated, or it is the device id.
        let name = RemoteDevicePairingPolicy.renderableDeviceName(for: deviceID, in: state)
        return RemoteArmingDisclosureProjection(
            grantID: grantID,
            disclosure: GrantPolicy.armingDisclosure(for: grant, in: state),
            decidingDeviceName: name
        )
    }

    /// §4.7 layer 7. **One presence evaluation, bound to this grant, reuse
    /// duration 0** — PF-9's discipline, on the Mac's side of it.
    ///
    /// The presence probe runs first for the same reason §5.6's does: raising a
    /// prompt that cannot appear produces a failure the owner cannot read.
    @discardableResult
    public func armRemoteGrant(_ grantID: UUID) async throws -> GrantSummary {
        let state = try await metadata.load()
        guard let grant = state.grants.first(where: { $0.id == grantID }) else {
            throw VaultageError.invalidInput("That grant no longer exists.")
        }
        // BL-136 step 1. A pending record the broker did not write is refused
        // here, before the prompt: the owner's touch must never be the first
        // stamp on a grant. `GrantPolicy.arm` checks again under the lock.
        guard grantSigner.verifies(grant) else {
            throw VaultageError.policyDenied("That grant is not one this Mac recorded, so it cannot be armed.")
        }
        let presence = remoteApprovals?.presence() ?? .active
        guard presence.canPromptForPresence else {
            // The same sentence §5.6's `presence_unavailable` gives, because it
            // is the same fact about the same Mac.
            throw VaultageError.approvalDenied
        }
        let disclosure = try await remoteArmingDisclosure(grantID: grantID)
        let account = RemoteArmingCeremony.armingAccount(grantID)
        // **One evaluation, bound to this grant** (§2.2; PF-9). The account set
        // is the synthetic arming account and nothing else, so the same touch
        // cannot be carried into a Keychain read.
        let authentication = try await authenticator.authenticateOwner(
            reason: disclosure.promptReason,
            unlocking: [account],
            // §2.2 and appendix §4: **reuse duration stays 0** for the arming
            // touch (BM-L2). `RemoteArmingCeremony.reuseDurationSeconds` was a
            // constant nothing applied, and every evaluation took the 60-second
            // Keychain default — PF-9 makes "how long is this instance carried"
            // the whole control.
            reuseDuration: RemoteArmingCeremony.reuseDurationSeconds
        )
        let now = self.now()
        let armed = try await metadata.updateResult { state -> Grant in
            try RemoteArmingCeremony.arm(grantID: grantID, authentication: authentication, presence: presence, now: now, in: &state, signer: self.grantSigner)
        }
        try? await audit.append(AuditEvent(
            operation: "remote.grant.armed",
            decision: .approved,
            result: "Started a grant approved on \(disclosure.decidingDeviceName).",
            decidingDeviceID: grant.decidingDeviceID,
            decidingDeviceName: disclosure.decidingDeviceName
        ))
        let refreshed = try await metadata.load()
        guard let summary = GrantPolicy.summaries(in: refreshed, now: now, verify: grantSigner.verifies).first(where: { $0.id == armed.id }) else {
            throw VaultageError.storage("The armed grant could not be projected.")
        }
        return summary
    }
}
