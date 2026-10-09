import Foundation

/// BL-099 slice 3 step (a) — **the broker's publication path, and the consent
/// gate it reads from metadata** (§3.7, DB-H7 item 3; D38).
///
/// Slice 1 built publication as pure functions and slice 2 built the switch as a
/// core type with a gate and no store; the schema-22 pass gave it a home in
/// `VaultageMetadata`. What was missing, and is here, is the one caller that
/// joins them: **the broker reads `state.remoteMirroringSetting` from the same
/// `MetadataStore` it already holds, and nothing publishes until that value says
/// it may.**
///
/// **Never `UserDefaults`.** The app had a `RemoteMirroringStore` backed by
/// `UserDefaults.standard`, which is a second copy of an authorization-shaped
/// fact living outside the metadata lock, outside the schema gate, and readable
/// and writable by anything running as the owner. The broker is the process that
/// publishes, so the broker reads the stored value itself rather than being told
/// a position by the app — a switch the UI could assert would be a switch the UI
/// could get wrong, and "nothing was sent while it was off" is a claim this
/// product makes to owners.
///
/// **The gate is a precondition, not a default** (§3.7). A setting with no
/// current acknowledgement refuses publication outright, with its own reason
/// code, *before* the position is read at all — so "the owner never agreed" and
/// "the owner turned it off" are two different facts in the receipt, and the
/// second cannot be mistaken for the first.

extension RemoteMirrorEligibility {
    /// §3.7's whole publication gate, in order: **consent, then position, then
    /// presence, then the open-pending ceilings** — plus the one thing that is
    /// neither, a Mac with no paired phone to seal to.
    ///
    /// The order is the property. `RemoteMirroringSetting.effectivePosition`
    /// already fail-closes to `.off` with no current acknowledgement, and that
    /// is deliberately *not* what reports the refusal here: collapsing the two
    /// into `mirroring_off` would tell an owner reading a receipt that they had
    /// turned something off that they were never offered. Both remain true at
    /// once, which is the belt and the braces — the gate below names the fact,
    /// and the type underneath it makes the unsafe state unreachable even if
    /// this function were deleted.
    /// **The fourth clause is §3.7's ceilings** (BM-M3): *"The Mac does not
    /// publish when: … more than **8** pendings are open for the account or
    /// **4** for this agent client."* `RemoteOpenPendingLimits` had both numbers
    /// and `RemotePublicationContracts` asserted them, and nothing consulted
    /// either — `openPendingCount()` was used only as a digested field and a
    /// routing hint, correctly labelled "never an authorization input". It still
    /// is not an authorization input: this is a **publication** gate, in the
    /// same list as the owner's switch and their presence, and it refuses
    /// publishing rather than deciding anything.
    ///
    /// It is last because it is the clause an owner can do least about, and
    /// because reporting "you have eight requests waiting" to a Mac whose owner
    /// never consented would name the wrong fact.
    public static func publicationRefusal(
        setting: RemoteMirroringSetting,
        presence: RemotePresence,
        pairedPhoneCount: Int,
        openPendingCount: Int,
        agentClientPendingCount: Int
    ) -> Refusal? {
        if setting.needsConsentScreen { return .consentNotGiven }
        if let refusal = positionRefusal(setting.effectivePosition, presence: presence) { return refusal }
        if pairedPhoneCount == 0 { return .noPairedPhone }
        if openPendingCount >= RemoteOpenPendingLimits.perAccount { return .tooManyOpenPendings }
        if agentClientPendingCount >= RemoteOpenPendingLimits.perAgentClient { return .tooManyOpenPendings }
        return nil
    }

    /// The same gate for the **connect** path, plus §3.7's third number.
    ///
    /// §3.7 lists three ceilings in one clause — *"more than **8** pendings are
    /// open for the account, **4** for this agent client, or **2** open connect
    /// requests for the account"* — and BM-M3 closed two of the three.
    /// `connectRequestsPerAccount` was left because it needs a count of open
    /// **connect requests** specifically and no seam on this side reported one;
    /// `RemoteApprovalCoordinating.openConnectRequestCount()` is that seam.
    ///
    /// **Whose gate it is: the Mac's, and this is the Mac's half.** §3.7 settles
    /// it in the same paragraph BM-M3 was written from: the Worker enforces the
    /// same three numbers as `409 too_many_pending` on the publish route, which
    /// bounds what is *stored*; the Mac enforces them **before it composes and
    /// publishes**, which bounds how often a phone is alerted, *"and the Mac's
    /// check is not optional just because the Worker has one, because the Mac is
    /// the publisher"*. So the count is the Mac's own, over the connect requests
    /// this Mac opened and has not seen finish — not a number fetched from
    /// `GET /api/connect-requests` and believed. A conformer may populate it
    /// from that route, but what it is counting is still this Mac's own record:
    /// a relay that under-reports can only let a third connect request through,
    /// which is the direction the Worker's own ceiling closes.
    ///
    /// **Last, like the other two ceilings**, so an unconsented Mac over the
    /// connect ceiling still reports the consent — the fact that matters.
    public static func connectRequestRefusal(
        setting: RemoteMirroringSetting,
        presence: RemotePresence,
        pairedPhoneCount: Int,
        openPendingCount: Int,
        agentClientPendingCount: Int,
        openConnectRequestCount: Int
    ) -> Refusal? {
        if let refusal = publicationRefusal(
            setting: setting, presence: presence, pairedPhoneCount: pairedPhoneCount,
            openPendingCount: openPendingCount, agentClientPendingCount: agentClientPendingCount
        ) { return refusal }
        if openConnectRequestCount >= RemoteOpenPendingLimits.connectRequestsPerAccount {
            return .tooManyOpenConnectRequests
        }
        return nil
    }
}

extension VaultageBroker {
    /// Publishes one pending to every paired phone, or says why it did not.
    ///
    /// **Nothing here can make a local approval wait** (§3.7). The caller runs
    /// this in a detached task at the moment the native sheet appears; every
    /// outcome below — including every failure — is a value, never a throw, so
    /// a broker that cannot publish is a broker whose sheet is unaffected.
    ///
    /// **§3.6's mirrorable set is the caller's gate, not this one's.** That
    /// predicate needs an `Operation`, which `RemotePublicationRequest` has
    /// already flattened to its raw value; `RemoteMirrorEligibility.actionRefusal`
    /// is asserted in `RemotePublicationContracts` and is applied where the
    /// request is resolved, before a summary is composed at all. This function
    /// is the §3.7 half: the owner's switch, their consent, and where they are.
    public func publishRemoteApproval(
        _ request: RemotePublicationRequest,
        conversationRemaining: Int? = nil
    ) async -> RemotePublishOutcome {
        guard let coordinator = remoteApprovals else {
            return .notMirrored(.mirroringOff)
        }
        guard let state = try? await metadata.load() else {
            return .transportUnavailable("This Mac's metadata could not be read, so nothing was published.")
        }

        // **The consent gate, read from metadata.** Not from `UserDefaults`,
        // not from an argument, not from the app: from the same locked document
        // the schema gate protects and a reinstall preserves.
        let setting = state.remoteMirroringSetting
        let presence = coordinator.presence()
        let recipients = state.devicePairings
        let openPendingCount = await coordinator.openPendingCount()
        if let refusal = RemoteMirrorEligibility.publicationRefusal(
            setting: setting,
            presence: presence,
            pairedPhoneCount: recipients.count,
            openPendingCount: openPendingCount,
            agentClientPendingCount: await coordinator.openPendingCount(forAgentClientID: request.agentClientID)
        ) {
            return .notMirrored(refusal)
        }

        let issuedAt = Int(now().timeIntervalSince1970)
        let expiresAt = issuedAt + RemotePendingTTL.seconds(
            for: request.summaryClass,
            conversationRemaining: conversationRemaining
        )
        let publication: RemotePublication
        do {
            publication = try RemoteSummaryComposer.compose(
                request,
                to: recipients,
                presence: presence,
                openPendingCount: openPendingCount,
                issuedAt: issuedAt,
                expiresAt: expiresAt
            )
        } catch {
            // A composition that fails validation is a refusal of the whole
            // publication (§3.1) — there is no silent scrub and no partial
            // publish. The sheet is unaffected either way.
            return .transportUnavailable(Self.sentence(for: error))
        }

        var sealed: [RemoteSealedSummary] = []
        var retained = RemoteRetainedFieldLists()
        for recipient in publication.perRecipient {
            do { sealed.append(try RemoteSummarySealing.seal(recipient)) }
            catch { return .sealingUnavailable(Self.sentence(for: error)) }
            retained.record(recipient.retainedVersion, for: recipient.recipient.phoneDeviceID)
        }

        let record = RemotePendingPublication(
            pendingID: request.pendingID,
            summaryClass: request.summaryClass,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            recipients: publication.perRecipient.map(\.recipient.phoneDeviceID),
            retained: retained
        )
        do {
            // **One call, deliberately.** A publication that reached the relay
            // and was not retained locally cannot be verified at check 9a; one
            // retained and never published is a pending the phone never sees.
            try await coordinator.publish(
                RemotePublicationEnvelope(pendingId: request.pendingID, header: publication.header, sealed: sealed),
                recording: record
            )
        } catch {
            return .transportUnavailable(Self.sentence(for: error))
        }
        return .published
    }

    /// What this Mac's stored switch says right now, for the Devices screen and
    /// for the receipt trail. Read-only, and read from metadata.
    public func remoteMirroringSetting() async throws -> RemoteMirroringSetting {
        try await metadata.load().remoteMirroringSetting
    }

    /// The two ways the setting changes (§3.7), both through the metadata lock.
    ///
    /// Acknowledging lands on *When I'm away*, never on *Always*: the consent
    /// screen is where a statement is read, not where a position is chosen.
    ///
    /// **Behind the owner** (BM-M6). §3.7 makes the consent moment a
    /// precondition — *"the position defaults to When I'm away only after the
    /// owner acknowledges a one-screen statement"* — and this file argues at
    /// length that the broker must read the stored value itself because "a
    /// switch the UI could assert would be a switch the UI could get wrong". It
    /// then accepted the UI's bare assertion that the owner had read the
    /// statement: a client that passes BL-061's code-signing admission could
    /// call this and then `moveRemoteMirroring(.always)` and turn on mirroring
    /// the owner never agreed to. The five paragraphs are in the core
    /// (`RemoteMirroringConsent.consentBody`); whether they were **shown** was
    /// not, and a presence proof is the only thing on this side that can say so.
    /// The reason string names the act, per §2.2, so an acknowledgement touch is
    /// distinguishable from a credential read at the sensor.
    ///
    /// The device id is validated here too, as `unpairDevice`,
    /// `applyRemoteDecision`, `armRemoteGrant` and `moveRemoteMirroring` already
    /// validate their one input.
    @discardableResult
    public func acknowledgeRemoteMirroringConsent(phoneDeviceID: String) async throws -> RemoteMirroringSetting {
        guard UUID(uuidString: phoneDeviceID) != nil else {
            throw VaultageError.invalidInput("A mirroring acknowledgement names the paired phone it was read beside.")
        }
        let authentication = try await authenticator.authenticateOwner(
            reason: RemoteMirroringConsent.authenticationReason,
            unlocking: []
        )
        defer { authentication.invalidate() }
        let at = now()
        let updated = try await metadata.updateResult { state -> RemoteMirroringSetting in
            state.remoteMirroringSetting = state.remoteMirroringSetting.acknowledged(at: at, phoneDeviceID: phoneDeviceID)
            return state.remoteMirroringSetting
        }
        try? await audit.append(AuditEvent(
            operation: "remote.mirroring.consent",
            decision: .approved,
            result: "The owner acknowledged what is published to Vaultage's servers and to Apple, and \"\(RemoteMirroringConsent.switchTitle)\" is now \(RemoteMirroringConsent.label(for: updated.effectivePosition).title)."
        ))
        return updated
    }

    @discardableResult
    public func moveRemoteMirroring(to position: RemoteMirrorEligibility.Position) async throws -> RemoteMirroringSetting {
        let updated = try await metadata.updateResult { state -> RemoteMirroringSetting in
            state.remoteMirroringSetting = state.remoteMirroringSetting.movedTo(position)
            return state.remoteMirroringSetting
        }
        try? await audit.append(AuditEvent(
            operation: "remote.mirroring.position",
            decision: .approved,
            result: "\"\(RemoteMirroringConsent.switchTitle)\" is now \(RemoteMirroringConsent.label(for: updated.effectivePosition).title)."
        ))
        return updated
    }

    /// Errors become sentences here rather than at the call site, so a
    /// publication outcome never carries a raw `Error` description an agent
    /// could read as an instruction.
    ///
    /// **Through `Redactor.safeError`** (BM-M10). This was the only path on the
    /// new surface that returned an error's own description verbatim, and it
    /// becomes `RemotePublishOutcome.transportUnavailable(_)` and
    /// `RemoteConnectRequestOutcome.unavailable(_)` — the second of which is
    /// designed to reach the provisioning conversation, that is, an agent. Most
    /// messages on the path are fixed literals; the redaction is what makes that
    /// a property rather than an audit of the current set.
    static func sentence(for error: any Error) -> String {
        if let vaultage = error as? VaultageError { return Redactor.safeError(vaultage.localizedDescription) }
        return "This Mac could not publish the request."
    }
}

// MARK: - §5.1 and §5.3a — asking a phone to connect a provider

extension VaultageBroker {
    /// Wires §6.2's connect routes. `nil` — the default — is a Mac that can
    /// only be connected at its own keyboard.
    public func configureRemoteConnect(_ transport: (any RemoteConnectTransport)?) {
        remoteConnect = transport
    }

    /// What a connect attempt did, in the two words the provisioning
    /// conversation needs: is a request open on a phone, and if not, why not.
    public enum RemoteConnectRequestOutcome: Equatable, Sendable {
        /// A sealed `class: connect` summary is on the relay and the phone has
        /// been rung. The agent is told the request is waiting for the owner on
        /// their Mac **or** their phone.
        case waiting(connectRequestID: String, phoneDeviceID: String, phoneName: String)
        /// §3.6/§3.7 said this Mac does not ask phones. The agent is told the
        /// ordinary "connect it on your Mac" next step.
        case notMirrored(RemoteMirrorEligibility.Refusal)
        /// This build has no compiled connect contract for the provider, or the
        /// relay refused. Either way the Mac path is unaffected.
        case unavailable(String)
    }

    /// §5.1 step 2: *no verified connection for this provider*, and this Mac has
    /// a phone that can be asked.
    ///
    /// **This never creates a connection and never authorizes anything.** It
    /// publishes one sealed summary describing what the owner would be asked
    /// for, and the credential that may come back is validated against the
    /// **compiled** contract at §5.6 step 4 — not against anything this call
    /// sent. A failure here is always "the Mac path is what is left", never a
    /// blocked provisioning conversation.
    public func requestRemoteConnect(
        provider: Provider,
        connectionLabel: String,
        projectName: String,
        environmentName: String,
        sensitivity: EnvironmentSensitivity,
        isProduction: Bool,
        agentLabel: String?,
        agentClientID: String?
    ) async -> RemoteConnectRequestOutcome {
        guard let coordinator = remoteApprovals, let transport = remoteConnect else {
            return .notMirrored(.mirroringOff)
        }
        guard let state = try? await metadata.load() else {
            return .unavailable("This Mac's metadata could not be read.")
        }
        let presence = coordinator.presence()
        // A connect pending is an open pending for the account, so §3.7's
        // ceilings bite here too (BM-M3) — and **all three** of them now. The
        // third, `connectRequestsPerAccount`, is 2, and it is read from a seam
        // of its own rather than approximated by the account-wide number. It is
        // enforced **before composing**, which is where §3.7 puts it: the Mac is
        // the publisher, and a ceiling applied after the summary is sealed would
        // bound what is stored rather than how often a phone is alerted.
        if let refusal = RemoteMirrorEligibility.connectRequestRefusal(
            setting: state.remoteMirroringSetting,
            presence: presence,
            pairedPhoneCount: state.devicePairings.count,
            openPendingCount: await coordinator.openPendingCount(),
            agentClientPendingCount: await coordinator.openPendingCount(forAgentClientID: agentClientID),
            openConnectRequestCount: await coordinator.openConnectRequestCount()
        ) {
            return .notMirrored(refusal)
        }
        guard let identity = await coordinator.deviceIdentity() else {
            return .unavailable("This Mac has no device session, so it cannot open a connect request.")
        }
        // The Mac's own pinned `kex` thumbprint, from the key roles — never from
        // a roster and never from a request (§5.2, DB-C2).
        guard let macKexThumbprint = MacDeviceKeyRoles.kexKey().thumbprint else {
            return .unavailable(MacDeviceKeyRoles.unsignedSkipReason)
        }

        let composition: RemoteConnectRequestComposition
        do {
            composition = try RemoteConnectRequestComposer.compose(
                connectRequestID: RemoteConnectRequestComposer.freshConnectRequestID(),
                provider: provider.rawValue,
                connectionLabel: connectionLabel,
                projectName: projectName,
                environmentName: environmentName,
                sensitivity: sensitivity,
                isProduction: isProduction,
                agentState: agentClientID == nil ? "unenrolled" : "enrolled",
                agentLabel: agentClientID == nil ? nil : agentLabel,
                agentClientID: agentClientID,
                accountSubject: identity.accountSubject,
                macDeviceID: identity.macDeviceID,
                macKexThumbprint: macKexThumbprint,
                recipients: state.devicePairings,
                presence: presence,
                openPendingCount: await coordinator.openPendingCount(),
                issuedAt: Int(now().timeIntervalSince1970)
            )
        } catch {
            return .unavailable(Self.sentence(for: error))
        }

        do {
            let echoed = try await transport.createConnectRequest(composition.creation)
            guard echoed == composition.connectRequestID else {
                return .unavailable("The control plane answered with a different connect request id than the one this Mac sealed into the summary.")
            }
        } catch {
            return .unavailable(Self.sentence(for: error))
        }
        try? await audit.append(AuditEvent(
            operation: "remote.connect.requested",
            decision: .approved,
            result: "Asked \(composition.recipient.deviceName) to connect \(provider.title). \(composition.permissionWording)",
            decidingDeviceID: composition.recipient.phoneDeviceID,
            decidingDeviceName: composition.recipient.deviceName
        ))
        return .waiting(
            connectRequestID: composition.connectRequestID,
            phoneDeviceID: composition.recipient.phoneDeviceID,
            phoneName: composition.recipient.deviceName
        )
    }
}
