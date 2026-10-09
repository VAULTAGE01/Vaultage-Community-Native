import CryptoKit
import Foundation

/// BL-099 — the pairing pins and the device-signed revocation list, both of
/// which live in `VaultageMetadata` (§2.4, §2.6).
///
/// **Why the pins live in the metadata store and not in a side store** (§2.4,
/// Q17 item 2). `Grant.coveringDigest` is a pure function of `(scope,
/// environmentIDs, bindings, includesProduction, state: VaultageMetadata)`, and
/// §4.6's device section needs the pinned thumbprint and `pinGeneration` inside
/// that function. Putting the pins in `state` is what keeps `coveringDigest`
/// pure and testable instead of reaching outside itself.
///
/// **The pin is the authority, and it needs no network.** §4.3 step 2 — "is this
/// deciding device locally paired and not revoked" — is the only check that
/// survives a compromised control plane, and it is evaluated **first**, before
/// the roster is consulted at all.

// MARK: - The pin record

/// One paired phone, as §2.4's ceremony writes it.
///
/// **§2.4 lists the pin record as five thumbprints, and a thumbprint cannot
/// verify a signature.** §2.6 rule 1 requires the Mac to honour a revocation
/// "only if it verifies against a key that Mac has **pinned**", and §4.3 step 3
/// requires the verifying `apv` key to come from the pin rather than the wire.
/// Neither is possible from a hash. So the record carries the **public keys**,
/// with the thumbprints kept beside them as the primary key (DB-L13) and as what
/// the six words compare — and every use re-derives the thumbprint from the key
/// and refuses a record that disagrees with itself. Reported as a gap in §2.4's
/// wording rather than resolved silently.
public struct DevicePairingRecord: Codable, Hashable, Sendable, Identifiable {
    /// §3.2's cap: four paired phones, so at most four sealed summaries per
    /// pending.
    public static let maximumPairedPhones = 4

    /// The control-plane device id (`device.ts:334`). Kept for display and for
    /// §4.3 step 2's selection; the **thumbprint is the primary key**, because
    /// the id is a `crypto.randomUUID()` the control plane assigns per enrolment.
    public let phoneDeviceID: String
    public let deviceName: String
    /// X9.63 uncompressed points, `0x04 ‖ X[32] ‖ Y[32]`, one per phone role.
    public let sigPublicKey: Data
    public let sigwPublicKey: Data
    public let apvPublicKey: Data
    public let sumPublicKey: Data
    public let sum2PublicKey: Data
    public let sigThumbprint: String
    public let sigwThumbprint: String
    public let apvThumbprint: String
    public let sumThumbprint: String
    public let sum2Thumbprint: String
    public let pairedAt: Date
    /// Incremented on every ceremony that overwrites an existing pin (§2.4 rule
    /// 6). It is an input to `coveringDigest`'s device section, so grants
    /// created under the old pin die and **do not come back**.
    public let pinGeneration: Int

    public var id: String { phoneDeviceID }

    public init(phoneDeviceID: String, deviceName: String, sigPublicKey: Data, sigwPublicKey: Data, apvPublicKey: Data, sumPublicKey: Data, sum2PublicKey: Data, pairedAt: Date, pinGeneration: Int) {
        self.phoneDeviceID = phoneDeviceID
        self.deviceName = deviceName
        self.sigPublicKey = sigPublicKey
        self.sigwPublicKey = sigwPublicKey
        self.apvPublicKey = apvPublicKey
        self.sumPublicKey = sumPublicKey
        self.sum2PublicKey = sum2PublicKey
        self.sigThumbprint = RemoteDeviceKeyThumbprint.p256(x963Representation: sigPublicKey) ?? ""
        self.sigwThumbprint = RemoteDeviceKeyThumbprint.p256(x963Representation: sigwPublicKey) ?? ""
        self.apvThumbprint = RemoteDeviceKeyThumbprint.p256(x963Representation: apvPublicKey) ?? ""
        self.sumThumbprint = RemoteDeviceKeyThumbprint.p256(x963Representation: sumPublicKey) ?? ""
        self.sum2Thumbprint = RemoteDeviceKeyThumbprint.p256(x963Representation: sum2PublicKey) ?? ""
        self.pairedAt = pairedAt
        self.pinGeneration = pinGeneration
    }

    /// **All five** (§2.6 rule 5; version 7, DB-L31). Version 6 recorded four and
    /// left `sig` out, so a re-enrolling phone carried one pinned identifier
    /// across a revocation.
    public var allThumbprints: [String] { [sigThumbprint, sigwThumbprint, apvThumbprint, sumThumbprint, sum2Thumbprint] }

    /// A decoded record is never trusted to be coherent: every stored thumbprint
    /// must be the RFC 7638 thumbprint of the key stored beside it, every key
    /// must be a well-formed uncompressed point, and **`deviceName` must pass
    /// the same Class B validation `connectionLabel` passes two files away**
    /// (BM-H4).
    ///
    /// The name half is checked here as well as at `pin` so that a
    /// decoded-but-illegal record fails closed at `normalize` — which drops it
    /// — rather than at render, and so that every read through
    /// `RemoteDevicePairingPolicy.pairing(for:)` is already validated.
    public var isWellFormed: Bool {
        guard !phoneDeviceID.isEmpty, UUID(uuidString: phoneDeviceID) != nil, pinGeneration >= 1 else { return false }
        guard (try? RemoteSummaryValidation.validateClassB(deviceName, .deviceName)) != nil else { return false }
        let pairs = [
            (sigPublicKey, sigThumbprint), (sigwPublicKey, sigwThumbprint), (apvPublicKey, apvThumbprint),
            (sumPublicKey, sumThumbprint), (sum2PublicKey, sum2Thumbprint)
        ]
        for (key, thumbprint) in pairs {
            guard let derived = RemoteDeviceKeyThumbprint.p256(x963Representation: key), derived == thumbprint else { return false }
            guard (try? P256.Signing.PublicKey(x963Representation: key)) != nil else { return false }
        }
        return Set(allThumbprints).count == 5
    }

    /// The `apv` key §4.3 step 3 verifies against, resolved from the pin and
    /// never from the wire. Returns `nil` for an incoherent record, which then
    /// matches nothing.
    public var apvVerifyingKey: P256.Signing.PublicKey? {
        guard isWellFormed else { return nil }
        return try? P256.Signing.PublicKey(x963Representation: apvPublicKey)
    }

    /// Which recipient key a summary of this sensitivity seals to (§3.2,
    /// DB-M19): `sum` for an ordinary summary, `sum2` for a sensitive one, so
    /// §2.5's promise is enforced by the ACL rather than by a UI branch.
    public func summaryRecipient(isSensitive: Bool) -> (thumbprint: String, publicKey: Data) {
        isSensitive ? (sum2Thumbprint, sum2PublicKey) : (sumThumbprint, sumPublicKey)
    }
}

// MARK: - The device-signed revocation list

/// One verified DSRL entry. **Written once, never removed by any network
/// input** (§2.6 rule 2): a compromised relay can delay a revocation; it can
/// never reverse one.
public struct DeviceRevocationRecord: Codable, Hashable, Sendable, Identifiable {
    public let accountSubject: String
    public let revokedDeviceID: String
    public let revokedAt: Date
    public let revokingDeviceID: String
    public let serial: Int
    public let reason: RemoteRevocationReason
    /// When this Mac verified it against a pinned `apv` key. The durable stamp
    /// §4.6 writes on the grants this revocation kills is taken at this instant.
    public let verifiedAt: Date
    /// §2.6 rule 5's Touch ID-gated local clearance. Clearing restores *being
    /// served*, never *being re-paired*, and never resets the serial watermark.
    public var clearedAt: Date?

    public var id: String { "\(revokingDeviceID)#\(serial)" }
    public var isActive: Bool { clearedAt == nil }

    public init(accountSubject: String, revokedDeviceID: String, revokedAt: Date, revokingDeviceID: String, serial: Int, reason: RemoteRevocationReason, verifiedAt: Date, clearedAt: Date? = nil) {
        self.accountSubject = accountSubject
        self.revokedDeviceID = revokedDeviceID
        self.revokedAt = revokedAt
        self.revokingDeviceID = revokingDeviceID
        self.serial = serial
        self.reason = reason
        self.verifiedAt = verifiedAt
        self.clearedAt = clearedAt
    }
}

// MARK: - The rules

public enum RemoteDevicePairingPolicy {
    /// Why a ceremony was refused. Each case is a sentence the Devices screen
    /// can say without inventing one.
    public enum PairingRefusal: LocalizedError, Equatable {
        case deviceWasRevoked(String)
        case keyWasRevoked(String)
        case tooManyPairedPhones
        case malformedRecord
        case pairingWithThisMac
        case staleQRPayload
        /// The six words were computed over a ceremony that is not the one this
        /// Mac opened: a different nonce, or a Mac whose `sig`/`kex`
        /// thumbprints are not the ones this Mac's QR carried.
        case ceremonyMismatch
        /// The account roster has no entry for the device the owner just
        /// confirmed, so there is no source for its public keys.
        case deviceNotInRoster(String)
        /// The roster's entry for a role is missing, is not a usable P-256
        /// point, or carries a thumbprint the six words did not confirm.
        case rosterKeyMismatch(role: String)

        public var errorDescription: String? {
            switch self {
            case .deviceWasRevoked(let id):
                "This device (\(id)) was revoked on this Mac. Clearing a revocation lets it be served requests again; it never lets it be paired again, and the grants it created stay ended."
            case .keyWasRevoked:
                "One of this device's keys was revoked on this Mac. Re-enrolling under a new device id does not clear that: what a revocation ends is a key, not an id."
            case .tooManyPairedPhones:
                "This Mac is already paired with \(DevicePairingRecord.maximumPairedPhones) phones. Unpair one first."
            case .malformedRecord:
                "This pairing record does not describe a usable set of keys."
            case .pairingWithThisMac:
                "A Mac cannot pair with itself."
            case .staleQRPayload:
                "This pairing code has expired. Show a new one on your Mac."
            case .ceremonyMismatch:
                "The words this phone showed were computed for a different pairing than the one this Mac opened. Start again from a new code on your Mac."
            case .deviceNotInRoster(let id):
                "This account does not list a device (\(id)) with the fingerprints you just confirmed, so this Mac has no source for its keys. Refresh and try again."
            case .rosterKeyMismatch(let role):
                "This account's record of the phone's \(role) key does not match the fingerprint you just confirmed on both screens. Nothing was paired."
            }
        }
    }

    /// Why a revocation was not written. Each of these is *ignored*, not an
    /// error the owner must act on: the control plane cannot invent a revocation
    /// any more than it can invent an approval.
    public enum RevocationOutcome: Equatable, Sendable {
        /// Written, together with **the grants this revocation killed** (§2.6
        /// rule 6, §4.6). The ids are returned rather than merely stamped so the
        /// caller can drop their cached secrets in the same breath
        /// (`GrantSecretCache.invalidate`) and name them in a receipt, exactly
        /// as `VaultageBroker.unpairDevice` already does.
        case written(DeviceRevocationRecord, stampedGrantIDs: [UUID])
        /// §2.6 rule 1 — the signer is not pinned, or the signature does not
        /// verify against that phone's pinned `apv` key.
        case ignoredUnpinnedSigner
        case ignoredBadSignature
        /// §2.6 rule 3 — a replayed older statement cannot re-activate a device.
        case ignoredStaleSerial(highestSeen: Int)
        /// §2.6 rule 4 — revoking the machine that holds the credentials is not
        /// a capability a companion needs.
        case refusedNamingThisMac
        case ignoredWrongAccount
        /// Already written at this serial or higher from this signer.
        case alreadyKnown
    }

    // MARK: Pairing

    /// §2.4 rule 6 — **a ceremony never clears a revocation, and never revives
    /// what one killed.**
    ///
    /// It consults the **never-cleared sets**, not the live DSRL, which the
    /// Touch ID clearance empties. The thumbprint half is the one that matters:
    /// `deviceId` is a fresh UUID per enrolment, and what the Mac pins and a
    /// revocation kills is a **key thumbprint**, so a phone that re-enrols while
    /// keeping its Secure Enclave keys would otherwise pair again under a fresh
    /// id **to the exact key that was revoked**.
    public static func pairingRefusal(
        phoneDeviceID: String,
        thumbprints: [String],
        macDeviceID: String,
        in state: VaultageMetadata
    ) -> PairingRefusal? {
        if phoneDeviceID == macDeviceID { return .pairingWithThisMac }
        if state.everRevokedDeviceIDs.contains(phoneDeviceID) { return .deviceWasRevoked(phoneDeviceID) }
        if let revoked = thumbprints.first(where: { state.everRevokedKeyThumbprints.contains($0) }) {
            return .keyWasRevoked(revoked)
        }
        let isOverwrite = state.devicePairings.contains { $0.phoneDeviceID == phoneDeviceID }
        if !isOverwrite, state.devicePairings.count >= DevicePairingRecord.maximumPairedPhones {
            return .tooManyPairedPhones
        }
        return nil
    }

    /// Writes the Mac's half of the ceremony: one pin record, with
    /// `pinGeneration` incremented when it overwrites an existing one.
    ///
    /// The caller has already displayed the QR, compared six words with the
    /// owner and taken Touch ID. **Nothing here is a substitute for that**: this
    /// function's job is to apply the two rules a later reader will forget —
    /// the never-cleared sets, and the generation bump that ends the old pin's
    /// grants for good.
    @discardableResult
    public static func pin(
        phoneDeviceID: String,
        deviceName: String,
        sigPublicKey: Data,
        sigwPublicKey: Data,
        apvPublicKey: Data,
        sumPublicKey: Data,
        sum2PublicKey: Data,
        macDeviceID: String,
        now: Date,
        in state: inout VaultageMetadata
    ) throws -> DevicePairingRecord {
        let candidate = DevicePairingRecord(
            phoneDeviceID: phoneDeviceID, deviceName: deviceName,
            sigPublicKey: sigPublicKey, sigwPublicKey: sigwPublicKey, apvPublicKey: apvPublicKey,
            sumPublicKey: sumPublicKey, sum2PublicKey: sum2PublicKey,
            pairedAt: now, pinGeneration: 1
        )
        // **The name is refused exactly as `validateClassB` refuses it
        // elsewhere** (BM-H4), and before `isWellFormed`'s flat
        // `malformedRecord`, so the Devices screen can say which rule the name
        // broke rather than "this pairing record does not describe a usable set
        // of keys" about a string.
        try RemoteSummaryValidation.validateClassB(deviceName, .deviceName)
        guard candidate.isWellFormed else { throw PairingRefusal.malformedRecord }
        if let refusal = pairingRefusal(phoneDeviceID: phoneDeviceID, thumbprints: candidate.allThumbprints, macDeviceID: macDeviceID, in: state) {
            throw refusal
        }
        let previous = state.devicePairings.first { $0.phoneDeviceID == phoneDeviceID }
        let record = DevicePairingRecord(
            phoneDeviceID: phoneDeviceID, deviceName: deviceName,
            sigPublicKey: sigPublicKey, sigwPublicKey: sigwPublicKey, apvPublicKey: apvPublicKey,
            sumPublicKey: sumPublicKey, sum2PublicKey: sum2PublicKey,
            pairedAt: now, pinGeneration: (previous?.pinGeneration ?? 0) + 1
        )
        state.devicePairings.removeAll { $0.phoneDeviceID == phoneDeviceID }
        state.devicePairings.append(record)
        state.devicePairings.sort { $0.phoneDeviceID < $1.phoneDeviceID }
        return record
    }

    /// §2.4's ceremony, at the one moment it has a key source: **the roster
    /// entry whose thumbprints are exactly the ones the QR and the six words
    /// bound.**
    ///
    /// **The gap this closes.** The four-parameter `pin` above takes the five
    /// public keys and had no product caller, because §2.4's transport carries
    /// *thumbprints and no key bytes in either direction*: P1 (the QR) carries
    /// the Mac's two, `POST /api/pairings/:id/respond` carries the phone's five,
    /// and P2 folds all seven into six words. The appendix §4 sentence *"the pin
    /// stores the public keys"* was therefore not satisfiable on this side at
    /// all. The only channel carrying key bytes is the roster (§2.3), so this is
    /// where the ceremony gets them — and the admission rule is what keeps §2.3's
    /// *"No key is ever used because the roster contains it"* literally true: no
    /// key is used **because** the roster contains it; a key is used because the
    /// owner compared six words that covered its thumbprint, and the roster was
    /// merely where the matching bytes were found.
    ///
    /// **Four independent things have to agree before a byte is stored**, which
    /// is what makes a substituted key unreachable rather than merely unlikely:
    ///
    /// 1. The SAS is over **this** ceremony — the nonce and the Mac thumbprints
    ///    this Mac's own QR carried. A SAS computed against another Mac, or a
    ///    replayed one, is `ceremonyMismatch`.
    /// 2. The QR is inside its 120 seconds (§2.4).
    /// 3. For each of the five roles, the roster entry's thumbprint equals the
    ///    one the SAS bound. Not "contains", not "any role" — role by role.
    /// 4. The roster entry's key **re-derives** that thumbprint per RFC 7638
    ///    (`RemoteRosterKey.p256PublicKey` returns bytes only from a
    ///    self-consistent entry), and `DevicePairingRecord` re-derives it a
    ///    second time from the stored bytes, so a record that disagrees with
    ///    itself matches nothing.
    ///
    /// **The name comes from the roster and is Class B-validated** by the `pin`
    /// this forwards to (BM-H4). It is display text the control plane supplies
    /// and it authorises nothing; the keys are what the six words admitted.
    ///
    /// The Mac's own two keys are **not** read from here and never are — they
    /// come from `MacDeviceKeyRoles` and the Secure Enclave. What the roster
    /// supplies is the peer's half, which is the half this Mac cannot generate.
    @discardableResult
    public static func pin(
        phoneDeviceID: String,
        confirmedBy sas: RemoteSASInputs,
        boundTo payload: RemotePairingPayload,
        from roster: RemoteRoster,
        now: Date,
        in state: inout VaultageMetadata
    ) throws -> DevicePairingRecord {
        // 1. The six words were computed over the ceremony this Mac opened.
        guard sas.nonce == payload.nonce,
              sas.macSigThumbprint == payload.macSigThumbprint,
              sas.macKexThumbprint == payload.macKexThumbprint
        else { throw PairingRefusal.ceremonyMismatch }
        // 2. §2.4: valid 120 seconds, single use, never reused across pairings.
        guard payload.isFresh(at: Int(now.timeIntervalSince1970)) else {
            throw PairingRefusal.staleQRPayload
        }
        // 3. The entry, and only the entry, for the device the owner confirmed.
        guard let entry = roster.device(phoneDeviceID) else {
            throw PairingRefusal.deviceNotInRoster(phoneDeviceID)
        }
        // 4. Role by role, against the thumbprint the SAS bound — and the bytes
        //    are reachable only through a self-consistent entry.
        var keys: [RemoteDeviceKeyRole: Data] = [:]
        for (role, confirmed) in [
            (RemoteDeviceKeyRole.sig, sas.phoneSigThumbprint),
            (.sigw, sas.phoneSigwThumbprint),
            (.apv, sas.phoneApvThumbprint),
            (.sum, sas.phoneSumThumbprint),
            (.sum2, sas.phoneSum2Thumbprint)
        ] {
            guard let key = entry.key(role), key.thumbprint == confirmed, let bytes = key.p256PublicKey else {
                throw PairingRefusal.rosterKeyMismatch(role: role.rawValue)
            }
            keys[role] = bytes
        }
        guard let sig = keys[.sig], let sigw = keys[.sigw], let apv = keys[.apv],
              let sum = keys[.sum], let sum2 = keys[.sum2]
        else { throw PairingRefusal.malformedRecord }
        return try pin(
            phoneDeviceID: phoneDeviceID,
            deviceName: entry.name,
            sigPublicKey: sig, sigwPublicKey: sigw, apvPublicKey: apv,
            sumPublicKey: sum, sum2PublicKey: sum2,
            macDeviceID: payload.macDeviceId,
            now: now,
            in: &state
        )
    }

    /// §2.6's first row: **local unpairing works against a dishonest control
    /// plane, with a window of zero.** Local record, no network, evaluated
    /// before the roster.
    ///
    /// Unpairing does **not** add to the never-cleared sets: it is not a
    /// revocation, and an owner who unpairs a phone to re-pair it must be able
    /// to. What it does do — stamping the grants that phone created — is §4.6's,
    /// and is applied by the caller inside the same metadata update.
    @discardableResult
    public static func unpair(phoneDeviceID: String, in state: inout VaultageMetadata) -> DevicePairingRecord? {
        guard let index = state.devicePairings.firstIndex(where: { $0.phoneDeviceID == phoneDeviceID }) else { return nil }
        return state.devicePairings.remove(at: index)
    }

    public static func pairing(for phoneDeviceID: String, in state: VaultageMetadata) -> DevicePairingRecord? {
        state.devicePairings.first { $0.phoneDeviceID == phoneDeviceID && $0.isWellFormed }
    }

    /// §4.3 step 2, as one predicate: **locally paired and not revoked by any
    /// active DSRL entry.** The only check that survives a compromised relay,
    /// and it needs no network.
    public static func isServedAndPaired(_ phoneDeviceID: String, in state: VaultageMetadata) -> Bool {
        guard pairing(for: phoneDeviceID, in: state) != nil else { return false }
        return !state.deviceRevocations.contains { $0.revokedDeviceID == phoneDeviceID && $0.isActive }
    }

    /// §4.8's render rule, and BM-H4's second half: **the name a surface shows
    /// is a Class B-validated name or it is the device id.**
    ///
    /// `pin` refuses an illegal name and `isWellFormed` drops a record carrying
    /// one, so in a store this build wrote the two can never differ. What this
    /// exists for is the store an *earlier* build wrote, and the direct
    /// `state.devicePairings.first { … }?.deviceName` reads that do not go
    /// through `pairing(for:)` — the arming prompt's reason, the Activity line,
    /// the remote audit events, the Devices rows and the production banner. A
    /// refusal cannot throw at a render site, so the refusal is to render the
    /// id instead: a string the owner can still act on, and one no relay chose.
    ///
    /// The lookup deliberately does **not** go through `pairing(for:)`. That
    /// function's `isWellFormed` filter is about whether a record's *keys* can
    /// be used, and a render surface is not using keys; conflating the two would
    /// make the Devices screen go silent about a phone for a reason that has
    /// nothing to do with its name. One rule, one question.
    public static func renderableDeviceName(for phoneDeviceID: String, in state: VaultageMetadata) -> String {
        renderableDeviceName(state.devicePairings.first { $0.phoneDeviceID == phoneDeviceID }, fallback: phoneDeviceID)
    }

    /// The same rule applied to a record already in hand.
    public static func renderableDeviceName(_ pin: DevicePairingRecord?, fallback: String) -> String {
        guard let pin, (try? RemoteSummaryValidation.validateClassB(pin.deviceName, .deviceName)) != nil else { return fallback }
        return pin.deviceName
    }

    // MARK: Revocation

    /// Verifies a DSRL entry and, if it survives every rule, writes it.
    ///
    /// The rules, in the order §2.6 states them and in the order they fail
    /// cheapest-first: the account must be this one; the Mac refuses an entry
    /// naming itself; the signer must be **pinned**; the signature must verify
    /// against that phone's pinned `apv` key — **not `sig`** (DB-H11, DB-M43a),
    /// because `sig` admits a passcode and that handed a thief holding an
    /// unlocked phone an irreversible kill switch over the owner's Mac; and the
    /// serial must exceed the highest ever seen from that signer.
    ///
    /// **What a verified revocation writes** (§2.6 rules 5 and 6): the DSRL
    /// record, the serial watermark, the two never-cleared sets, and §4.6's
    /// durable kill stamp on every grant the revoked device created —
    /// including one still waiting to be armed, because `GrantPolicy.arm`
    /// refuses a stamped grant and arming must not be a way around the stamp.
    /// The stamped ids come back on `.written` so the caller can invalidate
    /// their cached secrets in the same breath.
    @discardableResult
    public static func verifyAndRecordRevocation(
        _ statement: RemoteRevocationStatement,
        signature: Data,
        macDeviceID: String,
        accountSubject: String,
        now: Date,
        in state: inout VaultageMetadata,
        grantSigner: any GrantSigning
    ) -> RevocationOutcome {
        guard statement.accountSubject == accountSubject else { return .ignoredWrongAccount }
        guard statement.revokedDeviceId != macDeviceID else { return .refusedNamingThisMac }
        guard let signer = pairing(for: statement.revokingDeviceId, in: state), let key = signer.apvVerifyingKey else {
            return .ignoredUnpinnedSigner
        }
        guard let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              key.isValidSignature(ecdsa, for: RemoteApprovalDigests.revocationPreimage(statement))
        else { return .ignoredBadSignature }
        // Rule 3. The watermark is per **revoking** device and is never reset by
        // a clearance, or a captured older statement replays.
        let watermark = state.revocationSerialWatermarks[statement.revokingDeviceId] ?? 0
        guard statement.serial > watermark else { return .ignoredStaleSerial(highestSeen: watermark) }
        if state.deviceRevocations.contains(where: { $0.revokingDeviceID == statement.revokingDeviceId && $0.serial == statement.serial }) {
            return .alreadyKnown
        }
        let record = DeviceRevocationRecord(
            accountSubject: statement.accountSubject,
            revokedDeviceID: statement.revokedDeviceId,
            revokedAt: Date(timeIntervalSince1970: TimeInterval(statement.revokedAtEpochSeconds)),
            revokingDeviceID: statement.revokingDeviceId,
            serial: statement.serial,
            reason: statement.reason,
            verifiedAt: now
        )
        state.deviceRevocations.append(record)
        state.revocationSerialWatermarks[statement.revokingDeviceId] = statement.serial
        // §2.6 rule 5: the two never-cleared sets, recorded **at the moment of
        // verification**, with all five of the revoked device's pinned
        // thumbprints. If the revoked device was never pinned here there are no
        // thumbprints to record, and the id half still applies.
        state.everRevokedDeviceIDs.insert(statement.revokedDeviceId)
        if let revoked = pairing(for: statement.revokedDeviceId, in: state) {
            for thumbprint in revoked.allThumbprints { state.everRevokedKeyThumbprints.insert(thumbprint) }
        }
        // §2.6 rule 6: a revocation covers the device's pin, its open pendings
        // and — per §4.6 — **the grants it created, by a durable stamp written
        // at the moment of verification, not by a lookup.** Before this, a
        // verified revocation stopped the phone being *served* and did nothing
        // else: every grant it had created kept authorizing and its `pendingArm`
        // grant was still armable, while `clearanceSentence` shipped "the grants
        // it created stay ended". The stamp is what makes that sentence true,
        // and it is the same call `unpairDevice` makes for the weaker act.
        //
        // **The pin is deliberately *not* removed.** Rule 5's clearance restores
        // *being served*, and it can only do that if there is still a pin to
        // serve; `isServedAndPaired` already answers false for a device with an
        // active DSRL entry, which is what "covers the device's pin" means here.
        let stamped = GrantPolicy.stampDeviceKillSwitch(forDeviceID: statement.revokedDeviceId, now: now, in: &state, signer: grantSigner)
        return .written(record, stampedGrantIDs: stamped)
    }

    /// §2.6 rule 5 — **the owner at the Mac can clear one, and only the owner at
    /// the Mac can.** The Touch ID gate is the caller's; what this function
    /// guarantees is the half a later reader would get wrong:
    ///
    /// * clearing restores **being served**, never **being re-paired** — the
    ///   never-cleared sets are untouched, so §2.4 rule 6 still refuses;
    /// * clearing **never resets the highest-seen serial** for that signer, or a
    ///   captured older statement replays.
    ///
    /// The clearance sheet says both in words: *"This device will be served
    /// requests again. It cannot be paired with this Mac again, and the grants
    /// it created stay ended."*
    public static let clearanceSentence = "This device will be served requests again. It cannot be paired with this Mac again, and the grants it created stay ended."

    @discardableResult
    public static func clearRevocations(
        forDeviceID deviceID: String,
        now: Date,
        in state: inout VaultageMetadata
    ) -> Int {
        var cleared = 0
        for index in state.deviceRevocations.indices where state.deviceRevocations[index].revokedDeviceID == deviceID && state.deviceRevocations[index].isActive {
            state.deviceRevocations[index].clearedAt = now
            cleared += 1
        }
        return cleared
    }

    /// Builds the statement this Mac would verify, for the self-tests and for
    /// the live proof's step 11b. The Mac never signs one: §2.6's table has one
    /// signer kind and it is a phone (checklist 4 dropped the peer-Mac union).
    public static func statement(
        accountSubject: String,
        revokedDeviceID: String,
        revokedAt: Date,
        revokingDeviceID: String,
        serial: Int,
        reason: RemoteRevocationReason
    ) -> RemoteRevocationStatement {
        RemoteRevocationStatement(
            accountSubject: accountSubject,
            revokedDeviceId: revokedDeviceID,
            revokedAtEpochSeconds: Int(revokedAt.timeIntervalSince1970),
            revokingDeviceId: revokingDeviceID,
            serial: serial,
            reason: reason
        )
    }
}

// MARK: - The repair pass

/// BL-099's `normalize`, in the same shape and the same place as
/// `VaultOrganization`'s, `ResourceInventory`'s and
/// `DeployedCredentialLedger`'s: it runs on every decode, it is idempotent, and
/// it reasons about the relationships between the arrays rather than about one
/// of them.
///
/// **It only ever moves in the direction §2.6 permits.** Rule 2 says a
/// revocation is never removed by any network input, and rule 3 says a
/// clearance never resets a serial watermark; a hand-edited or partially written
/// file can violate both, and the repair is to restore the stricter state, never
/// the looser one. So this pass adds to the never-cleared sets and raises
/// watermarks; it removes nothing and lowers nothing.
public enum RemoteDeviceRecords {
    public static func normalize(_ state: inout VaultageMetadata) {
        // An incoherent pin matches nothing anywhere in this protocol, so
        // keeping it is only a way to mislead the Devices screen.
        state.devicePairings.removeAll { !$0.isWellFormed }
        // One pin per device id, newest generation wins.
        var byDevice: [String: DevicePairingRecord] = [:]
        for pairing in state.devicePairings {
            if let existing = byDevice[pairing.phoneDeviceID], existing.pinGeneration >= pairing.pinGeneration { continue }
            byDevice[pairing.phoneDeviceID] = pairing
        }
        state.devicePairings = byDevice.values.sorted { $0.phoneDeviceID < $1.phoneDeviceID }

        for revocation in state.deviceRevocations {
            // Rule 2, restored: a revocation that is present implies its device
            // is in the never-cleared set, cleared or not.
            state.everRevokedDeviceIDs.insert(revocation.revokedDeviceID)
            // Rule 3, restored: the watermark is the highest serial ever seen
            // from that signer, and a clearance never lowers it.
            let watermark = state.revocationSerialWatermarks[revocation.revokingDeviceID] ?? 0
            if revocation.serial > watermark {
                state.revocationSerialWatermarks[revocation.revokingDeviceID] = revocation.serial
            }
            // The thumbprint half is recorded at verification time, from the pin
            // that existed then. If that pin is still here — an entry written
            // before the pin was removed, or a file edited in between — the five
            // thumbprints are restored.
            if let pinned = byDevice[revocation.revokedDeviceID] {
                for thumbprint in pinned.allThumbprints { state.everRevokedKeyThumbprints.insert(thumbprint) }
            }
        }
        state.deviceRevocations.sort { ($0.revokingDeviceID, $0.serial) < ($1.revokingDeviceID, $1.serial) }
    }
}
