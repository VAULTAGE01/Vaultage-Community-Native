import Foundation

/// BL-099 — the pending-approval publication path (§3.2, §3.5, §3.6, §3.7,
/// §3.8), as pure functions over explicit inputs.
///
/// Everything here is decidable without a network, a Keychain or a clock the
/// caller does not supply, which is what lets §9.2 assert the rules that
/// actually bite: what may mirror, which recipient key a summary seals to, what
/// the relay is told in the clear, how many versions the Mac keeps, and the
/// re-publish budget that stops an agent manufacturing approval fatigue.
///
/// **Publication never blocks the sheet** (§3.7). It happens in a detached task
/// at the moment the native sheet appears; if it is slow, fails or is refused,
/// the sheet is unaffected and the request is simply not mirrored. Nothing in
/// this file can make a local approval wait.

// MARK: - §3.6 — what mirrors

/// The mirrorable set, expressed as a single predicate a test can assert
/// (§3.6).
///
/// **Written against `ApprovalRequirement`, not against a trust-class enum**
/// (DB-H13). Version 3 defined `trustClass` as
/// `read | configuration_write | admin | billing`; the shipped table is
/// `OperationTrustClass` — `ordinary | billing | production-affecting | admin` —
/// and a builder mapping the code's `production-affecting` onto the invented
/// `configuration_write` would have mirrored a zone-level DNS change in
/// *staging*, approved from a train platform. `ApprovalRequirement.of` already
/// maps `trust == .productionAffecting` to `.nativeSheetEveryTime`, which is
/// exactly what §3.6 is trying to guarantee, and it is one call.
///
/// **Every production predicate is `Environment.isProduction`** (checklist 2,
/// DB-H21), never `EnvironmentSensitivity`: an owner who names an environment
/// "production" and leaves the sensitivity at its default is treated as
/// production by every gate in the shipped code.
public enum RemoteMirrorEligibility {
    /// Why a request is native-only. Each case is a sentence the receipt and the
    /// Devices screen can use without inventing one.
    public enum Refusal: String, Equatable, Sendable {
        case runtimeInjection = "runtime_injection"
        case runtimeDelivery = "runtime_delivery"
        case mintsCredential = "mints_credential"
        case production = "production"
        case nativeSheetEveryTime = "native_sheet_every_time"
        case neverAutoAllowed = "never_auto_allowed"
        case nativeApprovalOnly = "native_approval_only"
        case mirroringOff = "mirroring_off"
        case presenceActiveInAwayPosition = "presence_active_in_away_position"
        /// §3.7's consent moment, **as a precondition rather than a default**
        /// (BL-099 slice 3 step (a)). The owner has never acknowledged the
        /// one-screen statement, so nothing may be published whatever the
        /// stored position says. Kept distinct from `mirroringOff` because a
        /// receipt reading "you turned this off" about something the owner was
        /// never offered is a lie the switch would be telling for them.
        case consentNotGiven = "consent_not_given"
        /// Consented, positioned and present — and no phone is paired, so there
        /// is no recipient key to seal to. Not a refusal of the request; a
        /// statement about this Mac.
        case noPairedPhone = "no_paired_phone"
        /// §3.7's open-pending ceilings, **as the Mac's own gate** (BM-M3).
        /// `RemoteOpenPendingLimits.perAccount` and `perAgentClient` were
        /// constants nothing read: the ceiling existed only at the Worker, and
        /// the Mac is the publisher, so an agent that churned requests produced
        /// unbounded publications. That is the approval-fatigue half of A18 —
        /// §3.8's re-publish budget closes it for one pending and nothing closed
        /// it across pendings.
        case tooManyOpenPendings = "too_many_open_pendings"
        /// §3.7's **third** number — *"or **2** open connect requests for the
        /// account"* — which BM-M3 left owed because it needs a count of open
        /// connect requests specifically and no seam reported one. Kept
        /// distinct from `tooManyOpenPendings` because the numbers are 2 and 8:
        /// a receipt saying "you have eight requests waiting" about a Mac
        /// holding two connect requests names the wrong fact, and the owner's
        /// remedy — finish or cancel a connect on the phone — is different.
        case tooManyOpenConnectRequests = "too_many_open_connect_requests"
    }

    /// Every refusal above, in one list, so a test can assert the set rather
    /// than a sample of it and a new case cannot be added without an
    /// owner-facing sentence.
    public static let allRefusals: [Refusal] = [
        .runtimeInjection, .runtimeDelivery, .mintsCredential, .production,
        .nativeSheetEveryTime, .neverAutoAllowed, .nativeApprovalOnly,
        .mirroringOff, .presenceActiveInAwayPosition, .consentNotGiven, .noPairedPhone,
        .tooManyOpenPendings, .tooManyOpenConnectRequests
    ]

    /// `class: action`. The mirrorable set is exactly **"reads, and ordinary
    /// creates and updates, outside production"**.
    public static func actionRefusal(
        operation: Operation,
        isProduction: Bool
    ) -> Refusal? {
        // `--run` runtime injection has no `Operation` case at all and is
        // refused by `ApprovalWire` before it reaches here. A delivery is the
        // one class that moves a credential **value** to a new location, and
        // D38 names it native-only; D71 made every delivery run its own path,
        // so the operation's taxonomy is the whole test.
        if operation.taxonomy.isDelivery { return .runtimeDelivery }
        if operation.taxonomy.mintsCredential { return .mintsCredential }
        // The production gate runs before the requirement gate so the refusal an
        // owner reads names the thing they can change.
        if isProduction { return .production }
        switch operation.approvalRequirement {
        case .bindingsAndGrants, .grantScopedToOperation:
            return nil
        case .nativeSheetEveryTime:
            return .nativeSheetEveryTime
        case .neverAutoAllowed:
            return .neverAutoAllowed
        case .nativeApprovalOnly:
            return .nativeApprovalOnly
        }
    }

    /// §3.7's three mirroring positions. The middle one is the default (O10).
    public enum Position: String, Codable, CaseIterable, Sendable {
        case off
        case whenAway = "when_away"
        case always
    }

    /// `mirroringOffPublishesNothing` and
    /// `mirroringPositionAwayPublishesNothingWhileActive`, as one function.
    ///
    /// Presence is a **publication** input here and nowhere else: it is never
    /// consulted by an authorization check (DB-H8, Q10).
    public static func positionRefusal(_ position: Position, presence: RemotePresence) -> Refusal? {
        switch position {
        case .off: .mirroringOff
        case .whenAway: presence == .active ? .presenceActiveInAwayPosition : nil
        case .always: nil
        }
    }
}

// MARK: - §3.5 — TTL

public enum RemotePendingTTL {
    /// The hard ceiling the Worker enforces and the Mac re-checks.
    public static let ceilingSeconds = 15 * 60

    /// `action` and `grant` get five minutes; `connect` ten;
    /// `provisioning_selection` the lesser of its conversation's remaining life
    /// and fifteen minutes.
    ///
    /// DB-L6: version 2's stated reason was wrong — `PendingProvisioning`
    /// records stay collectable for one further lifetime after expiry, so the
    /// mirror is *tighter* than the thing mirrored, not co-terminous. The
    /// correct reason is simply that a human question older than fifteen minutes
    /// should be asked again.
    public static func seconds(for summaryClass: RemoteApprovalClass, conversationRemaining: Int? = nil) -> Int {
        switch summaryClass {
        case .action, .grant: 5 * 60
        case .connect: 10 * 60
        case .provisioningSelection: min(conversationRemaining ?? ceilingSeconds, ceilingSeconds)
        }
    }

    public static func isWithinCeiling(issuedAt: Int, expiresAt: Int) -> Bool {
        expiresAt > issuedAt && expiresAt - issuedAt <= ceilingSeconds
    }
}

// MARK: - §6.3 — the open-pending ceilings

public enum RemoteOpenPendingLimits {
    public static let perAccount = 8
    public static let perAgentClient = 4
    public static let connectRequestsPerAccount = 2
    /// `POST /api/approvals/republish`'s body cap. **A different quantity** from
    /// the retained-version cap, and version 7's "the same number bounds"
    /// sentence is deleted (version 8, NEW-L1).
    public static let republishBatchSize = 8
}

// MARK: - §3.2 — the sealed summary's envelope shape

/// The padding and bucket arithmetic of §5.3, which the summary envelope shares
/// with the credential envelope.
///
/// Pure and OS-independent, deliberately: HPKE itself needs macOS 14, and the
/// sizes are what a second implementation most easily gets wrong.
public enum RemoteEnvelopePadding {
    public static let buckets = [1024, 2048, 4096, 8192]
    /// `1 + 1 + 65 + bucket + 16`, one per bucket. Migration 0007's
    /// `byte_length` CHECK is exactly these four (§6.1).
    public static let rawEnvelopeSizes = [1107, 2131, 4179, 8275]
    /// Over this many bytes of plaintext is an explicit `credential_too_large`
    /// refusal (DB-L3): the largest bucket holds `8192 - 2`.
    public static let maximumPlaintextBytes = 8190

    public static func bucket(forPlaintextLength length: Int) -> Int? {
        buckets.first { $0 >= 2 + length }
    }

    public static func rawEnvelopeSize(bucket: Int) -> Int { 1 + 1 + 65 + bucket + 16 }

    /// `padded := u16be(plaintextLength) ‖ plaintext ‖ 0x00 × (bucket − 2 − len)`
    public static func pad(_ plaintext: Data) throws -> Data {
        guard plaintext.count <= maximumPlaintextBytes, let bucket = bucket(forPlaintextLength: plaintext.count) else {
            throw VaultageError.invalidInput("credential_too_large")
        }
        var padded = Data(capacity: bucket)
        padded.append(UInt8(truncatingIfNeeded: plaintext.count >> 8))
        padded.append(UInt8(truncatingIfNeeded: plaintext.count))
        padded.append(plaintext)
        padded.append(Data(repeating: 0, count: bucket - 2 - plaintext.count))
        return padded
    }

    public static func unpad(_ padded: Data) throws -> Data {
        guard buckets.contains(padded.count), padded.count >= 2 else {
            throw VaultageError.invalidInput("A sealed payload is not one of the four bucket sizes.")
        }
        let bytes = [UInt8](padded)
        let length = Int(bytes[0]) << 8 | Int(bytes[1])
        guard length <= padded.count - 2 else {
            throw VaultageError.invalidInput("A sealed payload declares more plaintext than it carries.")
        }
        // The tail must be zeros. A non-zero tail is a second channel inside a
        // padded field, which is exactly what padding to a bucket exists to
        // remove.
        guard bytes[(2 + length)...].allSatisfy({ $0 == 0 }) else {
            throw VaultageError.invalidInput("A sealed payload's padding is not zero.")
        }
        return Data(bytes[2..<(2 + length)])
    }
}

/// One sealed summary, one recipient. The bytes on the wire.
public struct RemoteSealedSummary: Codable, Hashable, Sendable {
    public static let version: UInt8 = 0x01
    public static let suite: UInt8 = 0x01

    public let phoneDeviceID: String
    /// `version(1) ‖ suite(1) ‖ enc(65) ‖ ciphertext(bucket) ‖ tag(16)`.
    public let envelope: Data
    /// Which pinned key it was sealed to — `sum`, or `sum2` for a sensitive
    /// summary. Recorded so the Devices screen and the receipt can say which ACL
    /// the owner's phone will have to satisfy.
    public let recipientThumbprint: String
    public let isSensitive: Bool
    /// **P8's `issuedAt`, carried beside the ciphertext** (BL-096 slice 2).
    ///
    /// The HPKE `info` is also the AAD, so the phone must rebuild
    /// `summaryEnvelopeInfoFields` — which ends in `issuedAt` — **before** it
    /// can open the envelope. `issuedAt` is inside the summary, which is the
    /// thing it cannot read yet, and the §3.2 routing header carries
    /// `expiresAt` and not `issuedAt`; subtracting §3.5's class TTL recovers it
    /// for `action`, `grant` and `connect` and **not** for
    /// `provisioning_selection`, whose TTL is its conversation's remaining life.
    /// So it travels per recipient, in the clear, beside the ciphertext it is
    /// the AAD for — which discloses nothing the header's `expiresAt` does not
    /// already, and is not trusted: a wrong value is an AEAD failure.
    public let sealedAt: Int

    public init(phoneDeviceID: String, envelope: Data, recipientThumbprint: String, isSensitive: Bool, sealedAt: Int) {
        self.phoneDeviceID = phoneDeviceID
        self.envelope = envelope
        self.recipientThumbprint = recipientThumbprint
        self.isSensitive = isSensitive
        self.sealedAt = sealedAt
    }

    public var isWellFormed: Bool {
        guard RemoteEnvelopePadding.rawEnvelopeSizes.contains(envelope.count) else { return false }
        let bytes = [UInt8](envelope.prefix(2))
        return bytes.count == 2 && bytes[0] == Self.version && bytes[1] == Self.suite
    }
}

// MARK: - §3.2 — the cleartext routing header

/// What the Worker is told, and nothing more.
///
/// **Every header field is inside the sealed summary, or is derived from exactly
/// one field that is under rule 1a — with two named carve-outs** (version 8,
/// NEW-H2): `requestDigest` and `sensitivityBucket`. The phone compares every
/// field that is *inside* the seal and **never** compares those two.
public struct RemoteRoutingHeader: Codable, Hashable, Sendable {
    public let summaryClass: RemoteApprovalClass
    public let verb: String
    public let sensitivityBucket: String
    public let presence: RemotePresence
    public let expiresAt: Int
    public let openPendingCount: Int
    /// **Routing metadata only** (version 7, DB-M41). Residual 8 made
    /// `summaryDigest` — and therefore `approvalRequestDigest` — per recipient
    /// for `class: grant`, so there is no single value: this is the *first*
    /// recipient's, in `phoneDeviceId` order. The Mac's own poll matches on
    /// `pendingId`, not on this, and the phone never compares it. Version 7 left
    /// the older universal claim standing, under which a phone would derive its
    /// own digest, compare it to this, and **refuse every multi-recipient
    /// grant**.
    public let requestDigest: String

    public init(summaryClass: RemoteApprovalClass, verb: String, sensitivityBucket: String, presence: RemotePresence, expiresAt: Int, openPendingCount: Int, requestDigest: String) {
        self.summaryClass = summaryClass
        self.verb = verb
        self.sensitivityBucket = sensitivityBucket
        self.presence = presence
        self.expiresAt = expiresAt
        self.openPendingCount = openPendingCount
        self.requestDigest = requestDigest
    }

    /// **Derived from the digested `isProduction`, not from `sensitivity`**
    /// (DB-L24). It is a §3.3 rule-1a derivation — one digested field, total
    /// over a boolean — and deriving it from `sensitivity` would reintroduce
    /// DB-H21 in the header, bucketing an environment *named* "production" as
    /// `non_production`.
    public static func sensitivityBucket(isProduction: Bool) -> String {
        isProduction ? "production" : "non_production"
    }

    /// The header field list, which §9.1's `headerFieldListEqualsPendingApprovalsColumnSet`
    /// asserts against `pending_approvals`' cleartext column set (DB-M14). **The
    /// disclosure the owner reads is the disclosure the database makes.**
    public static let fieldNames = ["class", "verb", "sensitivityBucket", "presence", "expiresAt", "openPendingCount", "requestDigest"]
}

// MARK: - §3.2 — the retained field lists

/// One version of one pending, as sealed to one recipient.
///
/// **Field lists, not ciphertext** (§3.2). The Mac recomputes the digests from
/// these at verification (§4.3 step 9a); without them it cannot construct the
/// preimage it must verify against, because `presence` and the five display
/// fields are values that will have moved by the time the owner signs — which
/// turns signature verification into a search over candidate preimages, and that
/// is a vulnerability rather than a workaround.
public struct RemoteRetainedVersion: Codable, Hashable, Sendable {
    public let issuedAt: Int
    public let fields: [String]
    public let summaryDigest: String
    public let approvalRequestDigest: String

    public init(issuedAt: Int, fields: [String], summaryDigest: String, approvalRequestDigest: String) {
        self.issuedAt = issuedAt
        self.fields = fields
        self.summaryDigest = summaryDigest
        self.approvalRequestDigest = approvalRequestDigest
    }
}

/// The ordered version lists, **one per recipient phone, keyed by
/// `phoneDeviceId`** (residual 8, DB-M37).
///
/// It is per recipient because §3.3.1's grant section carries `"recipient",
/// phoneDeviceId, phoneApvThumbprint`. Version 5 justified the keying by "the
/// grant section's device fields differ per recipient", which was not true of
/// the section as written, so all four lists were byte-identical and 9a's
/// selection was vacuous. With the recipient digested, a **cross-recipient
/// replay fails at 9a** rather than only at the seal. For a non-grant class the
/// lists are identical and the keying is future-proofing; that is stated rather
/// than implied.
public struct RemoteRetainedFieldLists: Codable, Hashable, Sendable {
    /// **16 per recipient** — the budget's 15 re-publishes plus the original —
    /// evicted **oldest-first** (version 7, DB-H34; version 8, NEW-H1 put the
    /// number in step 9a). Version 6 capped it at 8, smaller than the count the
    /// same paragraph derived, so a long-lived pending's early versions were
    /// evicted and the owner who signed the copy their phone fetched on the
    /// first doorbell push got `digest_mismatch` and tampering copy — exactly
    /// the failure the list exists to prevent.
    public static let maximumVersionsPerRecipient = 16

    /// Oldest first.
    public private(set) var versionsByRecipient: [String: [RemoteRetainedVersion]]

    public init(versionsByRecipient: [String: [RemoteRetainedVersion]] = [:]) {
        self.versionsByRecipient = versionsByRecipient
    }

    public mutating func record(_ version: RemoteRetainedVersion, for recipient: String) {
        var versions = versionsByRecipient[recipient] ?? []
        versions.append(version)
        // The budget makes the cap unreachable in practice, so eviction is a
        // safety net rather than a policy.
        if versions.count > Self.maximumVersionsPerRecipient {
            versions.removeFirst(versions.count - Self.maximumVersionsPerRecipient)
        }
        versionsByRecipient[recipient] = versions
    }

    /// §4.3 step 9a verifies **newest-first** over this list.
    public func versionsNewestFirst(for recipient: String) -> [RemoteRetainedVersion] {
        (versionsByRecipient[recipient] ?? []).reversed()
    }

    public func newest(for recipient: String) -> RemoteRetainedVersion? {
        versionsByRecipient[recipient]?.last
    }

    /// **Deleted in the same metadata update that writes the terminal state**,
    /// so a decided pending retains nothing (§3.2, acceptance [13]).
    public mutating func deleteAll() { versionsByRecipient.removeAll() }

    public var totalVersions: Int { versionsByRecipient.values.reduce(0) { $0 + $1.count } }
}

// MARK: - §3.8 item 2 — the re-publish budget

/// **The churn bound, and why the cap is not derived from the concurrency
/// ceiling** (version 8, NEW-H3).
///
/// Version 7 derived 15 versions from "§6.3's ceiling of 8 open pendings ⇒ 7
/// increases and 7 decreases", which holds only if each of the other seven
/// pendings opens **once**. The ceiling bounds *concurrency*, not *reuse*: an
/// agent may open a cheap pending, close it, open another, indefinitely, and
/// each cycle re-publishes every other open pending. At `approvals.publish`'s
/// 120/min with a batched re-publish counting as one unit, that is ≈80
/// versions/minute added to a chosen pending — 16 exhausted in about twelve
/// seconds — and version 7's rule then **cancelled** it. That handed any agent a
/// deterministic, cheap cancel primitive against any pending it chooses,
/// including the production grant the owner is walking to their phone to
/// approve: approval fatigue manufactured on demand.
///
/// So the bound is on the churn, per pending, not on the concurrency:
///
/// > **Minimum interval: one re-publish per pending per 20 seconds.** Count
/// > changes inside the window are coalesced and applied once, at the window's
/// > end. **Per-pending budget: 15 re-publishes**, which with the interval takes
/// > at least 300 s — the whole TTL of an `action` or `grant` pending.
///
/// **When the budget is exhausted the Mac stops re-publishing. It never
/// cancels.** The pending keeps its newest sealed version and lives out its TTL;
/// the only consequence is that the digested `openPendingCount` in that version
/// is older, which the phone already renders in the past tense with its as-of
/// time. **Exceeding the budget is never a cancellation**, and there is no input
/// an agent can supply that cancels another pending.
public struct RemoteRepublishBudget: Codable, Hashable, Sendable {
    public static let maximumRepublishes = 15
    public static let minimumIntervalSeconds = 20
    /// 15 re-publishes plus the original.
    public static var maximumVersions: Int { maximumRepublishes + 1 }

    public private(set) var used: Int
    public private(set) var lastPublishedAt: Int
    /// A count change that arrived inside the interval and is waiting for the
    /// window to end. Coalesced: many changes inside one window become one
    /// re-publish.
    public private(set) var hasCoalescedChange: Bool

    public init(firstPublishedAt: Int) {
        self.used = 0
        self.lastPublishedAt = firstPublishedAt
        self.hasCoalescedChange = false
    }

    public enum Outcome: Equatable, Sendable {
        /// Re-publish now.
        case republish
        /// Inside the 20-second window. The change is remembered and applied
        /// once, at `notBefore`.
        case coalesced(notBefore: Int)
        /// The budget is spent. **Stop re-publishing; never cancel.**
        case exhausted
    }

    /// Asks for a re-publish at `now`. Mutates only when it answers
    /// `.republish` or when it remembers a coalesced change.
    public mutating func requestRepublish(at now: Int) -> Outcome {
        guard used < Self.maximumRepublishes else { return .exhausted }
        let earliest = lastPublishedAt + Self.minimumIntervalSeconds
        guard now >= earliest else {
            hasCoalescedChange = true
            return .coalesced(notBefore: earliest)
        }
        used += 1
        lastPublishedAt = now
        hasCoalescedChange = false
        return .republish
    }

    /// The soonest instant a coalesced change could be applied, or `nil` when
    /// there is nothing waiting.
    public var coalescedDueAt: Int? { hasCoalescedChange ? lastPublishedAt + Self.minimumIntervalSeconds : nil }

    public var isExhausted: Bool { used >= Self.maximumRepublishes }
}

// MARK: - The Mac's local record of an open pending

/// §3.4's states, Mac side. `Applied` and `Discarded` are Mac-side only; the
/// control plane's last word is `Delivered` and it is never told whether the Mac
/// acted.
public enum RemotePendingState: String, Codable, Hashable, Sendable, CaseIterable {
    case pending, decided, delivered, applied, discarded, cancelled, expired

    public var isTerminal: Bool {
        switch self {
        case .pending, .decided, .delivered: false
        case .applied, .discarded, .cancelled, .expired: true
        }
    }
}

/// §3.8's cancel reasons, posted to the relay. Exactly seven; the Worker's
/// `cancel_reason` CHECK carries the same seven.
public enum RemoteCancelReason: String, Codable, Hashable, Sendable, CaseIterable {
    case decidedLocally = "decided_locally"
    case decidedRemotely = "decided_remotely"
    case requestChanged = "request_changed"
    case digestMismatch = "digest_mismatch"
    case decisionStale = "decision_stale"
    case agentAbandoned = "agent_abandoned"
    case brokerShutdown = "broker_shutdown"
}

public struct RemotePendingPublication: Codable, Hashable, Sendable, Identifiable {
    public let pendingID: String
    public let summaryClass: RemoteApprovalClass
    public let issuedAt: Int
    public let expiresAt: Int
    /// Sorted `phoneDeviceId`s, which is also the order `requestDigest` picks
    /// its first recipient from.
    public let recipients: [String]
    public var state: RemotePendingState
    public var retained: RemoteRetainedFieldLists
    public var budget: RemoteRepublishBudget

    public var id: String { pendingID }

    public init(pendingID: String, summaryClass: RemoteApprovalClass, issuedAt: Int, expiresAt: Int, recipients: [String], state: RemotePendingState = .pending, retained: RemoteRetainedFieldLists = .init(), budget: RemoteRepublishBudget? = nil) {
        self.pendingID = pendingID
        self.summaryClass = summaryClass
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.recipients = recipients.sorted()
        self.state = state
        self.retained = retained
        self.budget = budget ?? RemoteRepublishBudget(firstPublishedAt: issuedAt)
    }

    /// **The retained lists are deleted in the same update that writes the
    /// terminal state** (§3.2, acceptance [13]), so a decided pending retains
    /// nothing.
    public mutating func markTerminal(_ terminal: RemotePendingState) {
        precondition(terminal.isTerminal, "markTerminal was handed a non-terminal state")
        state = terminal
        retained.deleteAll()
    }

    public func isOpen(at now: Int) -> Bool { state == .pending && now < expiresAt }
}
