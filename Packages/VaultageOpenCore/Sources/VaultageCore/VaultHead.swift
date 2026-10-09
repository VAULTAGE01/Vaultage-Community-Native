import CryptoKit
import Foundation

// BL-100 slice A — the head (`13-MULTI-DEVICE-CUSTODY.md` §3.3), at
// **`headFormat` 1**.
//
// **Slice A syncs adds and edits only.** The head carries **no `tomb` entries in
// its live set and no `provisional` field at all**; both `provisional` and
// `provisionalDigest` are out of the structure and out of the preimage until
// slice C lands. The count is `"10"` in both formats and **that is a
// coincidence rather than a continuity** — which is exactly why the format
// carries a version field: arity is not a version.
//
// **Time decides nothing** (eighth pass, DB8-H1/H2/H3, closed as a class by
// simplification). Ordering is `(keyGeneration, headSeq)` and the chain. There
// is no ceiling, no per-generation floor, no one-step relaxation and no
// time-sync clause. `writtenAt` stays in the signature preimage and is
// **informational**: it is what the owner is shown, and it is signed so a relay
// cannot forge that display.

// MARK: - Clocks

/// A clock that cannot be set backwards and does not move when the timezone or
/// NTP does. **Every duration in this design is measured on one of these**, by
/// each device, from the event that starts it (§7's box).
///
/// What it does not survive is a **reboot**, and §3.3's accumulator is built
/// around that rather than against it: a reboot contributes **zero**, never a
/// reset and never a finalization.
public protocol MonotonicClock: Sendable {
    /// Seconds since an origin this process cannot move. Resets at boot.
    var uptime: TimeInterval { get }
}

public struct SystemMonotonicClock: MonotonicClock {
    public init() {}
    public var uptime: TimeInterval { ProcessInfo.processInfo.systemUptime }
}

/// The settable clock, used for **display only**. Nothing in head admission
/// reads one — `VaultHeadAdmission` takes no wall clock at all, which is the
/// structural half of "no head-admission check consults a clock".
public protocol WallClock: Sendable {
    var now: Date { get }
}

public struct SystemWallClock: WallClock {
    public init() {}
    public var now: Date { Date() }
}

// MARK: - The head

/// §3.3 change 2's structure, at `headFormat` 1.
public struct VaultHead: Codable, Sendable, Equatable {
    /// **1 = slice A. 2 = slice C**, which re-adds `provisional` and
    /// `provisionalDigest`. A verifier refuses a `headFormat` it does not
    /// implement, by name.
    public let headFormat: Int
    public let vaultID: UUID
    public let keyGeneration: Int
    public let headSeq: Int
    public let previousHeadDigest: String
    /// `CanonicalDigest.hex` over the sorted `(wireID, revision)` pairs of
    /// every **live** record. It covers **names and revisions, not bytes** —
    /// which is why §7.1 stage 2 proves the relay served the right set of names
    /// and nothing whatever about their content (A-1, A-6).
    public let digest: String
    public let acks: [VaultHeadAck]
    /// Signed, and **informational**. No verifier decision depends on it.
    public let writtenAt: Int
    public let writerDeviceId: String

    public static let sliceAFormat = 1
    public static let sliceCFormat = 2
    /// A sanity ceiling rather than a bound that binds: a slice-A head carries
    /// ten scalar fields, one digest and `acks`, which the 24-device roster cap
    /// already bounds.
    public static let maximumBytes = 64 * 1024

    public init(
        headFormat: Int = VaultHead.sliceAFormat,
        vaultID: UUID,
        keyGeneration: Int,
        headSeq: Int,
        previousHeadDigest: String,
        digest: String,
        acks: [VaultHeadAck],
        writtenAt: Int,
        writerDeviceId: String
    ) {
        self.headFormat = headFormat
        self.vaultID = vaultID
        self.keyGeneration = keyGeneration
        self.headSeq = headSeq
        self.previousHeadDigest = previousHeadDigest
        self.digest = digest
        self.acks = acks
        self.writtenAt = writtenAt
        self.writerDeviceId = writerDeviceId
    }

    /// §3.3's signature preimage. **Ten body fields, count `"10"`** — and
    /// `provisional`/`provisionalDigest` are **not** among them.
    ///
    /// > `["vaultage.vault.head.v2", "10", headFormat, accountSubject, vaultID,
    /// >   keyGeneration, headSeq, previousHeadDigest, digest, acksDigest,
    /// >   writtenAt, writerDeviceId]`
    ///
    /// Read the **field list**, not the number: a builder who reads `"10"` and
    /// reaches for version 12's list produces a head that verifies against
    /// nothing.
    public static let domain = "vaultage.vault.head.v2"

    public func preimageFields(accountSubject: String) -> [String] {
        let body = [
            "\(headFormat)",
            accountSubject,
            vaultID.uuidString.lowercased(),
            "\(keyGeneration)",
            "\(headSeq)",
            previousHeadDigest,
            digest,
            VaultHeadAck.digest(of: acks),
            "\(writtenAt)",
            writerDeviceId
        ]
        return [VaultHead.domain, "\(body.count)"] + body
    }

    public func preimage(accountSubject: String) -> Data {
        CanonicalDigest.encode(preimageFields(accountSubject: accountSubject))
    }

    /// **`previousHeadDigest` is `CanonicalDigest.hex` over the previous head's
    /// signature preimage**, not over the serialized record — so the chain
    /// binds exactly what the signature binds, and an edited `writtenAt` breaks
    /// the *next* head's chain check as well as its own signature check.
    public func chainDigest(accountSubject: String) -> String {
        CanonicalDigest.hex(preimageFields(accountSubject: accountSubject))
    }

    /// The first head in a vault's chain anchors on this, which is the digest
    /// of the empty field list and therefore not a head anybody can produce.
    public static let genesisPreviousDigest = CanonicalDigest.hex(["vaultage.vault.head.genesis.v1"])

    /// **The inverse of `preimage(accountSubject:)`** — BL-100 slice A's
    /// transport, which has to turn what a relay served back into a head.
    ///
    /// It lives here, beside the encoder, for one reason: a decoder that drifts
    /// from its encoder is a chain break nobody sees. It does **not** weaken the
    /// enumeration below it — *"the writer is the only thing that **writes** a
    /// `VaultHead`"* — because rebuilding a head that already exists produces
    /// nothing to push, advances no watermark, and is refused unless it
    /// reproduces the exact bytes it came from.
    ///
    /// §3.3's relay *"trusts no digest"*: `digest` and `previousHeadDigest` are
    /// link labels it orders its table by, and the authority is the body the
    /// signature covers. So a device rebuilds from the body, and
    /// `accountSubject` and `vaultID` are **this device's** rather than the
    /// wire's — both are fields of the preimage, so a head signed for another
    /// account or another vault fails here rather than at the signature check.
    public static func rebuilt(
        fromPreimage preimage: Data,
        accountSubject: String,
        vaultID: UUID,
        acks: [VaultHeadAck]
    ) -> VaultHead? {
        guard preimage.count <= maximumBytes,
              let fields = CanonicalDigest.decode(preimage), fields.count == 12,
              fields[0] == domain, fields[1] == "10",
              let headFormat = Int(fields[2]),
              fields[3] == accountSubject,
              fields[4] == vaultID.uuidString.lowercased(),
              let keyGeneration = Int(fields[5]), let headSeq = Int(fields[6]),
              // Field 9 is the acks digest and field 10 is `writtenAt`, in
              // `preimageFields`' own order — read the list, not the count.
              VaultHeadAck.digest(of: acks) == fields[9],
              let writtenAt = Int(fields[10])
        else { return nil }
        let head = VaultHead(
            headFormat: headFormat,
            vaultID: vaultID,
            keyGeneration: keyGeneration,
            headSeq: headSeq,
            previousHeadDigest: fields[7],
            digest: fields[8],
            acks: acks,
            writtenAt: writtenAt,
            writerDeviceId: fields[11]
        )
        // Asserted rather than assumed: what a verifier is about to check a
        // signature over must be the bytes that arrived.
        guard head.preimage(accountSubject: accountSubject) == preimage else { return nil }
        return head
    }

    /// Pairs this head with the signature that covers its preimage.
    ///
    /// One purpose: the transport that rebuilds a served head then names **no
    /// initializer of either type**, so the enumeration that asserts a head is
    /// made in one file keeps meaning what it says rather than being widened to
    /// let a second file in.
    public func signed(_ signature: Data) -> SignedVaultHead {
        SignedVaultHead(head: self, signature: signature)
    }
}

/// §3.3 change 3 — a **separate, small, scheduled push**, signed by `sig`, the
/// read-route key: `.privateKeyUsage` only, **no presence**, the key the
/// background refresh already uses.
///
/// The common phone is a **reader**, so an acknowledgement that rode on writes
/// would never advance and *"your iPhone has not seen this Mac since Tuesday"*
/// would be a permanent, correct-in-form and wrong-in-substance red light.
public struct VaultHeadAck: Codable, Sendable, Equatable {
    public let deviceId: String
    public let ackedKeyGeneration: Int
    public let ackedHeadSeq: Int
    public let ackedHeadDigest: String
    public let ackedAt: Int

    public init(deviceId: String, ackedKeyGeneration: Int, ackedHeadSeq: Int, ackedHeadDigest: String, ackedAt: Int) {
        self.deviceId = deviceId
        self.ackedKeyGeneration = ackedKeyGeneration
        self.ackedHeadSeq = ackedHeadSeq
        self.ackedHeadDigest = ackedHeadDigest
        self.ackedAt = ackedAt
    }

    public static let domain = "vaultage.vault.ack.v1"

    /// The `ack` preimage, count **`"7"`**: accountSubject, vaultID, deviceId,
    /// ackedKeyGeneration, ackedHeadSeq, ackedHeadDigest, ackedAt.
    public func preimageFields(accountSubject: String, vaultID: UUID) -> [String] {
        let body = [
            accountSubject,
            vaultID.uuidString.lowercased(),
            deviceId,
            "\(ackedKeyGeneration)",
            "\(ackedHeadSeq)",
            ackedHeadDigest,
            "\(ackedAt)"
        ]
        return [VaultHeadAck.domain, "\(body.count)"] + body
    }

    public func preimage(accountSubject: String, vaultID: UUID) -> Data {
        CanonicalDigest.encode(preimageFields(accountSubject: accountSubject, vaultID: vaultID))
    }

    /// Pre-digested to a single field, which is why the head preimage has no
    /// live nested list and its count is a plain arity.
    public static func digest(of acks: [VaultHeadAck]) -> String {
        let sorted = acks.sorted { $0.deviceId < $1.deviceId }
        var fields: [String] = ["vaultage.vault.head.acks.v1", "\(sorted.count)"]
        for ack in sorted {
            fields.append(contentsOf: [
                ack.deviceId, "\(ack.ackedKeyGeneration)", "\(ack.ackedHeadSeq)", ack.ackedHeadDigest, "\(ack.ackedAt)"
            ])
        }
        return CanonicalDigest.hex(fields)
    }
}

/// A head as it is served and retained: the structure, its signature, and — on
/// this device — the monotonic instant **it** accepted it.
public struct SignedVaultHead: Codable, Sendable, Equatable {
    public let head: VaultHead
    public let signature: Data

    public init(head: VaultHead, signature: Data) {
        self.head = head
        self.signature = signature
    }

    public var byteCount: Int {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return (try? encoder.encode(self))?.count ?? 0
    }
}

/// §3.1's watermark record. **It carries the digest**, without which a device
/// that lost its whole store has nothing to anchor a backwards walk on and A-1
/// serves it whatever chain it likes below the watermark.
public struct VaultHeadWatermark: Codable, Sendable, Equatable {
    public let keyGeneration: Int
    public let headSeq: Int
    public let headDigest: String

    public init(keyGeneration: Int, headSeq: Int, headDigest: String) {
        self.keyGeneration = keyGeneration
        self.headSeq = headSeq
        self.headDigest = headDigest
    }

    /// Compared **lexicographically**, strictly, with **no tolerance**.
    /// `AccountClient`'s `ClockWatermark` is a wall clock with a 300-second
    /// tolerance and is cited as an analogy whose tolerance is deliberately not
    /// carried.
    public func admits(keyGeneration: Int, headSeq: Int) -> Bool {
        if keyGeneration != self.keyGeneration { return keyGeneration > self.keyGeneration }
        return headSeq > self.headSeq
    }
}

// MARK: - Signing

public protocol VaultHeadSigning: Sendable {
    var writerDeviceId: String { get }
    func sign(_ preimage: Data) throws -> Data
}

public protocol VaultHeadVerifying: Sendable {
    func verify(_ signature: Data, over preimage: Data) -> Bool
}

/// The Mac's `sig` role — `Curve25519.Signing`, software, the key every
/// read route already uses. Under §5.5's topology **the Mac is the only device
/// that signs a head**: protocol §2.4 pins exactly one pair per ceremony, so
/// phone↔phone is not pinned at all and a design in which phones verify each
/// other's heads has no key to verify with.
public struct VaultHeadSigSigner: VaultHeadSigning {
    public let writerDeviceId: String
    private let key: Curve25519.Signing.PrivateKey

    public init(writerDeviceId: String, key: Curve25519.Signing.PrivateKey) {
        self.writerDeviceId = writerDeviceId
        self.key = key
    }

    public func sign(_ preimage: Data) throws -> Data {
        try key.signature(for: preimage)
    }

    public var verifier: VaultHeadSigVerifier { VaultHeadSigVerifier(key: key.publicKey) }
}

public struct VaultHeadSigVerifier: VaultHeadVerifying {
    private let key: Curve25519.Signing.PublicKey
    public init(key: Curve25519.Signing.PublicKey) { self.key = key }
    public func verify(_ signature: Data, over preimage: Data) -> Bool {
        key.isValidSignature(signature, for: preimage)
    }
}

// MARK: - Admission

public enum VaultHeadRefusal: Error, Equatable, Sendable, LocalizedError {
    /// Not a chain break with the wrong diagnosis — a **named** refusal, in the
    /// shape of §9.3's schema guard.
    case unimplementedFormat(Int)
    case tooLarge(bytes: Int)
    case signatureInvalid
    case lowerKeyGeneration(served: Int, held: Int)
    case headSeqNotStrictlyGreater(served: Int, held: Int)
    case chainBreak(expected: String, served: String)
    case servedFieldDiffersFromSigned(String)
    case emptyDelta

    public var errorDescription: String? {
        switch self {
        case .unimplementedFormat:
            "This vault has been upgraded; update Vaultage on this Mac."
        case .tooLarge(let bytes):
            "A vault head of \(bytes) bytes is larger than this format allows."
        case .signatureInvalid:
            "A vault head did not verify against this vault's sequencer."
        case .lowerKeyGeneration:
            "A vault head arrived at an older key generation and was refused."
        case .headSeqNotStrictlyGreater:
            "A vault head arrived at a sequence this Mac has already passed and was refused."
        case .chainBreak:
            "A vault head does not follow the last head this Mac applied."
        case .servedFieldDiffersFromSigned(let field):
            "A vault head's \(field) does not match the value its sequencer signed."
        case .emptyDelta:
            "A vault head must record a fold, an acknowledgement batch or a generation change."
        }
    }
}

/// **Head admission, and it takes no clock.**
///
/// > Ordering is `(keyGeneration, headSeq)` and the chain. Never time. That is
/// > the whole of head admission, and none of it consults a clock.
///
/// The type is the assertion: there is no `Date`, no `WallClock` and no
/// `MonotonicClock` parameter anywhere below, so the clock-independence tests
/// at 1970, at 2099 and moved backwards mid-run are testing a property the
/// signature already forbids the other way.
public enum VaultHeadAdmission {
    /// `served` is the head as the relay served it; `signedFields` is what the
    /// signature covers. A relay that edits `writtenAt` or `writerDeviceId` in
    /// transit is caught here **and** by the signature, and the two diagnoses
    /// are kept apart so the owner is told the right thing.
    public static func admit(
        _ served: SignedVaultHead,
        accountSubject: String,
        watermark: VaultHeadWatermark?,
        verifier: some VaultHeadVerifying,
        implementedFormats: Set<Int> = [VaultHead.sliceAFormat]
    ) throws {
        let head = served.head
        guard implementedFormats.contains(head.headFormat) else {
            throw VaultHeadRefusal.unimplementedFormat(head.headFormat)
        }
        let bytes = served.byteCount
        guard bytes <= VaultHead.maximumBytes else { throw VaultHeadRefusal.tooLarge(bytes: bytes) }
        guard verifier.verify(served.signature, over: head.preimage(accountSubject: accountSubject)) else {
            throw VaultHeadRefusal.signatureInvalid
        }
        if let watermark {
            guard head.keyGeneration >= watermark.keyGeneration else {
                throw VaultHeadRefusal.lowerKeyGeneration(served: head.keyGeneration, held: watermark.keyGeneration)
            }
            guard watermark.admits(keyGeneration: head.keyGeneration, headSeq: head.headSeq) else {
                throw VaultHeadRefusal.headSeqNotStrictlyGreater(served: head.headSeq, held: watermark.headSeq)
            }
            if head.keyGeneration == watermark.keyGeneration, head.previousHeadDigest != watermark.headDigest {
                throw VaultHeadRefusal.chainBreak(expected: watermark.headDigest, served: head.previousHeadDigest)
            }
        }
    }

    /// A served head whose `writtenAt` or `writerDeviceId` differs from the
    /// signed value. The signature catches it; this names *which* field, so the
    /// owner is told the right thing rather than "chain break".
    public static func servedMatchesSigned(
        served: SignedVaultHead,
        signedWrittenAt: Int,
        signedWriterDeviceId: String
    ) throws {
        guard served.head.writtenAt == signedWrittenAt else {
            throw VaultHeadRefusal.servedFieldDiffersFromSigned("writtenAt")
        }
        guard served.head.writerDeviceId == signedWriterDeviceId else {
            throw VaultHeadRefusal.servedFieldDiffersFromSigned("writerDeviceId")
        }
    }
}

// MARK: - The writer

/// What caused a head. **No head is written with an empty delta** — a head
/// records a fold, an acknowledgement batch or a generation change — because
/// §3.3's one-per-`ε` rate limit is a floor on spacing, not a licence to write
/// 86,400 empty heads a day into every paired device's non-purgeable container.
public struct VaultHeadDelta: Sendable, Equatable {
    public let foldedRecords: Int
    public let acknowledgements: Int
    public let generationChanged: Bool

    public init(foldedRecords: Int = 0, acknowledgements: Int = 0, generationChanged: Bool = false) {
        self.foldedRecords = foldedRecords
        self.acknowledgements = acknowledgements
        self.generationChanged = generationChanged
    }

    public var isEmpty: Bool { foldedRecords == 0 && acknowledgements == 0 && !generationChanged }
}

/// The sequencer's head writer.
///
/// **The writer's rule survives, for the display's sake:**
/// `writtenAt = max(localNow, previousWrittenAt + max(ε, monotonicElapsedSinceLastHead))`
/// with **`ε` applied only when the real elapsed time is itself below `ε`**
/// (eighth pass, DB8-M2) — version 9's unconditional `max(ε, …)` let a
/// sequencer writing a hundred heads a second advance the displayed clock at a
/// hundred times real time. Head writes are rate-limited to at most one per `ε`.
public actor VaultHeadWriter {
    /// §3.3's `ε`, one second.
    public static let epsilon: TimeInterval = 1

    private let accountSubject: String
    private let signer: any VaultHeadSigning
    private let wallClock: any WallClock
    private let monotonic: any MonotonicClock
    private var lastWrittenAt: [UUID: Int] = [:]
    private var lastWriteUptime: [UUID: TimeInterval] = [:]

    public init(
        accountSubject: String,
        signer: any VaultHeadSigning,
        wallClock: any WallClock = SystemWallClock(),
        monotonic: any MonotonicClock = SystemMonotonicClock()
    ) {
        self.accountSubject = accountSubject
        self.signer = signer
        self.wallClock = wallClock
        self.monotonic = monotonic
    }

    public enum WriteRefusal: Error, Equatable, Sendable {
        case emptyDelta
        case rateLimited(sinceLastHead: TimeInterval)
    }

    public func write(
        vaultID: UUID,
        keyGeneration: Int,
        headSeq: Int,
        previousHeadDigest: String,
        digest: String,
        acks: [VaultHeadAck],
        delta: VaultHeadDelta
    ) throws -> SignedVaultHead {
        guard !delta.isEmpty else { throw WriteRefusal.emptyDelta }
        let uptime = monotonic.uptime
        let elapsed = lastWriteUptime[vaultID].map { max(0, uptime - $0) }
        if let elapsed, elapsed < Self.epsilon {
            throw WriteRefusal.rateLimited(sinceLastHead: elapsed)
        }
        let localNow = Int(wallClock.now.timeIntervalSince1970)
        let writtenAt: Int
        if let previous = lastWrittenAt[vaultID] {
            // `ε` applies **only** when the real elapsed time is itself below
            // `ε`; otherwise the real elapsed time is the term, so a hundred
            // heads an hour advance the display by an hour and not by a hundred
            // seconds.
            let term = max(Self.epsilon, elapsed ?? Self.epsilon)
            writtenAt = max(localNow, previous + Int(term.rounded(.up)))
        } else {
            writtenAt = localNow
        }
        let head = VaultHead(
            vaultID: vaultID,
            keyGeneration: keyGeneration,
            headSeq: headSeq,
            previousHeadDigest: previousHeadDigest,
            digest: digest,
            acks: acks,
            writtenAt: writtenAt,
            writerDeviceId: signer.writerDeviceId
        )
        let signature = try signer.sign(head.preimage(accountSubject: accountSubject))
        lastWrittenAt[vaultID] = writtenAt
        lastWriteUptime[vaultID] = uptime
        return SignedVaultHead(head: head, signature: signature)
    }

    /// The live set's digest: `CanonicalDigest.hex` over the sorted
    /// `(wireID, revision)` pairs. It names **which records** and **at which
    /// revision**, and nothing about their bytes.
    public nonisolated static func liveSetDigest(_ pairs: [(wireID: String, revision: Int)]) -> String {
        let sorted = pairs.sorted { $0.wireID == $1.wireID ? $0.revision < $1.revision : $0.wireID < $1.wireID }
        var fields = ["vaultage.vault.head.live.v1", "\(sorted.count)"]
        for pair in sorted { fields.append(contentsOf: [pair.wireID, "\(pair.revision)"]) }
        return CanonicalDigest.hex(fields)
    }
}

// MARK: - Write certificates

/// §3.3 change 1 — a phone that writes publishes a **write certificate**,
/// signed by its `apv`. The Mac verifies it against the phone's **pinned**
/// thumbprint, checks that `sha256(body)` matches the bytes it was served, and
/// folds the records into the next head.
public struct VaultWriteCertificate: Codable, Sendable, Equatable {
    public let vaultID: UUID
    public let keyGeneration: Int
    public let deviceId: String
    /// **Strictly monotonic per device**, and the Mac keeps that watermark
    /// exactly as it keeps `(keyGeneration, headSeq)`. A certificate whose
    /// `deviceSeq` is not greater than the highest seen from that device is
    /// refused, which is what makes replay of an old certificate fail.
    public let deviceSeq: Int
    public let bodyDigest: String
    public let ackedHeadDigest: String
    public let pairs: [Pair]

    public struct Pair: Codable, Sendable, Equatable {
        public let wireID: String
        public let revision: Int
        public init(wireID: String, revision: Int) {
            self.wireID = wireID
            self.revision = revision
        }
    }

    public init(
        vaultID: UUID,
        keyGeneration: Int,
        deviceId: String,
        deviceSeq: Int,
        bodyDigest: String,
        ackedHeadDigest: String,
        pairs: [Pair]
    ) {
        self.vaultID = vaultID
        self.keyGeneration = keyGeneration
        self.deviceId = deviceId
        self.deviceSeq = deviceSeq
        self.bodyDigest = bodyDigest
        self.ackedHeadDigest = ackedHeadDigest
        self.pairs = pairs
    }

    public static let domain = "vaultage.vault.write.v2"

    /// **`writeCert`'s leading field is `"\(body.count)"`, computed, never a
    /// closed form** — because a closed form is the thing that has now been got
    /// wrong twice. Version 7 wrote the literal `"9"` (no rule); version 8 wrote
    /// `8 + pairs.count`, which is **rule 2's answer in rule 1's slot**.
    ///
    /// The body is flat, so each `(wireID, revision)` pair is **two** encoded
    /// fields and `body.count` evaluates to `8 + 2n`. `pairs.count` — the
    /// group's own **item** count — is **rule 2** and stays as it is.
    public func preimageFields(accountSubject: String) -> [String] {
        var body: [String] = [
            accountSubject,
            vaultID.uuidString.lowercased(),
            "\(keyGeneration)",
            deviceId,
            "\(deviceSeq)",
            bodyDigest,
            ackedHeadDigest,
            "\(pairs.count)"              // RULE 2: the group's ITEM count
        ]
        for pair in pairs {               // …then its items, flat
            body.append(pair.wireID)
            body.append("\(pair.revision)")
        }
        return [VaultWriteCertificate.domain, "\(body.count)"] + body
    }

    public func preimage(accountSubject: String) -> Data {
        CanonicalDigest.encode(preimageFields(accountSubject: accountSubject))
    }

    public static func bodyDigest(of body: Data) -> String {
        SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    }
}

public enum VaultWriteCertificateRefusal: Error, Equatable, Sendable, LocalizedError {
    case unpairedDevice(String)
    case revokedDevice(String)
    case signatureInvalid
    case bodyDigestMismatch
    case deviceSeqReplay(served: Int, highest: Int)

    public var errorDescription: String? {
        switch self {
        case .unpairedDevice: "A write arrived from a device this Mac has not paired with."
        case .revokedDevice: "A write arrived from a device you revoked, and was refused."
        case .signatureInvalid: "A write certificate did not verify against that device's pinned key."
        case .bodyDigestMismatch: "A write certificate does not cover the records it was served with."
        case .deviceSeqReplay: "A write certificate was replayed and was refused."
        }
    }
}

public enum VaultWriteCertificateVerifier {
    /// Verified against the phone's **pinned `apv`** — from the pin record,
    /// never from the roster the control plane serves.
    public static func verify(
        _ certificate: VaultWriteCertificate,
        signature: Data,
        body: Data,
        accountSubject: String,
        in state: VaultageMetadata,
        highestDeviceSeq: Int?
    ) throws {
        if state.everRevokedDeviceIDs.contains(certificate.deviceId) {
            throw VaultWriteCertificateRefusal.revokedDevice(certificate.deviceId)
        }
        guard let pairing = state.devicePairings.first(where: { $0.phoneDeviceID == certificate.deviceId }),
              let key = pairing.apvVerifyingKey
        else { throw VaultWriteCertificateRefusal.unpairedDevice(certificate.deviceId) }
        guard VaultWriteCertificate.bodyDigest(of: body) == certificate.bodyDigest else {
            throw VaultWriteCertificateRefusal.bodyDigestMismatch
        }
        guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              key.isValidSignature(parsed, for: certificate.preimage(accountSubject: accountSubject))
        else { throw VaultWriteCertificateRefusal.signatureInvalid }
        if let highestDeviceSeq, certificate.deviceSeq <= highestDeviceSeq {
            throw VaultWriteCertificateRefusal.deviceSeqReplay(served: certificate.deviceSeq, highest: highestDeviceSeq)
        }
    }
}

// MARK: - The retained chain

/// One retained head: the head, its signature, and **the monotonic instant this
/// device accepted it** — which is what every duration in this design is
/// measured from, so it is part of the record rather than derived.
public struct RetainedHead: Codable, Sendable, Equatable {
    public let signed: SignedVaultHead
    /// Measured once, at acceptance. Re-encoding a head to weigh it makes the
    /// eviction pass quadratic in the chain's length, on a chain whose whole
    /// point is that it can reach a thousand maximal heads.
    public let bytes: Int
    public let acceptedAtMonotonic: TimeInterval
    /// The wall-clock instant of acceptance, kept **only** so the 30-day
    /// horizon can be evaluated across reboots. Nothing decides on it; the byte
    /// budget is the bound that binds and the horizon is the courtesy.
    public let acceptedAtWall: Int

    public init(signed: SignedVaultHead, acceptedAtMonotonic: TimeInterval, acceptedAtWall: Int) {
        self.signed = signed
        self.bytes = signed.byteCount
        self.acceptedAtMonotonic = acceptedAtMonotonic
        self.acceptedAtWall = acceptedAtWall
    }

    public var headSeq: Int { signed.head.headSeq }
    public var byteCount: Int { bytes }
}

/// §3.1's seventh kind: **retained, not synced**.
///
/// Retention is **30 days or 64 MiB per vault, whichever binds first**, priced
/// against the **enforced** one-head-per-`ε` rate — 86,400 a day, 5.4 GiB per
/// vault per day at the 64 KiB cap — rather than against an assumed twenty a
/// day, because A-2's compromised phone can otherwise fill every paired
/// device's disk at will.
///
/// **Eviction and re-acquisition share one `retentionFloor`**, so they cannot
/// chase each other: re-acquisition never requests a head below the floor, and
/// eviction never evicts a head at or above it. A device at the byte budget is
/// therefore **at its retention target**, not below the horizon.
public actor VaultHeadChainStore {
    public static let retentionDays = 30
    public static let retentionBytesPerVault = 64 * 1024 * 1024

    private let container: BrokerContainer
    private let monotonic: any MonotonicClock
    /// The per-vault byte budget in force for this store. It is a parameter for
    /// one reason: a contract has to be able to drive the eviction rule and the
    /// shared floor without writing 64 MiB of chain to a temporary directory,
    /// exactly as `MetadataStore.supportedSchemaVersion` is a parameter so a
    /// refusal test can *be* an older build. **Nothing in the product passes
    /// it**, and the shipped value is asserted against
    /// `retentionBytesPerVault` on its own.
    private let byteBudget: Int

    public init(
        container: BrokerContainer,
        monotonic: any MonotonicClock = SystemMonotonicClock(),
        byteBudget: Int = VaultHeadChainStore.retentionBytesPerVault
    ) {
        self.container = container
        self.monotonic = monotonic
        self.byteBudget = byteBudget
    }

    public nonisolated var root: URL { container.directory(.heads) }

    private nonisolated func file(_ vaultID: UUID) -> URL {
        root.appendingPathComponent("\(vaultID.uuidString.lowercased()).json")
    }

    public struct Chain: Codable, Sendable, Equatable {
        public var heads: [RetainedHead] = []
        public var watermark: VaultHeadWatermark?
        /// The `headSeq` of the oldest head this device **intends** to hold,
        /// set by whichever of the two bounds binds.
        public var retentionFloor: Int = 0
        /// True only for a device that lost heads it did **not** choose to
        /// drop — an OS eviction, a restore, a bug. It **says so on the vault
        /// surface and re-acquires**, and in slice A that is the whole
        /// consequence: there is nothing to finalize (DB11-L1).
        public var belowHorizon: Bool = false

        public init(
            heads: [RetainedHead] = [],
            watermark: VaultHeadWatermark? = nil,
            retentionFloor: Int = 0,
            belowHorizon: Bool = false
        ) {
            self.heads = heads
            self.watermark = watermark
            self.retentionFloor = retentionFloor
            self.belowHorizon = belowHorizon
        }
    }

    public func chain(_ vaultID: UUID) -> Chain {
        guard let data = try? Data(contentsOf: file(vaultID)),
              let chain = try? JSONDecoder().decode(Chain.self, from: data)
        else { return Chain() }
        return chain
    }

    /// Accepts a verified head, stamps this device's own acceptance instant,
    /// advances the watermark and applies the budget.
    @discardableResult
    public func accept(_ signed: SignedVaultHead, accountSubject: String, wallNow: Int) throws -> Chain {
        var chain = self.chain(signed.head.vaultID)
        chain.heads.append(RetainedHead(
            signed: signed,
            acceptedAtMonotonic: monotonic.uptime,
            acceptedAtWall: wallNow
        ))
        chain.watermark = VaultHeadWatermark(
            keyGeneration: signed.head.keyGeneration,
            headSeq: signed.head.headSeq,
            headDigest: signed.head.chainDigest(accountSubject: accountSubject)
        )
        chain.belowHorizon = false
        evict(&chain, wallNow: wallNow)
        try save(chain, vaultID: signed.head.vaultID)
        return chain
    }

    /// **Oldest-first**, at whichever bound binds. Raising the floor is what
    /// makes the eviction/re-acquisition loop unreachable: the device keeps the
    /// heads it *means* to have, so it is at its retention target rather than
    /// below the horizon, and it does not re-fetch what it just dropped.
    private func evict(_ chain: inout Chain, wallNow: Int) {
        let horizon = wallNow - Self.retentionDays * 24 * 60 * 60
        while let oldest = chain.heads.first, chain.heads.count > 1 {
            let overBytes = chain.heads.reduce(0) { $0 + $1.byteCount } > byteBudget
            let overAge = oldest.acceptedAtWall < horizon
            guard overBytes || overAge else { break }
            chain.heads.removeFirst()
            chain.retentionFloor = max(chain.retentionFloor, (chain.heads.first?.headSeq ?? oldest.headSeq))
        }
    }

    /// A device that lost heads it did not choose to drop. It **says so** and
    /// re-acquires **backwards from its watermark, down to the floor and no
    /// further** — walking forward returns nothing a pruned device lacks,
    /// because its deficit is the thirty days **behind** its watermark.
    public func markBelowHorizon(_ vaultID: UUID) throws {
        var chain = self.chain(vaultID)
        chain.belowHorizon = true
        try save(chain, vaultID: vaultID)
    }

    /// The backwards walk. Each head's `previousHeadDigest` anchors the next,
    /// so a withheld or substituted intermediate head is a **break the device
    /// sees** rather than a silent acceptance. The anchor is the watermark
    /// record, and it carries the digest.
    public func reacquireBackwards(
        vaultID: UUID,
        accountSubject: String,
        served: [SignedVaultHead],
        verifier: some VaultHeadVerifying,
        wallNow: Int
    ) throws -> Chain {
        var chain = self.chain(vaultID)
        guard let watermark = chain.watermark else { return chain }
        // **The anchor is what the device already holds, and it holds a
        // digest.** If any head survives, the next one backwards is the one its
        // `previousHeadDigest` names; if the whole store was lost, the anchor is
        // the watermark record's own digest and the served set has to begin
        // with that very head — without which A-1 serves whatever chain it
        // likes below the watermark.
        var expectedDigest = chain.heads.first?.signed.head.previousHeadDigest ?? watermark.headDigest
        let oldestHeld = chain.heads.first?.headSeq
        var accepted: [RetainedHead] = []
        // Newest first: the walk starts at the anchor and goes back.
        for signed in served.sorted(by: { $0.head.headSeq > $1.head.headSeq }) {
            guard signed.head.headSeq >= chain.retentionFloor else { break }
            if let oldestHeld, signed.head.headSeq >= oldestHeld { continue }
            guard signed.head.chainDigest(accountSubject: accountSubject) == expectedDigest else {
                throw VaultHeadRefusal.chainBreak(
                    expected: expectedDigest,
                    served: signed.head.chainDigest(accountSubject: accountSubject)
                )
            }
            guard verifier.verify(signed.signature, over: signed.head.preimage(accountSubject: accountSubject)) else {
                throw VaultHeadRefusal.signatureInvalid
            }
            accepted.append(RetainedHead(signed: signed, acceptedAtMonotonic: monotonic.uptime, acceptedAtWall: wallNow))
            expectedDigest = signed.head.previousHeadDigest
        }
        chain.heads = (accepted.reversed() + chain.heads)
            .reduce(into: [RetainedHead]()) { result, head in
                if !result.contains(where: { $0.headSeq == head.headSeq }) { result.append(head) }
            }
            .sorted { $0.headSeq < $1.headSeq }
        chain.belowHorizon = false
        try save(chain, vaultID: vaultID)
        return chain
    }

    private func save(_ chain: Chain, vaultID: UUID) throws {
        try container.ensure()
        let manager = FileManager.default
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(chain)
        let temporary = root.appendingPathComponent("chain-\(UUID().uuidString).tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw VaultCipherStoreError.storage("Could not create the head chain file.")
        }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try? handle.close()
        _ = try manager.replaceItemAt(file(vaultID), withItemAt: temporary, backupItemName: nil, options: [])
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(vaultID).path)
    }
}

// MARK: - §3.3's freeze fence

/// The persisted, broker-owned accumulator. **It measures monotonic time since
/// the last *successful* head exchange. It is zeroed there and only there;
/// within a window it accumulates and never decreases.**
///
/// `persistedElapsed += max(0, monotonicSinceLastSample)`, sampled on a timer
/// **and at every broker entry**, so a launch-on-demand broker's "24 hours"
/// cannot silently mean "24 hours of broker residency". **A reboot contributes
/// zero, not a reset; a backwards wall clock contributes nothing at all** —
/// version 8's `max(monotonic elapsed, wall delta)` failed in exactly one step,
/// because across a reboot **both** fail together.
public actor VaultFenceAccumulator {
    /// §3.3's three intervals. The only owner-facing control is the
    /// offline-by-design switch, and it turns the *signal* off, never the rule.
    public static let warningInterval: TimeInterval = 6 * 60 * 60
    public static let routingInterval: TimeInterval = 24 * 60 * 60
    public static let unseenPushInterval: TimeInterval = 15 * 60

    public struct State: Codable, Sendable, Equatable {
        public var persistedElapsed: TimeInterval = 0
        public var lastSampleUptime: TimeInterval = 0
        public var unsentChanges: Int = 0
        /// The per-vault switch. It suppresses the warning and the counter and
        /// says so on the Vault surface; it does **not** change what is sealed.
        public var offlineByDesign: Bool = false

        public init(
            persistedElapsed: TimeInterval = 0,
            lastSampleUptime: TimeInterval = 0,
            unsentChanges: Int = 0,
            offlineByDesign: Bool = false
        ) {
            self.persistedElapsed = persistedElapsed
            self.lastSampleUptime = lastSampleUptime
            self.unsentChanges = unsentChanges
            self.offlineByDesign = offlineByDesign
        }
    }

    public enum Stage: String, Sendable, Equatable {
        case current
        case warning
        case routingToUnsentChanges
        /// **The hold takes the warning and lets the routing accrue** (custody
        /// plan version 23 item 4; twentieth pass, DB20-M1; version 20 item 2
        /// and DB17-M3 before it). A refused head is a head that **arrived**, so
        /// the 6-hour warning — a *diagnosis* of silence — is held while a
        /// `headRefusal` marker is live, however long that is, and the vault
        /// shows §7.1's refused-head notice instead. The 24-hour routing is
        /// **not** a message: §3.3 states C-3 as *"nothing is sealed under a
        /// generation this device cannot confirm"*, a refused head is not a
        /// confirmation, and routing is reversible on the next successful
        /// exchange — so it accrues unheld and is correct under either cause.
        /// Version 22 held both, which bought A-1 six hours of sealing at an
        /// unconfirmable generation per vault, repeatable at will, to fix a
        /// sentence. The accumulator therefore never stops; only the warning
        /// stage is replaced while the marker stands.
        case heldByRefusedHead
    }

    private let container: BrokerContainer
    private let monotonic: any MonotonicClock

    public init(container: BrokerContainer, monotonic: any MonotonicClock = SystemMonotonicClock()) {
        self.container = container
        self.monotonic = monotonic
    }

    public nonisolated var root: URL { container.directory(.fence) }

    private nonisolated func file(_ vaultID: UUID) -> URL {
        root.appendingPathComponent("\(vaultID.uuidString.lowercased()).json")
    }

    public func state(_ vaultID: UUID) -> State {
        guard let data = try? Data(contentsOf: file(vaultID)),
              let state = try? JSONDecoder().decode(State.self, from: data)
        else { return State(persistedElapsed: 0, lastSampleUptime: monotonic.uptime) }
        return state
    }

    /// Sampled on a timer and at every broker entry.
    ///
    /// **The accumulator never stops** (custody plan version 23 item 4). Version
    /// 20 held it while a `headRefusal` marker was live, so that neither
    /// interval accrued under a refused head; version 23 splits the hold —
    /// the warning is held at `stage`, the routing accrues — and the
    /// accumulator is one thing measured one way: monotonic time since the
    /// last successful head exchange, under a marker or not.
    @discardableResult
    public func sample(_ vaultID: UUID) throws -> State {
        var state = self.state(vaultID)
        let uptime = monotonic.uptime
        // A reboot makes `uptime` smaller than the last sample. `max(0, …)`
        // contributes **zero** — not a reset, and not a finalization.
        state.persistedElapsed += max(0, uptime - state.lastSampleUptime)
        state.lastSampleUptime = uptime
        try save(state, vaultID: vaultID)
        return state
    }

    /// **The one thing that zeroes it.** Version 9's text said "accumulates and
    /// never decreases" twice and never said what zeroes it, which read as
    /// written puts every device permanently into the unsent-changes path.
    @discardableResult
    public func recordSuccessfulHeadExchange(_ vaultID: UUID) throws -> State {
        var state = self.state(vaultID)
        state.persistedElapsed = 0
        state.lastSampleUptime = monotonic.uptime
        try save(state, vaultID: vaultID)
        return state
    }

    public func setOfflineByDesign(_ on: Bool, vaultID: UUID) throws {
        var state = self.state(vaultID)
        state.offlineByDesign = on
        try save(state, vaultID: vaultID)
    }

    /// **The fence routes writes; it does not refuse them** (second pass,
    /// DB2-H8). Version 2 fenced a stale device into read-only, which converts
    /// a Vaultage outage past 24 hours into a fleet-wide write freeze and
    /// blocks the very rotation §5.3 tells an owner to perform after a
    /// revocation.
    public func stage(_ vaultID: UUID) throws -> Stage {
        let state = try sample(vaultID)
        // **The routing is C-3 and accrues unheld** (custody plan version 23
        // item 4): it is evaluated first, so a live marker cannot defer it.
        if state.persistedElapsed >= Self.routingInterval { return .routingToUnsentChanges }
        // **The warning is held, not tripped** (DB17-M3; DB20-M1). A refused
        // head is a head that arrived, so the diagnosis of silence is replaced
        // by §7.1's refused-head notice for as long as the marker stands.
        if VaultHeadRefusalStore.isHoldingARefusal(container: container, vaultID: vaultID) {
            return .heldByRefusedHead
        }
        if state.persistedElapsed >= Self.warningInterval { return .warning }
        return .current
    }

    /// An accepted write while the fence routes: it is **accepted into the
    /// local unsent-changes store** rather than sealed for sync. Rotation is
    /// allowed under the fence, so the remediation §5.3 demands is never
    /// blocked by the control §5.3's own revocation triggered.
    @discardableResult
    public func queueUnsentChange(_ vaultID: UUID) throws -> State {
        var state = try sample(vaultID)
        state.unsentChanges += 1
        try save(state, vaultID: vaultID)
        return state
    }

    private func save(_ state: State, vaultID: UUID) throws {
        try container.ensure()
        let manager = FileManager.default
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(state)
        let temporary = root.appendingPathComponent("fence-\(UUID().uuidString).tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw VaultCipherStoreError.storage("Could not create the fence accumulator file.")
        }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try? handle.close()
        _ = try manager.replaceItemAt(file(vaultID), withItemAt: temporary, backupItemName: nil, options: [])
        try? manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(vaultID).path)
    }
}
