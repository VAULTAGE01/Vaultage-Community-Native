import CryptoKit
import Foundation

// BL-100 slice A — **the Mac's half of BL-102's sixteen routes.**
//
// Normative: `blueprint/13-MULTI-DEVICE-CUSTODY.md` **version 21** (§3.1's
// bounds, §3.2's envelope and `wireID`, §3.3's chain and its compare-and-swap,
// §7.1's transfer stage and its paging rules, §8's blob rule) and the wire
// contract in the control plane's `docs/vault-sync.md`, which is what
// `src/vault-sync.ts` actually answers. **Custody plan version 22 had not
// merged when this was built**; the one thing it is expected to move — the
// membership map, out of the `vault` record's plaintext and into index page
// records — is invisible here by construction, and §"A record kind is opaque"
// below says why.
//
// ## What this file is, and what it deliberately is not
//
// It is a **transport**: it builds a request, signs it with the device session's
// own proof, parses a bounded answer and hands the bytes on. It decides nothing
// about what those bytes mean.
//
//  - **It opens nothing.** No key, no presence, no plaintext. Every ciphertext
//    on either side of it is a base64url string it copies.
//  - **It verifies no head.** `VaultHeadAdmission` does that, from the
//    **signed preimage**, inside `VaultSyncApply.transfer`. What this file does
//    is rebuild the head *from that preimage* rather than from the relay's index
//    columns — because §3.3's relay *"trusts no digest"* and a device that
//    rebuilt from the columns would be trusting exactly what the design says it
//    may not.
//  - **It stores nothing.** `VaultCipherStore` and `VaultHeadChainStore` are
//    reached through `VaultSyncApply`, and only after transfer has admitted a
//    head.
//
// ## A record kind is opaque to it
//
// `recordKind` is a **byte the caller supplies and this file copies**. It is
// never compared, never switched on, never sorted by and never mapped to a
// `VaultRecordKind`: `VaultSealedRecord` carries no kind at all (§3.2 — *"the
// header is value-free and kind-free"*), so the pairing is made by whoever is
// pushing and is carried through unexamined, exactly as the relay carries it.
// That is what makes this transport survive version 22: a head names whatever
// records it names, an index page record is a record like any other, and nothing
// here has a branch that a new kind could fall off.
//
// `VaultSyncContracts` asserts it as a property of the **source** and not only
// of the behaviour, the way BL-102's own suite asserts the relay's half.

// MARK: - Refusals

/// **Every refusal code `docs/vault-sync.md` names, as a case of its own.**
///
/// Twenty-four named codes, one shape family and three failures that are this
/// device's rather than the relay's. A `4xx` body from a vault route is
/// `{"error": "<code>"}` and nothing else, and **the body is never logged, never
/// rendered and never carried into an owner string** — what crosses is the case,
/// which is a value this Mac chose from a compiled list.
public enum VaultSyncRefusal: Error, Equatable, Sendable, LocalizedError {
    // The credential boundary.
    case apiTokenNotAccepted
    case deviceSessionNotAccepted
    case deviceKindNotPermitted
    case deviceRevoked
    case rateLimited

    // Bound 1, the record ceiling and §3.2's buckets.
    case transferRecordCountExceeded
    case transferByteCountExceeded
    case recordTooLarge
    case invalidSizeBucket

    // Bound 2 and bound 3.
    case vaultRecordLimitExceeded
    case vaultByteLimitExceeded
    case deviceRecordWindowExceeded

    // §3.3's compare-and-swap. **Both carry the current head**, re-fetched once,
    // because a caller that cannot see what it lost cannot do anything but retry
    // blindly — which is the one thing this transport will not do.
    case headChainConflict(current: VaultSyncServedHead?)
    case headNotSuccessor(current: VaultSyncServedHead?)

    // The push's shape rules.
    case duplicateWireID
    case recordGenerationMismatch

    // §3.3 change 3's liveness.
    case ackNotSuccessor

    // §6.1's recovery envelope, off by default on the deployed service.
    case recoveryEnvelopeDisabled
    case recoveryEnvelopeNotFound
    case recoveryEnvelopeNotSuccessor

    // §8's blobs.
    case blobStoreUnavailable
    case blobNotFound
    case blobTombstoned

    case requestTooLarge

    /// `invalid_json`, `invalid_<field>`, `<field>_too_large`, `<field>_too_many`
    /// — the shape family, carried as **the code and nothing from the body**.
    case malformedRequest(code: String)

    /// A status or a code this table does not name. The code is carried for the
    /// same reason `malformedRequest` carries one and under the same rule.
    case unrecognized(status: Int, code: String?)

    /// The answer did not parse, was over this transport's own cap, or
    /// contradicted itself — a served head whose index columns disagree with its
    /// own signed body, a page whose `servedBytesDigest` is not the digest of
    /// what it served.
    case malformedAnswer(String)

    /// The session, the proof or the origin. Raised by `DeviceAccountClient`
    /// before a vault route is reached and translated here so no
    /// `AccountClientError` escapes this surface.
    case sessionRejected

    /// The transport itself. **Never an approval failure and never a vault
    /// failure**: a Mac that cannot reach its relay has unsent changes, which is
    /// §3.3's fence's business and not this file's.
    case transportUnavailable

    /// The twenty-four codes, in `docs/vault-sync.md`'s own order. Asserted
    /// against that table by the contracts, so a code the service gains and this
    /// table does not is a failing test rather than an `unrecognized`.
    public static let namedCodes: [String] = [
        "api_token_not_accepted", "device_session_not_accepted", "device_kind_not_permitted",
        "device_revoked", "rate_limited", "transfer_record_count_exceeded",
        "transfer_byte_count_exceeded", "record_too_large", "invalid_size_bucket",
        "vault_record_limit_exceeded", "vault_byte_limit_exceeded", "device_record_window_exceeded",
        "head_chain_conflict", "head_not_successor", "duplicate_wire_id",
        "record_generation_mismatch", "ack_not_successor", "recovery_envelope_disabled",
        "recovery_envelope_not_found", "recovery_envelope_not_successor",
        "blob_store_unavailable", "blob_not_found", "blob_tombstoned", "request_too_large",
    ]

    /// The code → case map, with the two compare-and-swap cases left to the
    /// caller that can re-fetch the head.
    static func named(_ code: String) -> VaultSyncRefusal? {
        switch code {
        case "api_token_not_accepted": .apiTokenNotAccepted
        case "device_session_not_accepted": .deviceSessionNotAccepted
        case "device_kind_not_permitted": .deviceKindNotPermitted
        case "device_revoked": .deviceRevoked
        case "rate_limited": .rateLimited
        case "transfer_record_count_exceeded": .transferRecordCountExceeded
        case "transfer_byte_count_exceeded": .transferByteCountExceeded
        case "record_too_large": .recordTooLarge
        case "invalid_size_bucket": .invalidSizeBucket
        case "vault_record_limit_exceeded": .vaultRecordLimitExceeded
        case "vault_byte_limit_exceeded": .vaultByteLimitExceeded
        case "device_record_window_exceeded": .deviceRecordWindowExceeded
        case "head_chain_conflict": .headChainConflict(current: nil)
        case "head_not_successor": .headNotSuccessor(current: nil)
        case "duplicate_wire_id": .duplicateWireID
        case "record_generation_mismatch": .recordGenerationMismatch
        case "ack_not_successor": .ackNotSuccessor
        case "recovery_envelope_disabled": .recoveryEnvelopeDisabled
        case "recovery_envelope_not_found": .recoveryEnvelopeNotFound
        case "recovery_envelope_not_successor": .recoveryEnvelopeNotSuccessor
        case "blob_store_unavailable": .blobStoreUnavailable
        case "blob_not_found": .blobNotFound
        case "blob_tombstoned": .blobTombstoned
        case "request_too_large": .requestTooLarge
        default: nil
        }
    }

    /// **Diagnostics, and no owner surface renders one.** §7.1's owner strings
    /// are `VaultRefusalNotice`'s and are composed from a `reason`, not from an
    /// error's description — the same separation `VaultTransferRefusal` makes
    /// (custody plan version 21, eighteenth pass DB18-M3). Nothing below carries
    /// a response body, a `wireID`, a digest or a ciphertext length.
    public var errorDescription: String? {
        switch self {
        case .apiTokenNotAccepted: "A vault route refused an API token."
        case .deviceSessionNotAccepted: "A vault route refused this device session."
        case .deviceKindNotPermitted: "A vault route refused this device kind."
        case .deviceRevoked: "This device is on the account's revocation list."
        case .rateLimited: "A vault route's own budget refused this request."
        case .transferRecordCountExceeded: "A transfer carried more records than bound 1 admits."
        case .transferByteCountExceeded: "A transfer carried more bytes than bound 1 admits."
        case .recordTooLarge: "A record is over the ceiling for a record stored in the relay's rows."
        case .invalidSizeBucket: "A sealed length is not one of the record format's buckets."
        case .vaultRecordLimitExceeded: "This vault is at bound 2's record cap."
        case .vaultByteLimitExceeded: "This vault is at bound 2's byte cap."
        case .deviceRecordWindowExceeded: "This device is at bound 3's sliding window."
        case .headChainConflict: "The head this push names is not the relay's current head."
        case .headNotSuccessor: "The head this push carries does not advance the watermark."
        case .duplicateWireID: "One transfer named a record twice."
        case .recordGenerationMismatch: "A record's generation is not the head's."
        case .ackNotSuccessor: "An acknowledgement did not advance."
        case .recoveryEnvelopeDisabled: "The recovery envelope is off on this service."
        case .recoveryEnvelopeNotFound: "This vault has no live recovery envelope."
        case .recoveryEnvelopeNotSuccessor: "A recovery envelope was put at a lower generation."
        case .blobStoreUnavailable: "The relay has no blob store bound."
        case .blobNotFound: "The relay does not hold this blob."
        case .blobTombstoned: "This blob is tombstoned and inside its grace."
        case .requestTooLarge: "A request body was over the route's cap."
        case .malformedRequest(let code): "A vault route refused the request's shape (\(code))."
        case .unrecognized(let status, _): "A vault route answered \(status), which this build does not name."
        case .malformedAnswer(let what): "A vault route's answer was not usable: \(what)."
        case .sessionRejected: "This Mac's account session was refused."
        case .transportUnavailable: "This Mac could not reach its relay."
        }
    }
}

// MARK: - The wire shapes

/// §3.1's bounds as this transport reads them. **Every number is BL-102's own**,
/// and the two this file needs are bound 1's, because bound 1 is the only one a
/// client can evaluate before it sends.
public enum VaultSyncBounds {
    /// Bound 1, per transfer: 1,024 records **and** 16 MiB of sealed bytes,
    /// pushed and served (§3.1; DB17-C2 makes it per transfer rather than per
    /// head).
    public static let maximumRecordsPerTransfer = 1024
    public static let maximumTransferBytes = 16 * 1024 * 1024
    /// The forward chain walk's page, from `docs/vault-sync.md`.
    public static let maximumHeadsPerPage = 256
    /// §3.3: a head over 64 KiB is refused and **never split**.
    public static let maximumHeadBytes = 64 * 1024
    /// §3.1's `maximumSealedRecordBytes`, the blob route's ceiling.
    public static let maximumSealedRecordBytes = 10 * 1024 * 1024 + 64 * 1024

    /// **This transport's own cap on an answer it will parse**, sized to the
    /// largest legal serve: bound 1's 16 MiB of sealed bytes is 4/3 of that as
    /// base64url, plus 1,024 records' framing, plus the head and the vault
    /// facts. It is the receiving mirror of `HEAD_PUSH_BODY_MAX_BYTES`, and it
    /// exists so a relay cannot make this Mac parse an unbounded body.
    public static let maximumAnswerBytes = 24 * 1024 * 1024
}

/// One record on the wire. **`recordKind` is opaque** — see the file header.
public struct VaultSyncRecordEnvelope: Codable, Sendable, Equatable {
    public let wireId: String
    public let recordKind: Int
    public let keyGeneration: Int
    public let revision: Int
    /// base64url of the sealed bytes, verbatim.
    public let ciphertext: String

    public init(wireId: String, recordKind: Int, keyGeneration: Int, revision: Int, ciphertext: String) {
        self.wireId = wireId
        self.recordKind = recordKind
        self.keyGeneration = keyGeneration
        self.revision = revision
        self.ciphertext = ciphertext
    }

    /// The one construction, from a sealed record and a caller-supplied byte.
    /// The byte's **range** is checked because the relay's `recordKindField`
    /// checks it and a refusal at the far end is a round trip wasted; its
    /// **meaning** is not checked, because this file has none.
    public init(_ record: VaultSealedRecord, recordKind: Int) throws {
        guard VaultWireID.isWellFormed(record.wireID) else {
            throw VaultSyncRefusal.malformedAnswer("a record's wireID is not 128 bits of lowercase hex")
        }
        guard (0 ... 255).contains(recordKind) else {
            throw VaultSyncRefusal.malformedAnswer("a record kind is not a byte")
        }
        self.init(
            wireId: record.wireID,
            recordKind: recordKind,
            keyGeneration: record.keyGeneration,
            revision: record.revision,
            ciphertext: RemoteBase64URL.encode(record.sealed)
        )
    }
}

/// One record as the relay serves it. `etag` and `byteLength` are the relay's
/// own and are carried so the served-bytes digest can be recomputed from exactly
/// what arrived.
public struct VaultSyncServedRecord: Codable, Sendable, Equatable {
    public let wireId: String
    public let recordKind: Int
    public let keyGeneration: Int
    public let revision: Int
    public let etag: String
    public let byteLength: Int
    public let ciphertext: String

    public init(wireId: String, recordKind: Int, keyGeneration: Int, revision: Int, etag: String, byteLength: Int, ciphertext: String) {
        self.wireId = wireId
        self.recordKind = recordKind
        self.keyGeneration = keyGeneration
        self.revision = revision
        self.etag = etag
        self.byteLength = byteLength
        self.ciphertext = ciphertext
    }

    /// The sealed record this device stores. **The kind does not come with it**,
    /// because `VaultSealedRecord` has none: whoever opens it resolves the
    /// subject from the membership map, which is §3.2's whole point.
    public func sealedRecord() throws -> VaultSealedRecord {
        guard VaultWireID.isWellFormed(wireId) else {
            throw VaultSyncRefusal.malformedAnswer("a served record's wireID is not 128 bits of lowercase hex")
        }
        guard let sealed = RemoteBase64URL.decode(ciphertext), !sealed.isEmpty else {
            throw VaultSyncRefusal.malformedAnswer("a served record's ciphertext is not base64url")
        }
        guard sealed.count == byteLength else {
            throw VaultSyncRefusal.malformedAnswer("a served record's byteLength is not its ciphertext's length")
        }
        return VaultSealedRecord(wireID: wireId, revision: revision, keyGeneration: keyGeneration, sealed: sealed)
    }
}

/// One wrap row on the wire (§2.3). Opaque here in every field but its shape.
public struct VaultSyncWrapEnvelope: Codable, Sendable, Equatable {
    public let recipientDeviceId: String
    public let wrapId: String
    public let recipientVkxThumbprint: String
    public let ciphertext: String
    public let statementSignature: String

    public init(recipientDeviceId: String, wrapId: String, recipientVkxThumbprint: String, ciphertext: String, statementSignature: String) {
        self.recipientDeviceId = recipientDeviceId
        self.wrapId = wrapId
        self.recipientVkxThumbprint = recipientVkxThumbprint
        self.ciphertext = ciphertext
        self.statementSignature = statementSignature
    }
}

/// A wrap row as the relay serves it. **The relay's copy is a cache and this
/// device's own rows are the authority** (DB2-M3's other half): nothing in this
/// transport writes a served wrap anywhere, it hands them back to its caller.
public struct VaultSyncServedWrap: Codable, Sendable, Equatable {
    public let keyGeneration: Int
    public let recipientDeviceId: String
    public let wrapId: String
    public let recipientVkxThumbprint: String
    public let ciphertext: String
    public let byteLength: Int
    public let statementSignature: String
    public let wrappedAt: Int

    public init(keyGeneration: Int, recipientDeviceId: String, wrapId: String, recipientVkxThumbprint: String, ciphertext: String, byteLength: Int, statementSignature: String, wrappedAt: Int) {
        self.keyGeneration = keyGeneration
        self.recipientDeviceId = recipientDeviceId
        self.wrapId = wrapId
        self.recipientVkxThumbprint = recipientVkxThumbprint
        self.ciphertext = ciphertext
        self.byteLength = byteLength
        self.statementSignature = statementSignature
        self.wrappedAt = wrappedAt
    }
}

/// §3.3 change 3's acknowledgement, as the relay serves one.
public struct VaultSyncAcknowledgement: Codable, Sendable, Equatable {
    public let deviceId: String
    public let ackedKeyGeneration: Int
    public let ackedHeadSeq: Int
    public let ackedHeadDigest: String
    public let ackedAt: Int
    public let signature: String

    public init(deviceId: String, ackedKeyGeneration: Int, ackedHeadSeq: Int, ackedHeadDigest: String, ackedAt: Int, signature: String) {
        self.deviceId = deviceId
        self.ackedKeyGeneration = ackedKeyGeneration
        self.ackedHeadSeq = ackedHeadSeq
        self.ackedHeadDigest = ackedHeadDigest
        self.ackedAt = ackedAt
        self.signature = signature
    }
}

/// Bound 2's two counts and their limits, as the relay reports them. **Read for
/// display and for nothing else**: what refuses a fold for size is
/// `VaultSyncApply.transfer`, over this device's own store.
public struct VaultSyncVaultFacts: Codable, Sendable, Equatable {
    public struct Limits: Codable, Sendable, Equatable {
        public let maxRecords: Int
        public let maxBytes: Int

        public init(maxRecords: Int, maxBytes: Int) {
            self.maxRecords = maxRecords
            self.maxBytes = maxBytes
        }
    }

    public let recordCount: Int
    public let byteCount: Int
    public let limits: Limits

    public init(recordCount: Int, byteCount: Int, limits: Limits) {
        self.recordCount = recordCount
        self.byteCount = byteCount
        self.limits = limits
    }
}

/// A head as the relay serves it: the index columns, the **signed preimage
/// verbatim**, and the signature over it.
public struct VaultSyncServedHead: Codable, Sendable, Equatable {
    public let keyGeneration: Int
    public let headSeq: Int
    public let previousHeadDigest: String
    public let digest: String
    public let acks: String
    public let headBody: String
    public let signature: String
    public let writerDeviceId: String
    public let storedAt: Int

    /// Public because a **served** head is data, not authority: `signedHead`
    /// below is the only thing that turns one into something this device will
    /// act on, and it reads the signed body rather than any of these fields.
    /// A contract that could not build a head with a lying column could not
    /// drive the refusal that catches one.
    public init(keyGeneration: Int, headSeq: Int, previousHeadDigest: String, digest: String, acks: String, headBody: String, signature: String, writerDeviceId: String, storedAt: Int) {
        self.keyGeneration = keyGeneration
        self.headSeq = headSeq
        self.previousHeadDigest = previousHeadDigest
        self.digest = digest
        self.acks = acks
        self.headBody = headBody
        self.signature = signature
        self.writerDeviceId = writerDeviceId
        self.storedAt = storedAt
    }

    /// **Rebuilt from `headBody`, and cross-checked against the columns.**
    ///
    /// The relay *"trusts no digest"* and neither does this: `keyGeneration`,
    /// `headSeq`, `previousHeadDigest` and `digest` are link labels the relay
    /// orders its table by, and the authority is the body the signature covers.
    /// So the head is built from the body's own field list, and a column that
    /// disagrees with it is `malformedAnswer` — *"a client whose columns
    /// disagree with its own signed `headBody` fools this table and no device"*,
    /// stated from the device's side.
    ///
    /// `accountSubject` is **this device's**, never the wire's. It is a field of
    /// the preimage, so a relay that served another account's head produces a
    /// field list this Mac cannot match and the head is refused here rather than
    /// at the signature check.
    public func signedHead(accountSubject: String, vaultID: UUID) throws -> SignedVaultHead {
        guard let body = RemoteBase64URL.decode(headBody), body.count <= VaultSyncBounds.maximumHeadBytes else {
            throw VaultSyncRefusal.malformedAnswer("a served head's body is not base64url under 64 KiB")
        }
        let acknowledgements = try decodedAcks()
        // The rebuild — and the reproduction of the served bytes it ends with —
        // are `VaultHead.rebuilt`'s, beside the encoder they invert.
        guard let head = VaultHead.rebuilt(
            fromPreimage: body, accountSubject: accountSubject, vaultID: vaultID, acks: acknowledgements
        ) else {
            throw VaultSyncRefusal.malformedAnswer("a served head's signed body is not this account's format-1 head")
        }
        // **And the columns are checked against it.** They are the relay's
        // index; the body is the authority; a disagreement is the relay's table
        // fooled and this device not.
        //
        // `digest` is **not** a field of the body — the body's own `digest` is
        // §3.3's live-set digest, over `(wireID, revision)` pairs, and the
        // column is the chain label the *next* head's `previousHeadDigest`
        // names, which is `CanonicalDigest.hex` over this body. Two different
        // quantities with one name, so the column is checked against what it
        // actually is: the digest of the bytes served.
        guard head.keyGeneration == keyGeneration, head.headSeq == headSeq,
              head.previousHeadDigest == previousHeadDigest,
              head.chainDigest(accountSubject: accountSubject) == digest
        else {
            throw VaultSyncRefusal.malformedAnswer("a served head's columns disagree with its own signed body")
        }
        guard let signatureBytes = RemoteBase64URL.decode(signature) else {
            throw VaultSyncRefusal.malformedAnswer("a served head's signature is not base64url")
        }
        return head.signed(signatureBytes)
    }

    func decodedAcks() throws -> [VaultHeadAck] {
        guard let bytes = RemoteBase64URL.decode(acks), bytes.count <= VaultSyncBounds.maximumHeadBytes else {
            throw VaultSyncRefusal.malformedAnswer("a served head's acks are not base64url under 64 KiB")
        }
        guard let decoded = try? JSONDecoder().decode([VaultHeadAck].self, from: bytes) else {
            throw VaultSyncRefusal.malformedAnswer("a served head's acks are not this format's acks")
        }
        return decoded
    }
}

/// `GET /api/vaults/:id/head`'s answer. **A vault with no head is `head: nil`
/// and a successful exchange**, which is what zeroes §3.3's fence — never a
/// `404`.
public struct VaultSyncHeadFacts: Sendable, Equatable {
    public let head: VaultSyncServedHead?
    public let acknowledgements: [VaultSyncAcknowledgement]
    public let vault: VaultSyncVaultFacts
    public let exchangedAt: Int

    public init(head: VaultSyncServedHead?, acknowledgements: [VaultSyncAcknowledgement], vault: VaultSyncVaultFacts, exchangedAt: Int) {
        self.head = head
        self.acknowledgements = acknowledgements
        self.vault = vault
        self.exchangedAt = exchangedAt
    }
}

/// The chain, walked **forward** from a named digest.
public struct VaultSyncChainPage: Sendable, Equatable {
    public struct Coordinates: Codable, Sendable, Equatable {
        public let keyGeneration: Int
        public let headSeq: Int
        public let digest: String

        public init(keyGeneration: Int, headSeq: Int, digest: String) {
            self.keyGeneration = keyGeneration
            self.headSeq = headSeq
            self.digest = digest
        }
    }

    public let from: String
    public let heads: [VaultSyncServedHead]
    /// The page ended at its own bound. **Not a gap**: the caller walks again
    /// from the last digest it received.
    public let truncated: Bool
    /// The chain ends somewhere that is not the current head.
    public let gap: Bool
    public let gapAfterDigest: String?
    public let currentHead: Coordinates?

    public init(from: String, heads: [VaultSyncServedHead], truncated: Bool, gap: Bool, gapAfterDigest: String?, currentHead: Coordinates?) {
        self.from = from
        self.heads = heads
        self.truncated = truncated
        self.gap = gap
        self.gapAfterDigest = gapAfterDigest
        self.currentHead = currentHead
    }
}

/// A forward page over the live set, for a device that does not yet know the
/// names — a kit restore (§6.2a) or a fresh pairing (§5.1).
public struct VaultSyncRecordPage: Sendable, Equatable {
    public let keyGeneration: Int
    public let records: [VaultSyncServedRecord]
    public let servedRecordCount: Int
    public let servedByteCount: Int
    public let servedBytesDigest: String
    public let complete: Bool
    public let nextAfter: String?
    public let vault: VaultSyncVaultFacts

    public init(keyGeneration: Int, records: [VaultSyncServedRecord], servedRecordCount: Int, servedByteCount: Int, servedBytesDigest: String, complete: Bool, nextAfter: String?, vault: VaultSyncVaultFacts) {
        self.keyGeneration = keyGeneration
        self.records = records
        self.servedRecordCount = servedRecordCount
        self.servedByteCount = servedByteCount
        self.servedBytesDigest = servedBytesDigest
        self.complete = complete
        self.nextAfter = nextAfter
        self.vault = vault
    }
}

/// **The by-`wireID` selector's three facts**, kept apart exactly as the relay
/// keeps them apart: `missing` is *the relay does not hold it*, `deferred` is
/// *bound 1 cut the page*. DB17-H2 is about that difference, and a caller that
/// merged them would be back to a device that cannot tell a withheld record from
/// a slow one.
public struct VaultSyncNamedRecords: Sendable, Equatable {
    public let keyGeneration: Int
    public let records: [VaultSyncServedRecord]
    public let missing: [String]
    public let deferred: [String]
    public let servedRecordCount: Int
    public let servedByteCount: Int
    public let servedBytesDigest: String

    public init(keyGeneration: Int, records: [VaultSyncServedRecord], missing: [String], deferred: [String], servedRecordCount: Int, servedByteCount: Int, servedBytesDigest: String) {
        self.keyGeneration = keyGeneration
        self.records = records
        self.missing = missing
        self.deferred = deferred
        self.servedRecordCount = servedRecordCount
        self.servedByteCount = servedByteCount
        self.servedBytesDigest = servedBytesDigest
    }
}

/// What a push did. `retried` is the relay's own word for *a head I already
/// hold, same coordinates and same digest* — the idempotent answer that keeps a
/// device which lost its reply from being wedged.
public struct VaultSyncPushPageOutcome: Sendable, Equatable {
    public let index: Int
    public let recordCount: Int
    public let byteCount: Int
    public let wrapCount: Int
    public let retried: Bool

    public init(index: Int, recordCount: Int, byteCount: Int, wrapCount: Int, retried: Bool) {
        self.index = index
        self.recordCount = recordCount
        self.byteCount = byteCount
        self.wrapCount = wrapCount
        self.retried = retried
    }
}

public struct VaultSyncPushOutcome: Sendable, Equatable {
    public let digest: String
    public let keyGeneration: Int
    public let headSeq: Int
    /// One entry per page, **in the order they were sent**, which is the order
    /// their indices run.
    public let pages: [VaultSyncPushPageOutcome]
    public let vault: VaultSyncVaultFacts

    public init(digest: String, keyGeneration: Int, headSeq: Int, pages: [VaultSyncPushPageOutcome], vault: VaultSyncVaultFacts) {
        self.digest = digest
        self.keyGeneration = keyGeneration
        self.headSeq = headSeq
        self.pages = pages
        self.vault = vault
    }

    public var recordCount: Int { pages.reduce(0) { $0 + $1.recordCount } }
    public var pageCount: Int { pages.count }
}

/// §6.1's kit envelope, as the relay serves the one live row.
public struct VaultSyncRecoveryEnvelope: Codable, Sendable, Equatable {
    public let keyGeneration: Int
    public let envelope: String
    public let byteLength: Int
    public let createdAt: Int

    public init(keyGeneration: Int, envelope: String, byteLength: Int, createdAt: Int) {
        self.keyGeneration = keyGeneration
        self.envelope = envelope
        self.byteLength = byteLength
        self.createdAt = createdAt
    }
}

// MARK: - The served-bytes digest

/// **The relay's transport checksum, recomputed here from what arrived.**
///
/// Its construction is `docs/vault-sync.md`'s, reproduced field for field. It is
/// *not* one of §3.2's signed preimages, it takes neither of §3.2's counting
/// rules — `<count>` is a number of records, not a field count — and **it
/// decides nothing**: what decides what a device accepts is the head's own
/// signed `digest` over `(wireID, revision)` pairs, checked in
/// `VaultSyncApply.apply`.
///
/// What it is for is the line after: version 20's DB17-H1 keys a head refusal on
/// `(head digest, served byte digest)`, so an honest re-serve of a refused head
/// is a different byte digest and is fetched rather than refused from disk. The
/// relay offers its copy so the wire can be cross-checked **before** anything is
/// computed; this Mac computes its own on the next line and trusts the relay's
/// for nothing.
public enum VaultSyncServedBytes {
    public static let domain = "vaultage.vault.served.v1"

    public static func digest(_ records: [VaultSyncServedRecord]) -> String {
        var lines: [String] = [domain, "\(records.count)"]
        for record in records {
            lines.append(record.wireId)
            lines.append("\(record.recordKind)")
            lines.append("\(record.keyGeneration)")
            lines.append("\(record.revision)")
            lines.append("\(record.byteLength)")
            lines.append(record.ciphertext)
        }
        let joined = Data(lines.joined(separator: "\n").utf8)
        return SHA256.hash(data: joined).map { String(format: "%02x", $0) }.joined()
    }

    /// **Over pages, in index order.** The per-page digests above are the
    /// relay's cross-check; this is the quantity §10's `headRefusals/` row is
    /// keyed on, and `VaultHeadRefusalMarker.servedDigest(pages:)` is the form
    /// the store holds. Both are computed over the same pages in the same order
    /// and neither is derived from the other, so a relay that re-orders a
    /// sequence moves both.
    public static func digest(pages: [Int: [VaultSyncServedRecord]]) -> String {
        var lines: [String] = ["vaultage.vault.servedsequence.v1", "\(pages.count)"]
        for index in pages.keys.sorted() {
            lines.append("\(index)")
            lines.append(digest(pages[index] ?? []))
        }
        let joined = Data(lines.joined(separator: "\n").utf8)
        return SHA256.hash(data: joined).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - The seam

/// **What the Mac asks of BL-102's service.** One protocol, so the contracts
/// drive a recorded relay and the product drives `DeviceAccountClient` — the
/// shape `RemoteApprovalTransport` already has, and for the same reason.
///
/// Fifteen of the sixteen routes are here. The sixteenth — `DELETE
/// …/blobs/:wireId` — is `deleteBlob`, and §8 item 4 makes it a tombstone rather
/// than a deletion: **nothing in slice A writes a tomb**, so nothing in the
/// product reaches it. It is on the seam because the route exists and a
/// transport that silently lacked it would be a transport whose coverage nobody
/// could check.
public protocol VaultSyncTransport: Sendable {
    // §3.3's push and the two ways it can lose.
    func pushHead(
        vaultID: UUID,
        head: VaultSyncServedHead,
        records: [VaultSyncRecordEnvelope],
        wraps: [VaultSyncWrapEnvelope]
    ) async throws -> VaultSyncPushOutcome

    // The head and the chain.
    func fetchHead(vaultID: UUID) async throws -> VaultSyncHeadFacts
    func walkHeads(vaultID: UUID, from digest: String) async throws -> VaultSyncChainPage

    // Records.
    func pageRecords(vaultID: UUID, generation: Int?, after: String?) async throws -> VaultSyncRecordPage
    func fetchRecords(vaultID: UUID, generation: Int, wireIDs: [String]) async throws -> VaultSyncNamedRecords

    // Wraps, per recipient.
    func fetchWraps(vaultID: UUID, recipientDeviceID: String?, generation: Int?) async throws -> [VaultSyncServedWrap]
    func putWraps(vaultID: UUID, generation: Int, wraps: [VaultSyncWrapEnvelope]) async throws -> Int
    func deleteWraps(vaultID: UUID, recipientDeviceID: String, generation: Int?) async throws -> Int

    // Acknowledgements, presence-free, at apply.
    func fetchAcks(vaultID: UUID) async throws -> [VaultSyncAcknowledgement]
    func putAck(vaultID: UUID, ack: VaultHeadAck, signature: Data) async throws

    // Blobs, by key.
    func putBlob(vaultID: UUID, wireID: String, generation: Int, bytes: Data) async throws -> Int
    func fetchBlob(vaultID: UUID, wireID: String, generation: Int) async throws -> Data
    func deleteBlob(vaultID: UUID, wireID: String, generation: Int) async throws

    // §6.1's envelope, off by default on the deployed service.
    func putRecoveryEnvelope(vaultID: UUID, generation: Int, envelope: Data) async throws
    func fetchRecoveryEnvelope(vaultID: UUID, generation: Int?) async throws -> VaultSyncRecoveryEnvelope
    func deleteRecoveryEnvelope(vaultID: UUID) async throws -> Int
}

// MARK: - Paging the push

/// **§7.1's paging rules, applied to the direction that pushes.**
///
/// A head names the whole live set and bound 1 bounds *what one transfer
/// carries*, so a head naming more than 1,024 records is pushed in pages — and
/// the relay's own rule is what makes that safe: *"a re-push of a head this
/// service already holds, same coordinates and same digest, is a retry: `200`
/// with `retried: true`, and the records and wraps are written again
/// idempotently"*. Page 0 wins the compare-and-swap; pages 1…n−1 are retries of
/// the same head carrying the rest.
///
/// **The index and the count are this Mac's own and are not on the wire**, and
/// that is a decision rather than an omission: the push route's body is
/// `head`, `records` and `wraps`, and a field the relay does not read would look
/// like a contract it does not have. What §7.1's rules buy on this side is
/// enforced here instead — a sequence runs `0 … count−1`, in order, without a
/// repeat, over one head digest — and reported in `VaultSyncPushOutcome` so a
/// caller can see the sequence it sent.
public struct VaultSyncPushPlan: Sendable, Equatable {
    public struct Page: Sendable, Equatable {
        public let index: Int
        public let records: [VaultSyncRecordEnvelope]
        public let wraps: [VaultSyncWrapEnvelope]
    }

    public let pages: [Page]
    public var count: Int { pages.count }

    /// Cuts a transfer into pages at **both** halves of bound 1, whichever binds
    /// first, and puts every wrap on page 0 — §5.1's ceremony and §5.4's rekey
    /// write at most a 24-device roster's worth, so the wraps never need a page
    /// of their own and splitting them would put rows in the store that the head
    /// winning the CAS did not arrive with.
    public init(records: [VaultSyncRecordEnvelope], wraps: [VaultSyncWrapEnvelope]) throws {
        for record in records where RemoteBase64URL.decode(record.ciphertext) == nil {
            throw VaultSyncRefusal.malformedAnswer("a record's ciphertext is not base64url")
        }
        var pages: [Page] = []
        var current: [VaultSyncRecordEnvelope] = []
        var bytes = 0
        for record in records {
            let size = (record.ciphertext.count * 3) / 4
            if !current.isEmpty,
               current.count >= VaultSyncBounds.maximumRecordsPerTransfer
                   || bytes + size > VaultSyncBounds.maximumTransferBytes {
                pages.append(Page(index: pages.count, records: current, wraps: pages.isEmpty ? wraps : []))
                current = []
                bytes = 0
            }
            current.append(record)
            bytes += size
        }
        if !current.isEmpty || pages.isEmpty {
            pages.append(Page(index: pages.count, records: current, wraps: pages.isEmpty ? wraps : []))
        }
        self.pages = pages
    }
}

// MARK: - The shipped client

/// `DeviceAccountClient` is the one place a device route is spoken, and vault
/// sync does not get a second one: the same `Authorization: Device <token>`
/// header, the same fresh DPoP proof per request bound to the exact method and
/// absolute URL, the same origin pin, and the same `401` handling that clears a
/// rejected session and its cached lease.
///
/// **The Mac's single `sig` key serves every route here**, `write`-class rows
/// included. §2.2's `sig`/`sigw` split is the *phone's* and exists because a
/// `.userPresence` Enclave key cannot be exercised in a background task; the
/// relay's own `resolveProofKey` says the same thing from the other side — *"a
/// Mac has no `sigw` row and its single `sig` key serves both classes"*.
extension DeviceAccountClient: VaultSyncTransport {
    public func pushHead(
        vaultID: UUID,
        head: VaultSyncServedHead,
        records: [VaultSyncRecordEnvelope],
        wraps: [VaultSyncWrapEnvelope]
    ) async throws -> VaultSyncPushOutcome {
        let path = try vaultPath(vaultID, "head")
        let plan = try VaultSyncPushPlan(records: records, wraps: wraps)
        var outcomes: [VaultSyncPushPageOutcome] = []
        var facts: VaultSyncVaultFacts?
        var seen: Set<Int> = []
        for page in plan.pages {
            // The three rules a page sequence has on this side, enforced rather
            // than assumed: in order, in range, and never twice.
            guard page.index == outcomes.count, page.index < plan.count, seen.insert(page.index).inserted else {
                throw VaultSyncRefusal.malformedAnswer("a push page sequence is out of order")
            }
            let body = try vaultJSON([
                "head": head.pushFields(),
                "records": page.records.map { $0.pushFields() },
                "wraps": page.wraps.map { $0.pushFields() },
            ])
            let answer = try await vaultRequest(path: path, method: "PUT", body: body, accepting: [200], vaultID: vaultID)
            let object = try vaultObject(answer)
            let transfer = object["transfer"] as? [String: Any]
            outcomes.append(VaultSyncPushPageOutcome(
                index: page.index,
                recordCount: transfer?["recordCount"] as? Int ?? page.records.count,
                byteCount: transfer?["byteCount"] as? Int ?? 0,
                wrapCount: transfer?["wrapCount"] as? Int ?? page.wraps.count,
                retried: object["retried"] as? Bool ?? false
            ))
            facts = try vaultFacts(object["vault"])
        }
        guard let facts else { throw VaultSyncRefusal.malformedAnswer("a push answered with no vault facts") }
        return VaultSyncPushOutcome(
            digest: head.digest, keyGeneration: head.keyGeneration, headSeq: head.headSeq,
            pages: outcomes, vault: facts
        )
    }

    public func fetchHead(vaultID: UUID) async throws -> VaultSyncHeadFacts {
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "head"), method: "GET", body: nil, accepting: [200],
            vaultID: vaultID, mayRefetchHead: false
        ))
        return VaultSyncHeadFacts(
            head: try servedHead(object["head"]),
            acknowledgements: try decode([VaultSyncAcknowledgement].self, from: object["acknowledgements"] ?? []),
            vault: try vaultFacts(object["vault"]),
            exchangedAt: object["exchangedAt"] as? Int ?? 0
        )
    }

    public func walkHeads(vaultID: UUID, from digest: String) async throws -> VaultSyncChainPage {
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "heads"),
            query: [URLQueryItem(name: "from", value: try vaultDigest(digest))],
            method: "GET", body: nil, accepting: [200], vaultID: vaultID
        ))
        let served = try (object["heads"] as? [Any] ?? []).map { try requireServedHead($0) }
        guard served.count <= VaultSyncBounds.maximumHeadsPerPage else {
            throw VaultSyncRefusal.malformedAnswer("a chain page carried more heads than the page bound")
        }
        return VaultSyncChainPage(
            from: object["from"] as? String ?? digest,
            heads: served,
            truncated: object["truncated"] as? Bool ?? false,
            gap: object["gap"] as? Bool ?? false,
            gapAfterDigest: object["gapAfterDigest"] as? String,
            currentHead: try coordinates(object["currentHead"])
        )
    }

    public func pageRecords(vaultID: UUID, generation: Int?, after: String?) async throws -> VaultSyncRecordPage {
        var query: [URLQueryItem] = []
        if let generation { query.append(URLQueryItem(name: "generation", value: try vaultCounter(generation))) }
        if let after { query.append(URLQueryItem(name: "after", value: try vaultWireID(after))) }
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "records"), query: query,
            method: "GET", body: nil, accepting: [200], vaultID: vaultID
        ))
        let records = try servedRecords(object["records"])
        return VaultSyncRecordPage(
            keyGeneration: object["keyGeneration"] as? Int ?? generation ?? 0,
            records: records,
            servedRecordCount: object["servedRecordCount"] as? Int ?? records.count,
            servedByteCount: object["servedByteCount"] as? Int ?? 0,
            servedBytesDigest: try crossCheckedServedDigest(object, records: records),
            complete: object["complete"] as? Bool ?? false,
            nextAfter: object["nextAfter"] as? String,
            vault: try vaultFacts(object["vault"])
        )
    }

    public func fetchRecords(vaultID: UUID, generation: Int, wireIDs: [String]) async throws -> VaultSyncNamedRecords {
        guard !wireIDs.isEmpty, wireIDs.count <= VaultSyncBounds.maximumRecordsPerTransfer else {
            throw VaultSyncRefusal.malformedAnswer("a named-record selector is empty or over bound 1")
        }
        let asked = try wireIDs.map { try vaultWireID($0) }
        let body = try vaultJSON(["keyGeneration": generation, "wireIds": asked])
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "records/by-wire-id"), method: "POST", body: body,
            accepting: [200], vaultID: vaultID
        ))
        let records = try servedRecords(object["records"])
        let missing = try (object["missing"] as? [Any] ?? []).map { try vaultWireID($0 as? String ?? "") }
        let deferred = try (object["deferred"] as? [Any] ?? []).map { try vaultWireID($0 as? String ?? "") }
        // **The three facts stay three facts**, and each one has to be a name
        // this Mac asked for: a relay that answered `missing` with a `wireID`
        // nobody named would be inventing a cause for a refusal.
        let wanted = Set(asked)
        guard Set(records.map(\.wireId)).isSubset(of: wanted), Set(missing).isSubset(of: wanted),
              Set(deferred).isSubset(of: wanted)
        else {
            throw VaultSyncRefusal.malformedAnswer("a named-record answer carried a wireID this Mac did not ask for")
        }
        return VaultSyncNamedRecords(
            keyGeneration: object["keyGeneration"] as? Int ?? generation,
            records: records,
            missing: missing,
            deferred: deferred,
            servedRecordCount: object["servedRecordCount"] as? Int ?? records.count,
            servedByteCount: object["servedByteCount"] as? Int ?? 0,
            servedBytesDigest: try crossCheckedServedDigest(object, records: records)
        )
    }

    public func fetchWraps(vaultID: UUID, recipientDeviceID: String?, generation: Int?) async throws -> [VaultSyncServedWrap] {
        var query: [URLQueryItem] = []
        if let recipientDeviceID {
            query.append(URLQueryItem(name: "recipientDeviceId", value: try vaultIdentifier(recipientDeviceID)))
        }
        if let generation { query.append(URLQueryItem(name: "generation", value: try vaultCounter(generation))) }
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "wraps"), query: query,
            method: "GET", body: nil, accepting: [200], vaultID: vaultID
        ))
        return try decode([VaultSyncServedWrap].self, from: object["wraps"] ?? [])
    }

    public func putWraps(vaultID: UUID, generation: Int, wraps: [VaultSyncWrapEnvelope]) async throws -> Int {
        guard !wraps.isEmpty else { return 0 }
        let body = try vaultJSON(["keyGeneration": generation, "wraps": wraps.map { $0.pushFields() }])
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "wraps"), method: "PUT", body: body, accepting: [200], vaultID: vaultID
        ))
        return object["stored"] as? Int ?? 0
    }

    public func deleteWraps(vaultID: UUID, recipientDeviceID: String, generation: Int?) async throws -> Int {
        var fields: [String: Any] = ["recipientDeviceId": try vaultIdentifier(recipientDeviceID)]
        if let generation { fields["keyGeneration"] = generation }
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "wraps"), method: "DELETE", body: try vaultJSON(fields),
            accepting: [200], vaultID: vaultID
        ))
        return object["deleted"] as? Int ?? 0
    }

    public func fetchAcks(vaultID: UUID) async throws -> [VaultSyncAcknowledgement] {
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "acks"), method: "GET", body: nil, accepting: [200], vaultID: vaultID
        ))
        return try decode([VaultSyncAcknowledgement].self, from: object["acknowledgements"] ?? [])
    }

    /// **`PUT`, and `read`-class, and that is the whole point.** §3.3 change 3
    /// makes the acknowledgement a separate scheduled push that costs **no
    /// presence**; a `write`-class acknowledgement would take `sigw`, which is
    /// `.biometryCurrentSet`, and could never be emitted from a background
    /// refresh. That is DB2-H6, the finding that made it a separate push.
    ///
    /// The relay keys the row on the **session's** device and never on a device
    /// id in the body, so none is sent: a device may say where it is and may not
    /// say where another device is.
    public func putAck(vaultID: UUID, ack: VaultHeadAck, signature: Data) async throws {
        let body = try vaultJSON([
            "ackedKeyGeneration": ack.ackedKeyGeneration,
            "ackedHeadSeq": ack.ackedHeadSeq,
            "ackedHeadDigest": try vaultDigest(ack.ackedHeadDigest),
            "ackedAt": ack.ackedAt,
            "signature": RemoteBase64URL.encode(signature),
        ])
        _ = try await vaultRequest(
            path: try vaultPath(vaultID, "acks"), method: "PUT", body: body, accepting: [200], vaultID: vaultID
        )
    }

    /// §8 item 3: *"the blob uploads as-is, it is already ciphertext"*. Raw
    /// octets, no encoding, no framing, and the object key is the **relay's**,
    /// derived from the account, the vault, the generation and the `wireID` —
    /// never sent, because a key from a body is a path-traversal question.
    public func putBlob(vaultID: UUID, wireID: String, generation: Int, bytes: Data) async throws -> Int {
        guard !bytes.isEmpty, bytes.count <= VaultSyncBounds.maximumSealedRecordBytes else {
            throw VaultSyncRefusal.recordTooLarge
        }
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "blobs/\(try vaultWireID(wireID))"),
            query: [URLQueryItem(name: "generation", value: try vaultCounter(generation))],
            method: "PUT", body: bytes, contentType: "application/octet-stream",
            accepting: [200], vaultID: vaultID
        ))
        return object["byteLength"] as? Int ?? bytes.count
    }

    public func fetchBlob(vaultID: UUID, wireID: String, generation: Int) async throws -> Data {
        let answer = try await vaultRequest(
            path: try vaultPath(vaultID, "blobs/\(try vaultWireID(wireID))"),
            query: [URLQueryItem(name: "generation", value: try vaultCounter(generation))],
            method: "GET", body: nil, accepting: [200], vaultID: vaultID
        )
        guard !answer.body.isEmpty, answer.body.count <= VaultSyncBounds.maximumSealedRecordBytes else {
            throw VaultSyncRefusal.malformedAnswer("a served blob is empty or over the sealed-record ceiling")
        }
        return answer.body
    }

    public func deleteBlob(vaultID: UUID, wireID: String, generation: Int) async throws {
        _ = try await vaultRequest(
            path: try vaultPath(vaultID, "blobs/\(try vaultWireID(wireID))"),
            query: [URLQueryItem(name: "generation", value: try vaultCounter(generation))],
            method: "DELETE", body: nil, accepting: [200], vaultID: vaultID
        )
    }

    public func putRecoveryEnvelope(vaultID: UUID, generation: Int, envelope: Data) async throws {
        let body = try vaultJSON([
            "keyGeneration": generation,
            "envelope": RemoteBase64URL.encode(envelope),
        ])
        _ = try await vaultRequest(
            path: try vaultPath(vaultID, "recovery-envelope"), method: "PUT", body: body,
            accepting: [200], vaultID: vaultID
        )
    }

    public func fetchRecoveryEnvelope(vaultID: UUID, generation: Int?) async throws -> VaultSyncRecoveryEnvelope {
        var query: [URLQueryItem] = []
        if let generation { query.append(URLQueryItem(name: "generation", value: try vaultCounter(generation))) }
        let answer = try await vaultRequest(
            path: try vaultPath(vaultID, "recovery-envelope"), query: query,
            method: "GET", body: nil, accepting: [200], vaultID: vaultID
        )
        guard let decoded = try? JSONDecoder().decode(VaultSyncRecoveryEnvelope.self, from: answer.body) else {
            throw VaultSyncRefusal.malformedAnswer("a recovery envelope answer is not the envelope shape")
        }
        return decoded
    }

    public func deleteRecoveryEnvelope(vaultID: UUID) async throws -> Int {
        let object = try vaultObject(try await vaultRequest(
            path: try vaultPath(vaultID, "recovery-envelope"), method: "DELETE", body: nil,
            accepting: [200], vaultID: vaultID
        ))
        return object["deleted"] as? Int ?? 0
    }
}

// MARK: - The request, the refusal and the parse

private extension DeviceAccountClient {
    /// One request. **The only place a vault route is spoken**, so the credential
    /// rules, the refusal table and the answer's cap are each in one place.
    func vaultRequest(
        path: String,
        query: [URLQueryItem] = [],
        method: String,
        body: Data?,
        contentType: String = "application/json",
        accepting: Set<Int>,
        vaultID: UUID,
        mayRefetchHead: Bool = true
    ) async throws -> AccountHTTPResponse {
        let response: AccountHTTPResponse
        do {
            // **Every status is accepted here and refused below**, which is the
            // point: `deviceRouteRequest`'s own `map` answers in
            // `AccountClientError`, which has no room for §3's twenty-four
            // codes, and a refusal re-read by repeating the request would spend
            // a second budget and — on a `PUT` or a `DELETE` — be a second
            // write. The `401` handling that clears a rejected session still
            // runs inside it, on this one request.
            response = try await deviceRouteRequest(
                path: path, query: query, method: method, body: body,
                contentType: contentType, accepting: Set(100 ... 599)
            )
        } catch is CancellationError {
            throw VaultSyncRefusal.transportUnavailable
        } catch let error as AccountClientError {
            switch error {
            case .cancelled, .networkUnavailable, .serviceUnavailable: throw VaultSyncRefusal.transportUnavailable
            case .accountNotLinked, .authorizationRevoked, .authorizationExpired: throw VaultSyncRefusal.sessionRejected
            default: throw VaultSyncRefusal.malformedAnswer("a vault route could not be addressed")
            }
        }
        guard response.body.count <= VaultSyncBounds.maximumAnswerBytes else {
            throw VaultSyncRefusal.malformedAnswer("an answer was over this transport's cap")
        }
        if accepting.contains(response.statusCode) { return response }
        throw await vaultRefusal(response, vaultID: vaultID, mayRefetchHead: mayRefetchHead)
    }

    /// **The refusal table, and the one place the compare-and-swap re-fetches.**
    ///
    /// The code is read from the body this request already has, and **nothing
    /// but the code leaves this function**: the body is not logged, not attached
    /// to an error, not rendered and not retained.
    ///
    /// A `409 head_chain_conflict` or `409 head_not_successor` is the only place
    /// this transport asks a second question, and it asks exactly one: **`GET
    /// …/head`, once, and then it refuses.** It does not re-push. A push that
    /// lost a race lost it to another device's head, and the records it was
    /// about to write are folded against a head this Mac has not applied; the
    /// caller applies the current head and signs a successor, which is different
    /// bytes. Re-pushing the same bytes would either be refused again or — at
    /// the same coordinates and the same digest — be the relay's idempotent
    /// retry, which is not a resolution of the race but a second way to fail to
    /// notice one.
    func vaultRefusal(_ response: AccountHTTPResponse, vaultID: UUID, mayRefetchHead: Bool) async -> VaultSyncRefusal {
        let code = (try? JSONSerialization.jsonObject(with: response.body) as? [String: Any])?["error"] as? String
        guard let code else { return .unrecognized(status: response.statusCode, code: nil) }
        if code == "head_chain_conflict" || code == "head_not_successor" {
            // `mayRefetchHead` is false on the re-fetch itself, so one refused
            // push costs exactly one extra `GET` and can never recurse.
            let current = mayRefetchHead ? try? await fetchHead(vaultID: vaultID).head : nil
            return code == "head_chain_conflict" ? .headChainConflict(current: current) : .headNotSuccessor(current: current)
        }
        if let named = VaultSyncRefusal.named(code) { return named }
        if code == "invalid_json" || code.hasPrefix("invalid_") || code.hasSuffix("_too_large") || code.hasSuffix("_too_many") {
            return .malformedRequest(code: code)
        }
        return .unrecognized(status: response.statusCode, code: code)
    }

    func vaultPath(_ vaultID: UUID, _ suffix: String) throws -> String {
        "/api/vaults/\(vaultID.uuidString.lowercased())/\(suffix)"
    }

    func vaultIdentifier(_ value: String) throws -> String {
        guard let uuid = UUID(uuidString: value) else {
            throw VaultSyncRefusal.malformedAnswer("a device id is not a UUID")
        }
        return uuid.uuidString.lowercased()
    }

    func vaultWireID(_ value: String) throws -> String {
        guard VaultWireID.isWellFormed(value) else {
            throw VaultSyncRefusal.malformedAnswer("a wireID is not 128 bits of lowercase hex")
        }
        return value
    }

    func vaultDigest(_ value: String) throws -> String {
        guard value.count == 64, value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw VaultSyncRefusal.malformedAnswer("a digest is not 64 lowercase hex digits")
        }
        return value
    }

    func vaultCounter(_ value: Int) throws -> String {
        guard value >= 0, value <= 999_999_999_999_999 else {
            throw VaultSyncRefusal.malformedAnswer("a counter is out of range")
        }
        return "\(value)"
    }

    /// Sorted keys, no escaped slashes — the same writer every other device
    /// route uses, so the bytes this Mac sends are reproducible by anyone
    /// holding the same values.
    func vaultJSON(_ value: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else {
            throw VaultSyncRefusal.malformedAnswer("a request body is not JSON")
        }
        return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    func vaultObject(_ response: AccountHTTPResponse) throws -> [String: Any] {
        guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw VaultSyncRefusal.malformedAnswer("an answer is not a JSON object")
        }
        return object
    }

    func decode<T: Decodable>(_ type: T.Type, from value: Any) throws -> T {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]),
              let decoded = try? JSONDecoder().decode(T.self, from: data)
        else {
            throw VaultSyncRefusal.malformedAnswer("an answer carried a field this build cannot read")
        }
        return decoded
    }

    func vaultFacts(_ value: Any?) throws -> VaultSyncVaultFacts {
        guard let value else { throw VaultSyncRefusal.malformedAnswer("an answer carried no vault facts") }
        return try decode(VaultSyncVaultFacts.self, from: value)
    }

    func servedHead(_ value: Any?) throws -> VaultSyncServedHead? {
        guard let value, !(value is NSNull) else { return nil }
        return try requireServedHead(value)
    }

    func requireServedHead(_ value: Any) throws -> VaultSyncServedHead {
        try decode(VaultSyncServedHead.self, from: value)
    }

    func coordinates(_ value: Any?) throws -> VaultSyncChainPage.Coordinates? {
        guard let value, !(value is NSNull) else { return nil }
        return try decode(VaultSyncChainPage.Coordinates.self, from: value)
    }

    func servedRecords(_ value: Any?) throws -> [VaultSyncServedRecord] {
        let records = try decode([VaultSyncServedRecord].self, from: value ?? [])
        guard records.count <= VaultSyncBounds.maximumRecordsPerTransfer else {
            throw VaultSyncRefusal.transferRecordCountExceeded
        }
        let bytes = records.reduce(0) { $0 + $1.byteLength }
        guard bytes <= VaultSyncBounds.maximumTransferBytes else {
            throw VaultSyncRefusal.transferByteCountExceeded
        }
        return records
    }

    /// **The relay's copy, and this Mac's own, compared.** The relay's is
    /// offered so the wire can be cross-checked before anything is computed, and
    /// is trusted for nothing: what is returned is the one computed here.
    func crossCheckedServedDigest(_ object: [String: Any], records: [VaultSyncServedRecord]) throws -> String {
        let computed = VaultSyncServedBytes.digest(records)
        guard let claimed = object["servedBytesDigest"] as? String else {
            throw VaultSyncRefusal.malformedAnswer("a serve carried no served-bytes digest")
        }
        guard claimed == computed else {
            throw VaultSyncRefusal.malformedAnswer("a serve's served-bytes digest is not the digest of what it served")
        }
        return computed
    }
}

// MARK: - Push field lists

extension VaultSyncServedHead {
    /// The push's `head` object, exactly as `docs/vault-sync.md` shows it.
    /// `writerDeviceId` and `storedAt` are the relay's own and are **not** sent:
    /// the relay derives the writer from the session, and the head's own
    /// `writerDeviceId` is inside `headBody` where the signature covers it.
    func pushFields() -> [String: Any] {
        [
            "keyGeneration": keyGeneration,
            "headSeq": headSeq,
            "previousHeadDigest": previousHeadDigest,
            "digest": digest,
            "acks": acks,
            "headBody": headBody,
            "signature": signature,
        ]
    }

    /// The head this Mac is about to push, from what it signed. **`acks` is the
    /// opaque vector** — the relay stores and serves it and reads nothing in it
    /// — and `headBody` is the signature's own preimage, verbatim.
    public static func outbound(_ signed: SignedVaultHead, accountSubject: String) throws -> VaultSyncServedHead {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let acks = try? encoder.encode(signed.head.acks), acks.count <= VaultSyncBounds.maximumHeadBytes else {
            throw VaultSyncRefusal.malformedAnswer("a head's acks are over 64 KiB")
        }
        let preimage = signed.head.preimage(accountSubject: accountSubject)
        guard preimage.count <= VaultSyncBounds.maximumHeadBytes else {
            throw VaultSyncRefusal.malformedAnswer("a head is over 64 KiB and this design never splits one")
        }
        return VaultSyncServedHead(
            keyGeneration: signed.head.keyGeneration,
            headSeq: signed.head.headSeq,
            previousHeadDigest: signed.head.previousHeadDigest,
            digest: signed.head.chainDigest(accountSubject: accountSubject),
            acks: RemoteBase64URL.encode(acks),
            headBody: RemoteBase64URL.encode(preimage),
            signature: RemoteBase64URL.encode(signed.signature),
            writerDeviceId: signed.head.writerDeviceId,
            storedAt: 0
        )
    }
}

extension VaultSyncRecordEnvelope {
    func pushFields() -> [String: Any] {
        ["wireId": wireId, "recordKind": recordKind, "keyGeneration": keyGeneration, "revision": revision, "ciphertext": ciphertext]
    }
}

extension VaultSyncWrapEnvelope {
    func pushFields() -> [String: Any] {
        [
            "recipientDeviceId": recipientDeviceId,
            "wrapId": wrapId,
            "recipientVkxThumbprint": recipientVkxThumbprint,
            "ciphertext": ciphertext,
            "statementSignature": statementSignature,
        ]
    }
}
