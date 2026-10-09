import CryptoKit
import Foundation

/// BL-099 slice 2 — **the envelope consumption path**: §5.3a's connect context,
/// §5.4's single consumption, and §5.6's steps 1–9 on receipt (step 9 is the
/// BL-075 reporting seam — see `RemoteConnectConsumer.consume`).
///
/// The one place in this protocol where a **credential value** crosses the
/// relay. Everything else is value-free by construction; this is not, so every
/// rule here is about the same two things: the bytes only ever open on the Mac
/// that pinned the phone, and they never become anything a log, a crash report
/// or a `String` interpolation can reach.

// MARK: - The compiled connect contract (§5.3a items 1, 2a, and §5.6 step 4)

/// **What the owner may be asked for, and what they are told to put in it.**
///
/// §5.3a is a DB-H20 fix and its whole point is that neither half comes off the
/// wire. The *field list* comes from a contract compiled into the binary,
/// selected by `provider`; the *permission wording* comes from the same contract
/// keyed by `(provider, capability)`. A relay that rewrites `dns:read` to
/// `account:admin` therefore cannot make either screen say anything, on the
/// phone or on the Mac.
///
/// This is the **Mac's** half. BL-096 compiles the same table for the phone and
/// derives `fieldSchemaId` from it locally (§5.3a item 1); the two are joined by
/// the id, which is digested into `summaryDigest` and signed into
/// `connectContextPreimage`, so a disagreement is a refusal rather than a
/// silently different screen.
public struct RemoteConnectContract: Hashable, Sendable {
    public let providerSlug: String
    /// The id both sides derive locally and compare. **Versioned**, because a
    /// field list that changes shape without the id moving is exactly the
    /// undiagnosable divergence §5.3a exists to prevent.
    public let fieldSchemaId: String
    /// The **exact** set of field names, in render order. Not a minimum: §5.6
    /// step 4 refuses an unknown name *and* a missing one.
    public let fieldNames: [String]
    /// The capabilities this provider's contract knows. `capability` is Class A
    /// membership in a compiled set (§5.3a item 2a) — anything else is refused
    /// before a screen is drawn.
    public let capabilities: [String: String]

    public init(providerSlug: String, fieldSchemaId: String, fieldNames: [String], capabilities: [String: String]) {
        self.providerSlug = providerSlug
        self.fieldSchemaId = fieldSchemaId
        self.fieldNames = fieldNames
        self.capabilities = capabilities
    }

    /// The displayed permission wording, **from the contract, never from the
    /// request** (§5.3a item 2a).
    public func wording(for capability: String) -> String? { capabilities[capability] }

    public func permits(capability: String) -> Bool { capabilities[capability] != nil }

    /// Every shipped provider takes exactly one secret field, because that is
    /// what `Connection` → `VaultItem` → one Keychain account actually stores.
    /// The shape is a list rather than a single name so that a provider needing
    /// two (an id and a secret) is a table entry rather than a redesign.
    ///
    /// The id carries the field names so a contract that gains a field cannot
    /// keep its id by accident.
    public static func compiled(forProviderSlug slug: String) -> RemoteConnectContract? {
        guard let provider = Provider(rawValue: slug) else { return nil }
        let names = ["apiToken"]
        return RemoteConnectContract(
            providerSlug: provider.rawValue,
            fieldSchemaId: "vaultage.connect.fields.v1.\(provider.rawValue).\(names.joined(separator: "-"))",
            fieldNames: names,
            capabilities: [
                "credential:verify": "Read-only access, used once to confirm the credential works."
            ]
        )
    }
}

// MARK: - The plaintext, and why it is not JSON

/// **The sealed plaintext, as bytes rather than as a JSON object.**
///
/// §5.6 step 5 says "the value never enters a `String`", and §5.3 specifies the
/// envelope down to the padding without specifying the plaintext *inside* it.
/// A JSON body cannot satisfy step 5: every JSON decoder in the platform
/// materialises a string value as a `String`, whose storage Vaultage does not
/// own, cannot pin and cannot zero — which is the exact property `VaultSecret`
/// exists to provide. So the plaintext is length-prefixed binary:
///
/// ```
/// plaintext := u16be(headerLength) ‖ headerJSON ‖ field*
/// field     := u8(nameLength) ‖ name ‖ u16be(valueLength) ‖ value
/// headerJSON = {"fieldSchemaId": "…", "providerSlug": "…", "capability": "…"}
/// ```
///
/// Field **names** become `String`s — they are names, and step 4 has to compare
/// them. Field **values** are sliced straight into a `VaultSecret` and never
/// exist as anything else.
///
/// **Owed to the protocol: one paragraph in §5.3 fixing this shape.** It is a
/// wire format BL-096 must produce, and it is specified here because the
/// document does not specify it anywhere. Reported rather than resolved
/// silently, on the same discipline slice 1 used for its six findings.
public enum RemoteConnectPlaintext {
    public struct Header: Codable, Hashable, Sendable {
        public let fieldSchemaId: String
        public let providerSlug: String
        public let capability: String
        public init(fieldSchemaId: String, providerSlug: String, capability: String) {
            self.fieldSchemaId = fieldSchemaId
            self.providerSlug = providerSlug
            self.capability = capability
        }
    }

    /// A parsed plaintext: a header, and one `VaultSecret` per field name.
    ///
    /// Not `Codable`, not `CustomStringConvertible`, and deliberately carrying
    /// no synthesised description: the only way to a value is `secret(for:)`.
    public struct Parsed: Sendable {
        public let header: Header
        public let fieldNames: [String]
        private let values: [String: VaultSecret]

        init(header: Header, values: [String: VaultSecret], order: [String]) {
            self.header = header
            self.values = values
            self.fieldNames = order
        }

        public func secret(for field: String) -> VaultSecret? { values[field] }
    }

    /// Builds a plaintext. Used by the self-tests and by the live-proof
    /// harness's simulated phone; the product never seals one — the phone does.
    public static func encode(header: Header, fields: [(name: String, value: Data)]) throws -> Data {
        let headerBytes = try JSONEncoder().encode(header)
        guard headerBytes.count <= Int(UInt16.max) else {
            throw VaultageError.invalidInput("A connect plaintext header is too large.")
        }
        var out = Data()
        out.append(UInt8(headerBytes.count >> 8)); out.append(UInt8(headerBytes.count & 0xff))
        out.append(headerBytes)
        for field in fields {
            let name = Array(field.name.utf8)
            guard !name.isEmpty, name.count <= Int(UInt8.max) else {
                throw VaultageError.invalidInput("A connect field name is empty or too long.")
            }
            guard field.value.count <= Int(UInt16.max) else {
                throw VaultageError.invalidInput("A connect field value is too long.")
            }
            out.append(UInt8(name.count))
            out.append(contentsOf: name)
            out.append(UInt8(field.value.count >> 8)); out.append(UInt8(field.value.count & 0xff))
            out.append(field.value)
        }
        return out
    }

    /// Parses one. **Fails closed on every framing error** — a truncated length,
    /// a name that is not UTF-8, a duplicate name, trailing bytes — because a
    /// plaintext that parses two ways is a plaintext an attacker chooses the
    /// meaning of.
    public static func parse(_ data: Data) throws -> Parsed {
        var cursor = data.startIndex
        func need(_ count: Int) throws {
            guard data.distance(from: cursor, to: data.endIndex) >= count else {
                throw VaultageError.invalidInput(RemoteConnectFailure.envelopeInvalid.ownerSentence)
            }
        }
        try need(2)
        let headerLength = Int(data[cursor]) << 8 | Int(data[data.index(after: cursor)])
        cursor = data.index(cursor, offsetBy: 2)
        try need(headerLength)
        let headerBytes = data[cursor..<data.index(cursor, offsetBy: headerLength)]
        cursor = data.index(cursor, offsetBy: headerLength)
        guard let header = try? JSONDecoder().decode(Header.self, from: Data(headerBytes)) else {
            throw VaultageError.invalidInput(RemoteConnectFailure.envelopeInvalid.ownerSentence)
        }
        var values: [String: VaultSecret] = [:]
        var order: [String] = []
        while cursor < data.endIndex {
            try need(1)
            let nameLength = Int(data[cursor])
            cursor = data.index(after: cursor)
            try need(nameLength)
            guard nameLength > 0, let name = String(bytes: data[cursor..<data.index(cursor, offsetBy: nameLength)], encoding: .utf8) else {
                throw VaultageError.invalidInput(RemoteConnectFailure.envelopeInvalid.ownerSentence)
            }
            cursor = data.index(cursor, offsetBy: nameLength)
            try need(2)
            let valueLength = Int(data[cursor]) << 8 | Int(data[data.index(after: cursor)])
            cursor = data.index(cursor, offsetBy: 2)
            try need(valueLength)
            // The one place a credential value is touched. It goes straight into
            // an allocation `VaultSecret` owns, pins and zeroes.
            let secret = VaultSecret(Data(data[cursor..<data.index(cursor, offsetBy: valueLength)]))
            cursor = data.index(cursor, offsetBy: valueLength)
            guard values.updateValue(secret, forKey: name) == nil else {
                throw VaultageError.invalidInput(RemoteConnectFailure.envelopeInvalid.ownerSentence)
            }
            order.append(name)
        }
        return Parsed(header: header, values: values, order: order)
    }
}

// MARK: - Failure reasons

/// §5.6's terminal reasons, plus `presence_unavailable`.
///
/// **`presence_unavailable` is local-only** and shares
/// `RemoteRefusalReason.localOnly`'s rule: it says something about the owner's
/// Mac and never reaches the relay. Everything else here is a value-free result
/// code the relay is told, per §5.6 step 7.
public enum RemoteConnectFailure: String, Equatable, Sendable, CaseIterable {
    case envelopeInvalid = "envelope_invalid"
    case connectSignatureInvalid = "connect_signature_invalid"
    case unknownField = "unknown_field"
    case schemaMismatch = "schema_mismatch"
    case capabilityNotCompiled = "capability_not_compiled"
    case verificationFailed = "verification_failed"
    case envelopeConsumed = "envelope_consumed"
    case approvalExpired = "approval_expired"
    case presenceUnavailable = "presence_unavailable"
    case credentialTooLarge = "credential_too_large"
    case storageFailed = "storage_failed"
    /// §4.3 check 2's predicate, re-run at §5.6 step 4 (BM-L7): the pin this
    /// consumer was handed is locally unpaired, or a verified DSRL entry names
    /// it. **Local-only**, like `presenceUnavailable`: which devices this Mac
    /// serves is a local fact, and the relay is the party the design treats as
    /// hostile.
    case pairingRevoked = "pairing_revoked"

    /// Never posted to the relay (§3's local-only list).
    public var isLocalOnly: Bool {
        switch self {
        case .presenceUnavailable, .pairingRevoked: true
        default: false
        }
    }

    /// What the relay is told. `nil` means nothing is posted.
    public var wireResultCode: String? { isLocalOnly ? nil : rawValue }

    /// The agent-facing outcome is `approval_denied` for every one of them,
    /// unchanged from `09-ENGINEERING-CONTRACTS.md` §1.
    public var agentFacingOutcome: String { "approval_denied" }

    public var ownerSentence: String {
        switch self {
        case .envelopeInvalid: "The sealed credential did not open on this Mac. Nothing was stored."
        case .connectSignatureInvalid: "The phone's signature over this connect request did not verify against the key this Mac pinned. Nothing was stored."
        case .unknownField: "The sealed credential named a field this build does not know. Nothing was stored."
        case .schemaMismatch: "The sealed credential was entered against a different field list than this Mac asked for. Nothing was stored."
        case .capabilityNotCompiled: "This build has no compiled contract for that provider and permission."
        case .verificationFailed: "The provider refused the credential. It has been deleted from the Keychain."
        case .envelopeConsumed: "This credential was already delivered. Ask for it again from the phone."
        case .approvalExpired: "The connect request expired before the credential arrived."
        case .presenceUnavailable: "This Mac is locked, so it cannot complete a connection that needs your presence. Unlock it and try again."
        case .credentialTooLarge: "That credential is larger than a sealed envelope carries. Enter it on the Mac."
        case .storageFailed: "The credential could not be stored in the Keychain. Nothing was kept."
        case .pairingRevoked: "That phone is no longer paired with this Mac, or it was revoked here. Nothing was stored."
        }
    }
}

// MARK: - §5.4's route contract, as a seam

/// One consumed envelope, as `POST /api/connect-requests/:id/envelope/consume`
/// returns it after its `DELETE … RETURNING`.
public struct RemoteConsumedEnvelope: Codable, Hashable, Sendable {
    /// base64url of the whole envelope.
    public let ciphertext: String
    public let senderDeviceId: String
    public let recipientKexThumbprint: String
    /// §5.3a item 3's signature, base64url, 64 raw bytes `r ‖ s`.
    public let connectSignature: String
    public let issuedAt: Int

    public init(ciphertext: String, senderDeviceId: String, recipientKexThumbprint: String, connectSignature: String, issuedAt: Int) {
        self.ciphertext = ciphertext
        self.senderDeviceId = senderDeviceId
        self.recipientKexThumbprint = recipientKexThumbprint
        self.connectSignature = connectSignature
        self.issuedAt = issuedAt
    }

    /// §5.6 step 1: bound the response **before parsing**. 16 KiB, against the
    /// largest raw envelope of 8,275 bytes plus its base64url expansion and the
    /// four small fields beside it.
    public static let maximumResponseBytes = 16 * 1024
}

/// §5.6 step 7's value-free report.
public struct RemoteConnectResult: Codable, Hashable, Sendable {
    public let verified: Bool
    /// ≤96 characters, BL-075's refusals applied.
    public let principalHint: String?
    public let verifiedAt: Int?
    public let resultCode: String?

    public init(verified: Bool, principalHint: String?, verifiedAt: Int?, resultCode: String?) {
        self.verified = verified
        self.principalHint = principalHint
        self.verifiedAt = verifiedAt
        self.resultCode = resultCode
    }

    public static let maximumPrincipalHintCharacters = 96
}

/// The four connect routes of §6.2, as their own seam so the self-tests drive a
/// fake and the product drives `DeviceAccountClient`.
public protocol RemoteConnectTransport: Sendable {
    /// `POST /api/connect-requests`.
    func createConnectRequest(_ request: RemoteConnectRequestCreation) async throws -> String
    /// `POST /api/connect-requests/:id/envelope/consume` — the `DELETE …
    /// RETURNING`. **`nil` is `404 envelope_consumed`**, which is a second
    /// consume and is a refusal, not an empty result.
    func consumeEnvelope(connectRequestID: String) async throws -> RemoteConsumedEnvelope?
    /// `POST /api/connect-requests/:id/result`.
    func reportConnectResult(connectRequestID: String, result: RemoteConnectResult) async throws
}

public struct RemoteConnectRequestCreation: Codable, Hashable, Sendable {
    /// **The Mac mints the id, and this is a finding, not a preference**
    /// (BL-099 slice 3 step (b)).
    ///
    /// §5.3's HPKE `info` (P9) and §5.3a's `connectContextPreimage` (P10) both
    /// carry `connectRequestId`, and the summary sealed into `summaryCiphertext`
    /// carries it as `pendingId`. All three are fixed **before** this body is
    /// sent, so an id the Worker mints in its response arrives too late to be
    /// any of them. §6.2's row for this route does not say so and the shipped
    /// client decoded `{id}` from the response, which cannot work: the phone
    /// rebuilds `info` from the request it fetched, and a Worker-minted id would
    /// make every envelope fail its tag.
    ///
    /// So the id is minted here, sent here, and the Worker's echo is
    /// **compared**, never adopted. The route's body gaining one Class A field
    /// is owed by BL-098; until it lands, a Worker that rejects the unknown key
    /// refuses the request, which is the correct direction to fail in.
    public let id: String
    public let provider: String
    public let capability: String
    public let connectionLabel: String
    /// The sealed summary, base64url, exactly as `POST /api/approvals` carries
    /// one. The device never names itself in the body (§6.2).
    public let summaryCiphertext: String
    public let recipientDeviceId: String
    public let recipientThumbprint: String
    public let byteLength: Int

    public init(id: String, provider: String, capability: String, connectionLabel: String, summaryCiphertext: String, recipientDeviceId: String, recipientThumbprint: String, byteLength: Int) {
        self.id = id
        self.provider = provider
        self.capability = capability
        self.connectionLabel = connectionLabel
        self.summaryCiphertext = summaryCiphertext
        self.recipientDeviceId = recipientDeviceId
        self.recipientThumbprint = recipientThumbprint
        self.byteLength = byteLength
    }
}

// MARK: - §5.3a item 3 — the connect context, verified against the pin

public enum RemoteConnectContextVerification {
    /// **Verified against the pinned `apv` key, before anything is stored**
    /// (§5.3a item 3, §5.6 step 4).
    ///
    /// The key comes from the pin record's **public key**, never from its
    /// thumbprint and never from the wire — §2.6 rule 1 and §4.3 check 3 both
    /// require verification against a pinned key, and slice-1 deviation 2 is
    /// exactly the observation that a thumbprint cannot verify a signature. The
    /// record is re-derived and refused if it disagrees with itself.
    ///
    /// `macKexThumbprint` inside the preimage is **the Mac's own pinned value**,
    /// not the one the relay returned beside the ciphertext: taking it from the
    /// response would let a relay choose part of what it is being checked
    /// against.
    public static func verify(
        signature: Data,
        context: RemoteConnectContext,
        pin: DevicePairingRecord
    ) -> Bool {
        guard pin.phoneDeviceID == context.phoneDeviceId else { return false }
        guard let key = pin.apvVerifyingKey else { return false }
        guard let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(ecdsa, for: RemoteApprovalDigests.connectContextPreimage(context))
    }
}
