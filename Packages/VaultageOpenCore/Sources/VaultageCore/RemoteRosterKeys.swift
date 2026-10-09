import CryptoKit
import Foundation

/// BL-099 follow-up — **the roster's key material** (§2.3), which the fixes
/// pass recorded as owed and which §2.4's ceremony has no other source for on
/// this side.
///
/// **Why this file exists.** §2.4's transport carries *thumbprints and no key
/// bytes, in either direction*: P1 (the QR) carries the Mac's two, `POST
/// /api/pairings/:id/respond` carries the phone's five, and P2 folds all seven
/// into six words. `DevicePairingRecord` nevertheless stores the five **public
/// keys**, and must — §2.6 rule 1 and §4.3 step 3 both need a key that can
/// verify a signature, and a thumbprint cannot. The only channel that carries
/// key bytes is the roster: the Worker's `accountRoster` serves, per device,
/// `keys: [{ role, jwk, thumbprint }]`
/// (`device.ts:"list.push({ role: key.role, jwk: parsed, thumbprint: key.thumbprint });"`).
/// The Mac's `RemoteRoster` carried `issuedAt`, `digest` and `activeDeviceIDs`
/// and nothing else, so the ceremony had no implemented key source at all.
///
/// **And the roster is still not an authority.** §2.3's rule is verbatim: *"No
/// key is ever used because the roster contains it."* Nothing here admits a
/// key. What this file produces is a *candidate* keyed by its thumbprint; the
/// admission is `RemoteDevicePairingPolicy.pin(fromRoster:)`, which takes the
/// thumbprints the QR and the SAS bound and refuses every entry that does not
/// match them. Two independent reasons a substituted key cannot survive: the
/// six words diverge, and the record re-derives every thumbprint from the key
/// stored beside it.
///
/// **Two verifications happen here, and both refuse the whole roster.**
///
/// 1. **Every thumbprint is recomputed from its JWK** per RFC 7638 and compared
///    with the one served beside it. A roster entry that disagrees with itself
///    describes a producer that is not the one the digest claims, and admitting
///    the *rest* of it is how a relay chooses which entries a Mac keeps.
/// 2. **The digest is recomputed over what the protocol says it covers** — the
///    exact UTF-8 bytes of the `devices` array as the lease carries them,
///    lowercase hex SHA-256
///    (`remote-approvals.md:"so the Mac recomputes it from what it"`), *"with no
///    second canonicalisation to disagree about"*.
///    That is why `decode` takes bytes and not a decoded array: a second
///    canonicalisation on this side would be a second thing to be wrong about,
///    and the field it feeds is the one §4.8 records in the receipt.
///
/// **A refusal here is not a refusal of anything else.** `refreshRoster()`
/// turns a throwing source into `.unavailable`, the cached roster stands and no
/// decision is refused (§2.3, DB-M10). A relay that can corrupt this call can
/// only stop the roster improving — which is the same power it already had by
/// answering `503`.

// MARK: - §2.2's six roles

/// The six key roles, as the roster and the pairing routes name them.
///
/// A phone carries five (`sig`, `sigw`, `apv`, `sum`, `sum2`) and a Mac two
/// (`sig`, `kex`) — §2.2's split, and the arithmetic behind §2.3's 24-device,
/// 32 KiB, six-keys-per-device cap.
public enum RemoteDeviceKeyRole: String, Codable, Hashable, Sendable, CaseIterable {
    case sig, kex, sigw, apv, sum, sum2

    /// What §2.4's ceremony pins from the phone, in the order
    /// `RemoteDevicePairingPolicy.pin` takes them.
    public static let phoneRoles: [RemoteDeviceKeyRole] = [.sig, .sigw, .apv, .sum, .sum2]
    /// What the phone pins from the Mac, and what P1 carries thumbprints for.
    public static let macRoles: [RemoteDeviceKeyRole] = [.sig, .kex]
}

// MARK: - The wire shape

/// One public JWK exactly as the roster serves it.
///
/// Both curves this protocol uses appear here: P-256 for five of the six roles,
/// and Ed25519 for the Mac's shipped `sig` key, which is `Curve25519.Signing`
/// — the Secure Enclave cannot hold Ed25519 and Ed25519 cannot do ECDH, which
/// is the whole reason §2.2 has six roles rather than one.
public struct RemoteRosterJWK: Codable, Hashable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    /// Absent for `OKP`/`Ed25519`, which is one of the two differences RFC
    /// 7638's required-member set turns on.
    public let y: String?

    public init(kty: String, crv: String, x: String, y: String?) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
    }

    /// The RFC 7638 thumbprint of **this** JWK, recomputed rather than read.
    ///
    /// `nil` for a key type this build does not compile: an unknown `kty` has
    /// no required-member set, so there is no thumbprint to compare and the
    /// entry is refused rather than skipped.
    public var recomputedThumbprint: String? {
        switch (kty, crv) {
        case ("EC", "P-256"):
            guard let x = coordinate(x), let y = y.flatMap(coordinate) else { return nil }
            return RemoteDeviceKeyThumbprint.p256(x: x, y: y)
        case ("OKP", "Ed25519"):
            guard y == nil, let x = coordinate(x) else { return nil }
            return RemoteDeviceKeyThumbprint.ed25519(x: x)
        default:
            return nil
        }
    }

    /// X9.63 uncompressed point — `0x04 ‖ X[32] ‖ Y[32]` — which is the shape
    /// `DevicePairingRecord` stores and CryptoKit parses. `nil` for anything
    /// that is not a well-formed P-256 point on this curve.
    public var p256PublicKey: Data? {
        guard kty == "EC", crv == "P-256",
              let x = coordinate(x), let y = y.flatMap(coordinate)
        else { return nil }
        var representation = Data([0x04])
        representation.append(x)
        representation.append(y)
        guard (try? P256.Signing.PublicKey(x963Representation: representation)) != nil else { return nil }
        return representation
    }

    /// A coordinate is 32 bytes of base64url, and it is **re-encoded and
    /// compared** rather than merely decoded: a padded or otherwise
    /// non-canonical spelling decodes to the same bytes and hashes to a
    /// different thumbprint, so accepting it would admit a JWK whose thumbprint
    /// this Mac and the phone compute differently.
    private func coordinate(_ value: String) -> Data? {
        guard let decoded = RemoteBase64URL.decode(value), decoded.count == 32,
              RemoteBase64URL.encode(decoded) == value
        else { return nil }
        return decoded
    }
}

/// One `{ role, jwk, thumbprint }` entry.
public struct RemoteRosterKey: Codable, Hashable, Sendable {
    public let role: RemoteDeviceKeyRole
    public let jwk: RemoteRosterJWK
    /// What the Worker served. Never trusted: `isSelfConsistent` is what says
    /// whether it is the thumbprint of the key beside it.
    public let thumbprint: String

    public init(role: RemoteDeviceKeyRole, jwk: RemoteRosterJWK, thumbprint: String) {
        self.role = role
        self.jwk = jwk
        self.thumbprint = thumbprint
    }

    /// RFC 7638, recomputed and compared.
    public var isSelfConsistent: Bool {
        guard RemoteDeviceKeyThumbprint.isWellFormed(thumbprint) else { return false }
        return jwk.recomputedThumbprint == thumbprint
    }

    /// The key bytes the pin record stores, available only from a
    /// self-consistent entry — so no caller can reach the bytes without the
    /// comparison having been made.
    public var p256PublicKey: Data? {
        guard isSelfConsistent else { return nil }
        return jwk.p256PublicKey
    }
}

/// One device row of the roster.
public struct RemoteRosterDevice: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    public let name: String
    public let kind: String
    public let status: String
    /// Epoch **milliseconds**, as `devices.created_at` stores them.
    public let createdAt: Int
    public let revokedAt: Int?
    public let keys: [RemoteRosterKey]

    public init(id: String, name: String, kind: String, status: String, createdAt: Int, revokedAt: Int?, keys: [RemoteRosterKey]) {
        self.id = id
        self.name = name
        self.kind = kind
        self.status = status
        self.createdAt = createdAt
        self.revokedAt = revokedAt
        self.keys = keys
    }

    /// `devices.status` is `active | revoked` (`device.ts`), and a revoked row
    /// carries `revoked_at`. Both are read, so a row that says one and not the
    /// other is not active.
    public var isActive: Bool { status == "active" && revokedAt == nil }

    public func key(_ role: RemoteDeviceKeyRole) -> RemoteRosterKey? {
        keys.first { $0.role == role }
    }

    /// Every thumbprint this row presents, for the set comparison §2.4's
    /// admission makes.
    public var thumbprints: [String] { keys.map(\.thumbprint) }
}

// MARK: - §2.3's cap

/// The three numbers the appendix's Numbers row states, mirrored here because
/// the Mac is the party that has to disbelieve a roster it did not produce.
///
/// The Worker serves **no** roster past any of them
/// (`device.ts:"if (devices.length > ROSTER_MAX_DEVICES) return undefined;"`), so a
/// roster that exceeds one is not a roster this control plane would have
/// emitted, and it is refused rather than truncated. Truncation is the failure
/// mode §2.3 spent a paragraph rejecting: a silently shortened roster is a
/// roster whose digest cannot reproduce.
public enum RemoteRosterLimits {
    public static let maximumDevices = 24
    public static let maximumBytes = 32 * 1024
    public static let maximumKeysPerDevice = 6
}

// MARK: - Decoding, and the two verifications

public enum RemoteRosterDecodingFailure: Error, Equatable, LocalizedError {
    case malformedJSON
    case tooLarge(bytes: Int)
    case tooManyDevices(Int)
    case tooManyKeys(deviceID: String)
    case duplicateRole(deviceID: String, role: String)
    case duplicateDeviceID(String)
    /// The served thumbprint is not the RFC 7638 thumbprint of the JWK beside
    /// it, or the JWK is not a key this build can hash at all.
    case thumbprintMismatch(deviceID: String, role: String)
    /// `roster_digest` is not the SHA-256 of the bytes it arrived with.
    case digestMismatch(recomputed: String, served: String)

    public var errorDescription: String? {
        switch self {
        case .malformedJSON:
            "This account roster is not the shape the control plane documents, so it was not read."
        case .tooLarge(let bytes):
            "This account roster is \(bytes) bytes, past the \(RemoteRosterLimits.maximumBytes)-byte cap, so it was not read."
        case .tooManyDevices(let count):
            "This account roster lists \(count) devices, past the \(RemoteRosterLimits.maximumDevices)-device cap, so it was not read."
        case .tooManyKeys(let deviceID):
            "A device in this account roster (\(deviceID)) carries more than \(RemoteRosterLimits.maximumKeysPerDevice) keys, so the roster was not read."
        case .duplicateRole(let deviceID, let role):
            "A device in this account roster (\(deviceID)) carries two \(role) keys, so the roster was not read."
        case .duplicateDeviceID(let deviceID):
            "This account roster lists \(deviceID) twice, so it was not read."
        case .thumbprintMismatch(let deviceID, let role):
            "A key in this account roster (\(deviceID), \(role)) does not match the fingerprint served beside it, so the roster was not read."
        case .digestMismatch:
            "This account roster does not match its own digest, so it was not read."
        }
    }
}

extension RemoteRoster {
    /// Decodes the Worker's `devices` array and verifies it, from **the exact
    /// bytes the lease carried**.
    ///
    /// The parameter is `Data` and not `[RemoteRosterDevice]` on purpose: the
    /// digest covers those bytes, and a decoded-then-re-encoded array is a
    /// second canonicalisation to disagree about. A caller that has a lease
    /// hands over the slice; a caller that has a JSON body hands over the body.
    ///
    /// Order of refusals is the cheap-first order, and every one of them
    /// refuses the **whole** roster — see this file's header for why a partial
    /// admission is the wrong shape.
    public static func decode(
        devicesJSON: Data,
        issuedAt: Date,
        digest servedDigest: String
    ) throws -> RemoteRoster {
        guard devicesJSON.count <= RemoteRosterLimits.maximumBytes else {
            throw RemoteRosterDecodingFailure.tooLarge(bytes: devicesJSON.count)
        }
        // Verification 2, and it runs before the parse: a digest that does not
        // reproduce means these are not the bytes the Worker signed over, and
        // there is no reason to interpret them.
        let recomputed = Self.digest(ofDevicesJSON: devicesJSON)
        guard recomputed == servedDigest.lowercased() else {
            throw RemoteRosterDecodingFailure.digestMismatch(recomputed: recomputed, served: servedDigest)
        }
        let decoded: [RemoteRosterDevice]
        do { decoded = try JSONDecoder().decode([RemoteRosterDevice].self, from: devicesJSON) }
        catch { throw RemoteRosterDecodingFailure.malformedJSON }
        guard decoded.count <= RemoteRosterLimits.maximumDevices else {
            throw RemoteRosterDecodingFailure.tooManyDevices(decoded.count)
        }
        var seenDeviceIDs: Set<String> = []
        for device in decoded {
            guard seenDeviceIDs.insert(device.id).inserted else {
                throw RemoteRosterDecodingFailure.duplicateDeviceID(device.id)
            }
            guard device.keys.count <= RemoteRosterLimits.maximumKeysPerDevice else {
                throw RemoteRosterDecodingFailure.tooManyKeys(deviceID: device.id)
            }
            var seenRoles: Set<RemoteDeviceKeyRole> = []
            for key in device.keys {
                guard seenRoles.insert(key.role).inserted else {
                    throw RemoteRosterDecodingFailure.duplicateRole(deviceID: device.id, role: key.role.rawValue)
                }
                // Verification 1. RFC 7638, recomputed from the JWK and
                // compared with what was served beside it.
                guard key.isSelfConsistent else {
                    throw RemoteRosterDecodingFailure.thumbprintMismatch(deviceID: device.id, role: key.role.rawValue)
                }
            }
        }
        return RemoteRoster(
            issuedAt: issuedAt,
            digest: recomputed,
            activeDeviceIDs: decoded.filter(\.isActive).map(\.id),
            devices: decoded
        )
    }

    /// Lowercase hex SHA-256 over the bytes as received. The one definition, so
    /// the receipt field (§4.8) and the comparison above cannot drift apart.
    public static func digest(ofDevicesJSON devicesJSON: Data) -> String {
        SHA256.hash(data: devicesJSON).map { String(format: "%02x", $0) }.joined()
    }

    public func device(_ deviceID: String) -> RemoteRosterDevice? {
        devices.first { $0.id == deviceID }
    }
}

// MARK: - Where the bytes come from

/// §2.3's three claims, read out of an entitlement lease at
/// `entitlement_version: 2`.
///
/// **This type verifies no signature and is not where one is verified.** The
/// lease is an ES256 JWS the Worker mints and `DeviceAccountClient` already
/// verifies against the published entitlement key; what is handed here is the
/// payload of an *already verified* lease. Splitting it this way is what lets
/// the roster be decoded, digested and tested without a network and without a
/// second JWS verifier to disagree with the first.
///
/// **It reads the `devices` array as a byte slice** rather than as a decoded
/// value, because that is what the digest covers. Everything else — the
/// version, the issue time, the digest — is an ordinary scalar claim.
public enum RemoteRosterLease {
    /// `nil` — with no error — when this lease carries no roster.
    ///
    /// That is the ordinary case twice over: at `entitlement_version: 1`, which
    /// is what `ENTITLEMENT_LEASE_VERSION` defaults to, and at version 2 for an
    /// account over §2.3's cap, where *"it refuses the **roster**, never the
    /// lease"* and the plan still resolves. A Mac that treated either as an
    /// error would turn the roster's absence into a plan failure, which is
    /// DB-L2's failure mode with a new trigger.
    ///
    /// A lease that carries a roster it cannot stand behind — bytes that do not
    /// reproduce the digest, a thumbprint that is not its key's — **throws**.
    public static func roster(fromVerifiedLeasePayload payload: Data) throws -> RemoteRoster? {
        guard let claims = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw RemoteRosterDecodingFailure.malformedJSON
        }
        guard let digest = claims["roster_digest"] as? String,
              let issuedAtSeconds = claims["roster_issued_at"] as? Int
        else { return nil }
        guard let devicesJSON = devicesSlice(in: payload) else {
            throw RemoteRosterDecodingFailure.malformedJSON
        }
        return try RemoteRoster.decode(
            devicesJSON: devicesJSON,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(issuedAtSeconds)),
            digest: digest
        )
    }

    /// The exact bytes of the top-level `devices` value, string- and
    /// depth-aware so a device **name** containing `"devices":` or an unbalanced
    /// bracket cannot move where the slice ends.
    public static func devicesSlice(in payload: Data) -> Data? {
        let bytes = [UInt8](payload)
        var index = 0, depth = 0
        var inString = false, escaped = false
        var stringStart = 0
        var lastString: Range<Int>?
        while index < bytes.count {
            let byte = bytes[index]
            if inString {
                if escaped { escaped = false }
                else if byte == 0x5C { escaped = true }
                else if byte == 0x22 { inString = false; lastString = (stringStart + 1)..<index }
                index += 1
                continue
            }
            switch byte {
            case 0x22: inString = true; stringStart = index
            case 0x7B, 0x5B: depth += 1; lastString = nil
            case 0x7D, 0x5D: depth -= 1; lastString = nil
            case 0x3A:
                if depth == 1, let key = lastString, Array(bytes[key]) == Array("devices".utf8) {
                    var start = index + 1
                    while start < bytes.count, bytes[start] == 0x20 || bytes[start] == 0x09 || bytes[start] == 0x0A || bytes[start] == 0x0D {
                        start += 1
                    }
                    guard start < bytes.count, bytes[start] == 0x5B, let end = arrayEnd(bytes, from: start) else { return nil }
                    return Data(bytes[start..<end])
                }
                lastString = nil
            case 0x2C: lastString = nil
            default: break
            }
            index += 1
        }
        return nil
    }

    /// The index **after** the `]` that closes the array beginning at `start`.
    private static func arrayEnd(_ bytes: [UInt8], from start: Int) -> Int? {
        var index = start, depth = 0
        var inString = false, escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            if inString {
                if escaped { escaped = false }
                else if byte == 0x5C { escaped = true }
                else if byte == 0x22 { inString = false }
            } else if byte == 0x22 {
                inString = true
            } else if byte == 0x5B || byte == 0x7B {
                depth += 1
            } else if byte == 0x5D || byte == 0x7D {
                depth -= 1
                if depth == 0 { return index + 1 }
            }
            index += 1
        }
        return nil
    }
}
