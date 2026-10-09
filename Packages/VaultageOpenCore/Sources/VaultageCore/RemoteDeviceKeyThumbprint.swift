import CryptoKit
import Foundation

/// BL-099 — RFC 7638 JWK thumbprints, the primary key of every pin record.
///
/// §4.6 (DB-L13): `decidingDeviceID` is a control-plane-assigned UUID
/// (`device.ts:334`), so **the pinned thumbprint is the primary key** of the
/// device section and the id is kept for display. §2.6 rule 5 records all five
/// of a revoked device's thumbprints in `everRevokedKeyThumbprints` for the same
/// reason: a phone that re-enrols keeps its Enclave keys and would otherwise
/// pair again under a fresh id **to the exact key that was revoked** (DB-M32,
/// DB-L31).
///
/// RFC 7638 is a byte-exact recipe and the bytes are what both platforms digest,
/// so it is implemented literally: the required members only, lexicographic
/// order, no whitespace, base64url with no padding, SHA-256, base64url again.
public enum RemoteDeviceKeyThumbprint {
    /// `{"crv":"P-256","kty":"EC","x":"…","y":"…"}` — the five phone roles and
    /// the Mac's `kex`.
    public static func p256(x: Data, y: Data) -> String {
        let json = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(RemoteBase64URL.encode(x))\",\"y\":\"\(RemoteBase64URL.encode(y))\"}"
        return digest(json)
    }

    /// `{"crv":"Ed25519","kty":"OKP","x":"…"}` — the Mac's shipped `sig` key,
    /// which is `Curve25519.Signing` (`AccountClient.swift:423`). The Secure
    /// Enclave cannot hold Ed25519 and Ed25519 cannot do ECDH, which is the
    /// whole reason §2.2 has six roles rather than one.
    public static func ed25519(x: Data) -> String {
        digest("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"\(RemoteBase64URL.encode(x))\"}")
    }

    /// An X9.63 uncompressed point — `0x04 ‖ X[32] ‖ Y[32]`, which is what
    /// CryptoKit's `x963Representation` produces for every P-256 public key,
    /// signing and key-agreement alike.
    public static func p256(x963Representation representation: Data) -> String? {
        guard representation.count == 65, representation.first == 0x04 else { return nil }
        let body = representation.dropFirst()
        return p256(x: Data(body.prefix(32)), y: Data(body.suffix(32)))
    }

    public static func thumbprint(of key: P256.KeyAgreement.PublicKey) -> String {
        p256(x963Representation: key.x963Representation) ?? ""
    }

    public static func thumbprint(of key: P256.Signing.PublicKey) -> String {
        p256(x963Representation: key.x963Representation) ?? ""
    }

    public static func thumbprint(of key: Curve25519.Signing.PublicKey) -> String {
        ed25519(x: key.rawRepresentation)
    }

    /// A thumbprint as this protocol writes it: base64url of a SHA-256, so 43
    /// characters from the base64url alphabet and nothing else. Used to refuse a
    /// malformed value at a boundary rather than to prove one is genuine.
    public static func isWellFormed(_ value: String) -> Bool {
        value.count == 43 && value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }

    private static func digest(_ json: String) -> String {
        RemoteBase64URL.encode(Data(SHA256.hash(data: Data(json.utf8))))
    }
}
