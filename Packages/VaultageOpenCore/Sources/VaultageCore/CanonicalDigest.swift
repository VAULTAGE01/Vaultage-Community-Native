import CryptoKit
import Foundation

/// RP-07 — the one canonical encoding every security digest in Vaultage hashes.
///
/// The digests that decide whether an approval still applies — the grant's
/// covering digest, the read digest and the runtime-delivery request digest —
/// used to hash a string built by joining fields with `|` and records with
/// `\n`, with no escaping and no length prefixing. At least one field in each
/// is provider-supplied text (`ConnectionVerification.principalID`), so a value
/// containing the separators could reshape the canonical form: the re-pass
/// built two genuinely different covered-record sets — one grant over two
/// bindings, one over one — that hashed identically, by making the single
/// binding's principal carry the remainder of its own line, a record separator
/// and the whole of the second line.
///
/// A security digest should be injective by construction, not by the luck of
/// which provider fields happen to be validated today. So every field is
/// length-prefixed: a field is emitted as its UTF-8 byte count, a colon, and
/// exactly that many bytes. A reader consuming the encoding left to right
/// recovers the original field list uniquely, whatever bytes the fields
/// contain — separators, newlines, colons, digits, invalid-looking text — which
/// is what makes two different field lists impossible to hash alike.
///
/// Lists nested inside a digest (a grant's covered bindings) emit their count
/// as a field of their own before the elements, so a list of two records and a
/// list of one record whose fields happen to align cannot be confused either.
public enum CanonicalDigest {
    /// The canonical bytes for an ordered field list. Deterministic, injective,
    /// and independent of the order fields were built in only insofar as the
    /// caller sorts them.
    public static func encode(_ fields: [String]) -> Data {
        var data = Data()
        for field in fields {
            let bytes = Data(field.utf8)
            data.append(contentsOf: Array("\(bytes.count):".utf8))
            data.append(bytes)
        }
        return data
    }

    /// Lowercase hexadecimal SHA-256 over `encode(fields)`.
    public static func hex(_ fields: [String]) -> String {
        SHA256.hash(data: encode(fields)).map { String(format: "%02x", $0) }.joined()
    }

    /// The reader this encoding's own argument promises: *"a reader consuming
    /// the encoding left to right recovers the original field list uniquely"*.
    ///
    /// **Added for BL-100 slice A's transport, and for one reason.** §3.3's
    /// head is served by a relay that *"trusts no digest"*: the index columns
    /// beside it are link labels and the authority is `headBody`, the signed
    /// preimage verbatim. A device that rebuilt a head from the columns would
    /// be trusting exactly what the design says it may not, so it rebuilds from
    /// the body — and rebuilding from the body means reading this encoding.
    ///
    /// It is deliberately strict. A prefix that is not digits, a length that
    /// runs past the end, a trailing byte, a field that is not UTF-8: each is
    /// `nil` rather than a partial list, because a partial list is a field list
    /// that hashes to something and means nothing. `decode(encode(f)) == f` for
    /// every field list, and nothing else decodes at all.
    public static func decode(_ data: Data) -> [String]? {
        var fields: [String] = []
        var index = data.startIndex
        while index < data.endIndex {
            guard let colon = data[index...].firstIndex(of: UInt8(ascii: ":")) else { return nil }
            let digits = data[index ..< colon]
            guard !digits.isEmpty, digits.count <= 19, digits.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
                  let count = Int(String(decoding: digits, as: UTF8.self))
            else { return nil }
            let start = data.index(after: colon)
            guard count >= 0, data.distance(from: start, to: data.endIndex) >= count else { return nil }
            let end = data.index(start, offsetBy: count)
            let bytes = data[start ..< end]
            guard let field = String(bytes: bytes, encoding: .utf8) else { return nil }
            fields.append(field)
            index = end
        }
        return fields
    }
}
