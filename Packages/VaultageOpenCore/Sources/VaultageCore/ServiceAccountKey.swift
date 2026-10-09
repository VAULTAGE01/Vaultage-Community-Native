import Foundation

// BL-117 (D51) — the Google service-account key, parsed once, at paste.
//
// `blueprint/design/credential-classes-spec.md` version 2 §7.3 and §2.1 are the
// normative pages. §1.3 stores the key file as one `document` field and
// `CompositeCredentialKind.serviceAccountKey` records why this slot corrects
// that; what lives here is the correction's machinery — the parse that turns
// one downloaded JSON file into the envelope's typed halves.
//
// Google's documentation, read first-hand on **2026-09-13**:
//
//   * Using OAuth 2.0 for Server to Server Applications — the JWT header and
//     claim set, the token endpoint, the grant type, and the statement that the
//     service-account JSON carries `client_email`, `private_key` and
//     `private_key_id`
//     https://developers.google.com/identity/protocols/oauth2/service-account
//
// **The private key is never a Swift `String`, at any point.** That is not the
// ordinary care every credential path takes; it is the reason this file borrows
// §2.5's technique instead of reaching for `JSONSerialization` first. A JSON
// parse of the key file materialises every value as a `String`, and Swift
// `String` storage cannot be zeroed — so the cheap parse would leave a full
// plaintext copy of an RSA private key in freed heap memory on every paste, and
// residual R4b would gain a copy it does not currently name.
//
// So the PEM is lifted out of the raw bytes **before any JSON parse**,
// byte-by-byte into a `VaultSecret`, and the span it occupied is overwritten
// with a filler that keeps the document well-formed — exactly what
// `TokenExchangeReader` does to an `access_token`, for exactly the same reason.
// The redacted document is then parsed for the four value-free fields this
// connection needs.
//
// One difference from the reader, and it is the only one: a token is lifted
// verbatim because a JSON escape is refused outright, and a PEM **must** be
// unescaped, because Google's key file stores it with its line breaks written
// as `\n`. So this lift decodes the JSON string escapes it accepts, and refuses
// the one it does not (`\u`), rather than pretending the question does not
// arise.

/// One Google service-account key file, as Vaultage custodies it.
public enum ServiceAccountKey {

    // MARK: - Compiled facts

    /// The **only** token endpoint this build will exchange at, and what the
    /// pasted file's `token_uri` is pinned against.
    ///
    /// Google documents `aud` as *"When making an access token request this
    /// value is always `https://oauth2.googleapis.com/token`"* (read
    /// 2026-09-13), and the key file repeats the same URL in `token_uri`. The
    /// file's copy is **customer-supplied text**, so it is compared and
    /// discarded rather than stored and used.
    ///
    /// Why that matters enough to refuse a paste over: the assertion this key
    /// signs is a bearer of the service account's own identity for an hour. A
    /// key file whose `token_uri` named another host would aim one there. The
    /// compiled route table would refuse the URL and nothing would leave the
    /// Mac — but the refusal would land on every request, as a connection that
    /// never works, rather than on the paste, in front of the human who chose
    /// the file. Fail closed where somebody is standing.
    public static let tokenURI = "https://oauth2.googleapis.com/token"

    /// The `type` Google writes into a service-account key file. An OAuth
    /// client file or a `authorized_user` file is a different credential with a
    /// different flow, and is refused rather than half-read.
    public static let documentedType = "service_account"

    /// A key file is about 2.3 KiB. 32 KiB is an order of magnitude of headroom
    /// and bounds a hostile file before anything scans it.
    public static let maximumDocumentBytes = 32 * 1024
    /// A 2048-bit PKCS#8 PEM is about 1.7 KiB; a 4096-bit one about 3.2 KiB.
    public static let maximumPEMBytes = 16 * 1024
    public static let maximumEmailBytes = 256
    public static let maximumKeyIDBytes = 128

    /// The domain suffix every service-account address in the default universe
    /// carries — `…@<project>.iam.gserviceaccount.com`,
    /// `…@<project>.appspot.gserviceaccount.com`,
    /// `…@<project>.developer.gserviceaccount.com`.
    ///
    /// Pinned, and the trade is recorded rather than left implicit: a key
    /// issued in a non-default universe (Google's `universe_domain`, a
    /// sovereign or air-gapped cloud) is refused at paste. That is the
    /// fail-closed direction and it is *consistent*: `token_uri` is already
    /// pinned to `oauth2.googleapis.com`, which is the default universe's own
    /// endpoint, so a key from another universe could not exchange here in any
    /// case. Refusing it at paste says so; accepting it would produce a
    /// connection that fails at its first request for a reason nothing states.
    public static let emailDomainSuffix = ".gserviceaccount.com"

    // MARK: - The parse

    /// Turns one downloaded key file into the composite envelope the vault
    /// stores.
    ///
    /// Everything the compiled routes need is kept and everything else is
    /// dropped: `project_id`, `client_id`, `auth_uri`,
    /// `auth_provider_x509_cert_url`, `client_x509_cert_url` and
    /// `universe_domain` are read by no route this build compiles, and runbook
    /// §4 step 7 says to drop what the connection does not need.
    ///
    /// - Throws: `VaultageError.invalidInput` for every shape it will not take.
    ///   There is no partial import and no default: a file this refuses is a
    ///   file the human re-downloads, which is a sentence a connect panel can
    ///   say.
    public static func envelope(from document: Data) throws -> VaultSecret {
        guard !document.isEmpty, document.count <= maximumDocumentBytes else {
            throw VaultageError.invalidInput("That file is empty or larger than a service-account key can be.")
        }
        var raw = Array(document)
        defer { raw.withUnsafeMutableBytes { SecretMemory.zero($0) } }

        // --- The byte lift, before any JSON parse ---
        let pem = try liftPrivateKey(&raw)

        // --- Only now, the parse, on the redacted document ---
        guard let object = try? JSONSerialization.jsonObject(with: Data(raw)) as? [String: Any] else {
            throw VaultageError.invalidInput("That file is not a Google service-account key: it is not a JSON object.")
        }
        // The lift above must have taken the **top-level** `private_key`. If it
        // took a nested one, the top-level object does not carry the key and
        // this refuses — the same way `TokenExchangeReader` checks that its one
        // occurrence was the top-level one, rather than assuming it.
        guard let redacted = object["private_key"] as? String, !redacted.isEmpty,
              redacted.allSatisfy({ $0 == Character(UnicodeScalar(fillerByte)) }) else {
            throw VaultageError.invalidInput("That file's private key is not where a service-account key file carries it.")
        }
        guard (object["type"] as? String) == documentedType else {
            throw VaultageError.invalidInput("That file is not a service-account key. Download the JSON key for a service account, not an OAuth client or a gcloud user credential.")
        }
        // The pin. Compared, never stored, never used to build a URL.
        guard let declaredTokenURI = object["token_uri"] as? String, declaredTokenURI == tokenURI else {
            throw VaultageError.invalidInput("That file's token_uri is not \(tokenURI), which is the only token endpoint this build will send an assertion to.")
        }
        guard let email = object["client_email"] as? String, isDocumentedEmail(email) else {
            throw VaultageError.invalidInput("That file's client_email is not a service-account address.")
        }
        // Optional, and only optional in one direction: absent is a documented
        // state, and present-but-malformed is a refusal rather than a silently
        // dropped field. A key id that was quietly discarded would produce an
        // assertion with no `kid`, which verifies — so nothing downstream would
        // ever notice that the file was not the shape it claimed to be.
        let keyID = object["private_key_id"]
        if keyID != nil, !(keyID is NSNull) {
            guard let text = keyID as? String, isDocumentedKeyID(text) else {
                throw VaultageError.invalidInput("That file's private_key_id is not the shape a key id has.")
            }
        }

        // The PEM must be a key this build can actually sign with, decided
        // **here** rather than at the first request. §2.5 fail-closed (d) names
        // an unparseable PEM as a local refusal before a `URLSession` task
        // exists, and this is the earliest such place there is: in front of the
        // human who chose the file.
        try pem.withBytes { bytes in
            try RSAPrivateKeyMaterial.withPKCS1DER(ofPEM: bytes) { _ in }
        }

        var values: [CompositeCredentialField: VaultSecret] = [
            .identifier: VaultSecret(Data(email.utf8)),
            .privateKey: pem
        ]
        if let text = keyID as? String { values[.keyIdentifier] = VaultSecret(Data(text.utf8)) }
        return try CompositeCredential.envelope(kind: .serviceAccountKey, values: values)
    }

    /// The service account's own address, out of a stored credential.
    ///
    /// It is `CompositeCredentialField.identifier`, whose `isSecret` is false
    /// on the reasoning that field's own comment gives: the address is
    /// published — it is what an IAM binding names and what the console shows —
    /// and refusing to project it would leave a Google Cloud connection unable
    /// to say which service account it is, which is the one thing verification
    /// exists to establish.
    public static func clientEmail(of credential: VaultSecret) throws -> String {
        var email: String?
        try credential.withCompositeField(.identifier) { raw in
            guard VaultSecret.bytesAreValidUTF8(raw) else { return }
            let text = String(decoding: raw, as: UTF8.self)
            if isDocumentedEmail(text) { email = text }
        }
        guard let email else {
            throw VaultageError.invalidInput("This credential carries no service-account address.")
        }
        return email
    }

    /// BL-117 §7.3 and §5.1 — **the third needle, and the first partial one.**
    ///
    /// `VaultSecret.anySecretFieldOccurs(in:)` looks for a stored field's bytes
    /// *inside* a candidate, so it sees a reply that echoes a credential whole
    /// and is structurally blind to one that echoes part of it. For every
    /// credential before this one that distinction was academic — a bearer token
    /// is short, and half of one is not a credential. An RSA private key is not
    /// short, and §5.1 says plainly that a receipt may never carry *"any prefix
    /// or length"* of one.
    ///
    /// So this is a **window** scan: any 32-byte run of the key's own base64
    /// body, occurring anywhere in a reply, is a leak. Two choices make it
    /// precise rather than noisy:
    ///
    ///   * **the armour is excluded.** `-----BEGIN PRIVATE KEY-----` is a
    ///     public constant that appears in documentation, in error messages and
    ///     in this file; a window overlapping it would fire on text that carries
    ///     no key material at all. Only the base64 body is the needle.
    ///   * **whitespace is removed from both sides**, so a provider that echoed
    ///     the key with its own line breaks is caught as readily as one that
    ///     echoed it verbatim. That is strictly stronger than matching the
    ///     stored layout, and it costs one linear pass.
    ///
    /// Thirty-two base64 characters are twenty-four bytes of key. A false
    /// positive would need a reply to contain twenty-four contiguous bytes of
    /// this exact key by coincidence.
    ///
    /// Returns false for a credential that carries no private key, which is
    /// every credential outside this custody kind — so the caller may run it
    /// unconditionally.
    public static func keyMaterialOccurs(of credential: VaultSecret, in body: Data) -> Bool {
        guard credential.compositeFields.contains(.privateKey) else { return false }
        var found = false
        try? credential.withCompositeField(.privateKey) { pem in
            found = RSAPrivateKeyMaterial.keyMaterialOccurs(ofPEM: pem, in: Array(body))
        }
        return found
    }

    /// The key id, or nil when the file carried none.
    public static func keyID(of credential: VaultSecret) -> String? {
        guard credential.compositeFields.contains(.keyIdentifier) else { return nil }
        var identifier: String?
        try? credential.withCompositeField(.keyIdentifier) { raw in
            guard VaultSecret.bytesAreValidUTF8(raw) else { return }
            let text = String(decoding: raw, as: UTF8.self)
            if isDocumentedKeyID(text) { identifier = text }
        }
        return identifier
    }

    // MARK: - Shapes

    /// One `@`, both halves bounded and charset-checked, and the documented
    /// domain suffix.
    ///
    /// The charset is load-bearing twice over: it keeps a control character or
    /// a newline out of the approval sheet, and — because it admits neither `"`
    /// nor `\` — it is what lets the assertion's `iss` claim be written into
    /// the JWT payload without a JSON escaper standing between this value and
    /// the signed bytes.
    public static func isDocumentedEmail(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumEmailBytes else { return false }
        guard value.hasSuffix(emailDomainSuffix) else { return false }
        let halves = value.split(separator: "@", omittingEmptySubsequences: false)
        guard halves.count == 2, !halves[0].isEmpty, !halves[1].isEmpty else { return false }
        return value.range(of: "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$", options: .regularExpression) != nil
    }

    /// Google documents `kid` only as *"the ID of the service account key used
    /// to sign the JWT"* and gives a hexadecimal example; it does not state a
    /// format, so this does not invent one. What it does state is a charset and
    /// a bound — alphanumeric, so the value needs no JSON escaping in the JWT
    /// header either.
    public static func isDocumentedKeyID(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumKeyIDBytes else { return false }
        return value.range(of: "^[A-Za-z0-9]+$", options: .regularExpression) != nil
    }

    // MARK: - The lift

    /// The byte a lifted span is overwritten with. It is outside base64, out of
    /// PEM armour and out of every alphabet in this module, so a reader that
    /// somehow read the redacted value would get something that refuses.
    static let fillerByte = UInt8(ascii: "#")

    /// Lifts the top-level `private_key` out of the raw document, unescaping
    /// the JSON string as it goes, and overwrites the span it occupied.
    ///
    /// `"private_key_id"` cannot be mistaken for it: the needle carries its own
    /// closing quotation mark, and the byte after `key` in `private_key_id` is
    /// `_`. Exactly one occurrence anywhere in the document — a second one, at
    /// any nesting, refuses, which is §2.5's rule about a second `access_token`
    /// applied to the one value this file exists to protect.
    private static func liftPrivateKey(_ raw: inout [UInt8]) throws -> VaultSecret {
        let key = Array("\"private_key\"".utf8)
        let occurrences = TokenExchangeReader.occurrences(of: key, in: raw)
        guard occurrences.count == 1, let keyStart = occurrences.first else {
            throw VaultageError.invalidInput("That file does not carry exactly one private_key.")
        }
        var cursor = keyStart + key.count
        cursor = skipWhitespace(raw, from: cursor)
        guard cursor < raw.count, raw[cursor] == UInt8(ascii: ":") else {
            throw VaultageError.invalidInput("That file's private_key is not a JSON string.")
        }
        cursor = skipWhitespace(raw, from: cursor + 1)
        guard cursor < raw.count, raw[cursor] == UInt8(ascii: "\"") else {
            throw VaultageError.invalidInput("That file's private_key is not a JSON string.")
        }
        let valueStart = cursor + 1

        // Scan to the closing quotation mark, honouring escapes: a `\"` is not
        // the end of the string. The decoded bytes are accumulated in a buffer
        // this function zeroes, never in a `String`.
        let decoded = UnsafeMutableRawBufferPointer.allocate(byteCount: maximumPEMBytes, alignment: 1)
        SecretMemory.zero(decoded)
        defer {
            SecretMemory.zero(decoded)
            decoded.deallocate()
        }
        var written = 0
        var index = valueStart
        var closed = false
        while index < raw.count {
            let byte = raw[index]
            if byte == UInt8(ascii: "\"") { closed = true; break }
            // A raw control character inside a JSON string is malformed, and a
            // PEM has no use for one.
            guard byte >= 0x20 else {
                throw VaultageError.invalidInput("That file's private_key carries a control character.")
            }
            guard written < maximumPEMBytes else {
                throw VaultageError.invalidInput("That file's private_key is larger than a PEM private key can be.")
            }
            if byte == UInt8(ascii: "\\") {
                guard index + 1 < raw.count else {
                    throw VaultageError.invalidInput("That file's private_key ends inside an escape.")
                }
                let escape = raw[index + 1]
                let literal: UInt8
                switch escape {
                case UInt8(ascii: "n"): literal = 0x0A
                case UInt8(ascii: "r"): literal = 0x0D
                case UInt8(ascii: "t"): literal = 0x09
                case UInt8(ascii: "b"): literal = 0x08
                case UInt8(ascii: "f"): literal = 0x0C
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): literal = escape
                default:
                    // `\uXXXX` among them. A PEM is ASCII armour around base64;
                    // a file that needs a Unicode escape to express one is not
                    // a file this will guess at.
                    throw VaultageError.invalidInput("That file's private_key carries an escape a PEM cannot need.")
                }
                decoded[written] = literal
                written += 1
                index += 2
                continue
            }
            decoded[written] = byte
            written += 1
            index += 1
        }
        guard closed else {
            throw VaultageError.invalidInput("That file's private_key is not terminated.")
        }
        guard written > 0 else {
            throw VaultageError.invalidInput("That file's private_key is empty.")
        }

        // The overwrite, so the document stays well-formed for the parse below.
        // Same length, same quotation marks, and a filler byte that is not a
        // backslash — so the redacted string carries no escape and the parse
        // sees a syntactically identical document with the answer removed.
        for span in valueStart ..< index { raw[span] = fillerByte }

        return VaultSecret(bytes: UnsafeRawBufferPointer(start: decoded.baseAddress, count: written))
    }

    private static func skipWhitespace(_ raw: [UInt8], from index: Int) -> Int {
        var cursor = index
        while cursor < raw.count, raw[cursor] == 0x20 || raw[cursor] == 0x09 || raw[cursor] == 0x0A || raw[cursor] == 0x0D {
            cursor += 1
        }
        return cursor
    }
}

// MARK: - PEM and DER

/// BL-117 (D51) §7.3 and residual R4b — turning a PKCS#8 PEM into the DER the
/// Security framework will make a key out of, in buffers this type zeroes.
///
/// **Why it is written by hand rather than assembled from Foundation.** The
/// obvious route is `String(data:encoding:)` to strip the armour and
/// `Data(base64Encoded:)` to decode the body. Both produce storage Vaultage
/// cannot zero, and both hold the private key: R4b names *"the PEM text, the
/// decoded DER, the `CFData`, and whatever the `SecKey` keeps"* as four
/// unavoidable unzeroable copies. Three of the four are avoidable, and this is
/// where they are avoided — the armour is matched over bytes, the base64 is
/// decoded into an owned buffer, and the `CFData` handed to the framework is
/// built with `CFDataCreateWithBytesNoCopy` over that same buffer. What is left
/// is **one** copy, the one inside the `SecKey`, and §2.1's rule bounds its
/// lifetime: created per signature, released immediately, never cached and
/// never persisted.
enum RSAPrivateKeyMaterial {

    /// PKCS#8's armour, which is what Google writes.
    static let pkcs8Begin = Array("-----BEGIN PRIVATE KEY-----".utf8)
    static let pkcs8End = Array("-----END PRIVATE KEY-----".utf8)
    /// PKCS#1's armour and the encrypted form, both refused by name rather than
    /// by falling through: an `RSA PRIVATE KEY` block is a different DER shape
    /// that would decode to something this walk cannot describe, and an
    /// `ENCRYPTED PRIVATE KEY` needs a passphrase Vaultage has no way to ask
    /// for. Google emits neither.
    static let refusedArmour = [
        Array("-----BEGIN RSA PRIVATE KEY-----".utf8),
        Array("-----BEGIN ENCRYPTED PRIVATE KEY-----".utf8)
    ]

    /// `rsaEncryption`, `1.2.840.113549.1.1.1`, DER-encoded with its tag and
    /// length. The algorithm identifier must be this one: a PKCS#8 file holding
    /// an EC or Ed25519 key is refused rather than handed to an RSA signer.
    static let rsaEncryptionOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    /// The most DER a private key of a size this build will sign with can be.
    static let maximumDERBytes = 12 * 1024

    /// Runs `body` with the PKCS#1 `RSAPrivateKey` DER inside a PKCS#8 PEM.
    ///
    /// The buffer `body` is handed is owned by this function and is zeroed
    /// before it returns, on every path including a thrown one. There is
    /// deliberately no variant that returns the bytes.
    static func withPKCS1DER(
        ofPEM pem: UnsafeRawBufferPointer,
        _ body: (UnsafeRawBufferPointer) throws -> Void
    ) throws {
        for refused in refusedArmour where contains(pem, refused) {
            throw VaultageError.invalidInput("That private key is not an unencrypted PKCS#8 key, which is what a Google service-account file carries.")
        }
        guard let begin = firstIndex(of: pkcs8Begin, in: pem), let end = firstIndex(of: pkcs8End, in: pem) else {
            throw VaultageError.invalidInput("That private key is not a PEM private key.")
        }
        let bodyStart = begin + pkcs8Begin.count
        guard bodyStart < end else {
            throw VaultageError.invalidInput("That private key's PEM body is empty.")
        }

        let der = UnsafeMutableRawBufferPointer.allocate(byteCount: RSAPrivateKeyMaterial.maximumDERBytes, alignment: 1)
        SecretMemory.zero(der)
        defer {
            SecretMemory.zero(der)
            der.deallocate()
        }
        let length = try decodeBase64(
            UnsafeRawBufferPointer(start: pem.baseAddress!.advanced(by: bodyStart), count: end - bodyStart),
            into: der
        )
        let decoded = UnsafeRawBufferPointer(start: der.baseAddress, count: length)
        let pkcs1 = try privateKeyOctetString(in: decoded)
        try body(pkcs1)
    }

    // MARK: The DER walk

    /// PKCS#8 `PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm
    /// AlgorithmIdentifier, privateKey OCTET STRING }`, where the OCTET STRING
    /// holds the PKCS#1 `RSAPrivateKey` the framework wants.
    ///
    /// Everything about this walk is closed: definite lengths only, three
    /// members in one order, one accepted algorithm, and nothing recursive — so
    /// there is no nesting to exhaust and no shape this accepts that it has not
    /// been asked to accept.
    static func privateKeyOctetString(in der: UnsafeRawBufferPointer) throws -> UnsafeRawBufferPointer {
        var cursor = 0
        let outer = try element(tag: 0x30, in: der, at: &cursor)
        guard cursor == der.count else {
            throw VaultageError.invalidInput("That private key carries bytes after its PKCS#8 structure.")
        }
        var inner = 0
        let version = try element(tag: 0x02, in: outer, at: &inner)
        guard version.count == 1, version[0] == 0x00 else {
            throw VaultageError.invalidInput("That private key is not a version 0 PKCS#8 key.")
        }
        let algorithm = try element(tag: 0x30, in: outer, at: &inner)
        // The OID is the **first** member of the AlgorithmIdentifier, not
        // merely somewhere inside it: a substring test would accept a structure
        // that mentions `rsaEncryption` in a parameter.
        guard algorithm.count >= rsaEncryptionOID.count else {
            throw VaultageError.invalidInput("That private key is not an RSA key.")
        }
        for (offset, byte) in rsaEncryptionOID.enumerated() where algorithm[offset] != byte {
            throw VaultageError.invalidInput("That private key is not an RSA key.")
        }
        let privateKey = try element(tag: 0x04, in: outer, at: &inner)
        guard privateKey.count > 0 else {
            throw VaultageError.invalidInput("That private key's PKCS#8 body is empty.")
        }
        return privateKey
    }

    /// One DER element of the expected tag, advancing `cursor` past it.
    /// Definite lengths only — an indefinite length (`0x80`) is a BER shape DER
    /// forbids, and a length over the buffer is refused rather than clamped.
    private static func element(tag: UInt8, in buffer: UnsafeRawBufferPointer, at cursor: inout Int) throws -> UnsafeRawBufferPointer {
        guard cursor + 2 <= buffer.count, buffer[cursor] == tag else {
            throw VaultageError.invalidInput("That private key's DER is not the shape a PKCS#8 RSA key has.")
        }
        var index = cursor + 1
        let first = buffer[index]
        index += 1
        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7F)
            guard count > 0, count <= 4, index + count <= buffer.count else {
                throw VaultageError.invalidInput("That private key's DER carries a length this build will not read.")
            }
            for offset in 0 ..< count {
                length = (length << 8) | Int(buffer[index + offset])
            }
            index += count
        }
        guard length >= 0, index + length <= buffer.count else {
            throw VaultageError.invalidInput("That private key's DER declares more bytes than it carries.")
        }
        cursor = index + length
        return UnsafeRawBufferPointer(start: buffer.baseAddress!.advanced(by: index), count: length)
    }

    // MARK: Base64, over bytes

    /// The reverse alphabet, compiled once: value for a base64 byte, 0xFF for
    /// anything else. Whitespace is skipped; every other byte outside the
    /// alphabet is a refusal rather than a skip, because "ignore what you do not
    /// understand" is how a decoder accepts a document it was not handed.
    private static let base64Values: [UInt8] = {
        var table = [UInt8](repeating: 0xFF, count: 256)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
        for (value, byte) in alphabet.enumerated() { table[Int(byte)] = UInt8(value) }
        return table
    }()

    /// Decodes `source` into `destination`, returning the byte count written.
    @discardableResult
    static func decodeBase64(_ source: UnsafeRawBufferPointer, into destination: UnsafeMutableRawBufferPointer) throws -> Int {
        var quantum: UInt32 = 0
        var filled = 0
        var padding = 0
        var written = 0
        for byte in source {
            if byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D { continue }
            if byte == UInt8(ascii: "=") {
                padding += 1
                guard padding <= 2, filled >= 2 else {
                    throw VaultageError.invalidInput("That private key's PEM body is not base64.")
                }
                quantum <<= 6
                filled += 1
            } else {
                guard padding == 0 else {
                    throw VaultageError.invalidInput("That private key's PEM body carries base64 after its padding.")
                }
                let value = base64Values[Int(byte)]
                guard value != 0xFF else {
                    throw VaultageError.invalidInput("That private key's PEM body is not base64.")
                }
                quantum = (quantum << 6) | UInt32(value)
                filled += 1
            }
            guard filled == 4 else { continue }
            let produced = 3 - padding
            guard written + produced <= destination.count else {
                throw VaultageError.invalidInput("That private key is larger than this build will read.")
            }
            let bytes = [UInt8((quantum >> 16) & 0xFF), UInt8((quantum >> 8) & 0xFF), UInt8(quantum & 0xFF)]
            for offset in 0 ..< produced {
                destination[written] = bytes[offset]
                written += 1
            }
            quantum = 0
            filled = 0
        }
        guard filled == 0 else {
            throw VaultageError.invalidInput("That private key's PEM body is not a whole number of base64 quanta.")
        }
        guard written > 0 else {
            throw VaultageError.invalidInput("That private key's PEM body decoded to nothing.")
        }
        return written
    }

    // MARK: Byte search

    static func firstIndex(of needle: [UInt8], in haystack: UnsafeRawBufferPointer) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        let limit = haystack.count - needle.count
        var offset = 0
        while offset <= limit {
            var matched = true
            for index in 0 ..< needle.count where haystack[offset + index] != needle[index] {
                matched = false
                break
            }
            if matched { return offset }
            offset += 1
        }
        return nil
    }

    static func contains(_ haystack: UnsafeRawBufferPointer, _ needle: [UInt8]) -> Bool {
        firstIndex(of: needle, in: haystack) != nil
    }

    // MARK: The window scan

    /// Thirty-two base64 characters — twenty-four bytes of key.
    ///
    /// BL-117's GitHub slot moved the scan itself to `SecretWindowScan`, which
    /// this now calls: the window is that type's, so the two callers cannot
    /// drift to two numbers, and this constant is kept only for the PEM-specific
    /// length guard below.
    static var scanWindow: Int { SecretWindowScan.window }

    /// Whether any `scanWindow`-byte run of a PEM's base64 body occurs in
    /// `haystack`, with whitespace ignored on both sides.
    ///
    /// Rabin-Karp, so it is one linear pass over each side rather than one pass
    /// per window: a naive "search the reply for each of the key's windows"
    /// would be sixteen hundred searches of a body that may be half a megabyte,
    /// which is the kind of cost that gets a control removed later. Every hash
    /// hit is verified byte for byte, so a collision cannot produce a refusal.
    static func keyMaterialOccurs(ofPEM pem: UnsafeRawBufferPointer, in haystack: [UInt8]) -> Bool {
        // The needle is the base64 body only. A window overlapping the armour
        // would fire on any text that merely quotes `-----BEGIN PRIVATE KEY-----`.
        guard let begin = firstIndex(of: pkcs8Begin, in: pem) else { return false }
        let bodyStart = begin + pkcs8Begin.count
        let bodyEnd = firstIndex(of: pkcs8End, in: pem) ?? pem.count
        guard bodyStart < bodyEnd else { return false }

        // Whitespace is stripped here rather than by `SecretWindowScan` because
        // the armour has to be stripped in the same pass — the scan's
        // already-stripped arm exists for exactly this caller.
        var needle: [UInt8] = []
        needle.reserveCapacity(bodyEnd - bodyStart)
        for index in bodyStart ..< bodyEnd where !isWhitespace(pem[index]) { needle.append(pem[index]) }
        var hay: [UInt8] = []
        hay.reserveCapacity(haystack.count)
        for byte in haystack where !isWhitespace(byte) { hay.append(byte) }
        defer { needle.withUnsafeMutableBytes { SecretMemory.zero($0) } }
        guard needle.count >= scanWindow else { return false }
        // BL-117's GitHub slot: one scan, two callers. What used to be a
        // Rabin-Karp implementation in this file is now `SecretWindowScan`'s,
        // so a PEM and an `id_token` are searched for by the same code with the
        // same window.
        return SecretWindowScan.occurs(strippedNeedle: needle, strippedHaystack: hay)
    }

    private static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }
}

/// BL-117 §7.3. A read-only view of the key material machinery, for the
/// contract suite.
///
/// The same shape and the same reason as `AzureProbe` and
/// `ProviderRouteTableProbe`: the PKCS#8 unwrap, the base64 decoder and the
/// overwrite's filler byte are internal, and the suite must be able to assert
/// them against **the shipped code** rather than against a second copy kept in
/// a test — which is the rule PW-M2 established.
///
/// It exposes exactly those and nothing that can sign, store or configure.
/// `withPKCS1DER` keeps the shipped signature, so there is still no way to
/// obtain the DER bytes: the closure returns `Void` and the buffer is zeroed
/// when it returns.
public enum ServiceAccountKeyProbe {
    /// The byte a lifted private key's span is overwritten with.
    public static var fillerByte: UInt8 { ServiceAccountKey.fillerByte }
}

/// BL-117 §7.3. The PEM and DER walk, read-only, for the same reason.
public enum RSAPrivateKeyMaterialProbe {
    public static func withPKCS1DER(
        ofPEM pem: UnsafeRawBufferPointer,
        _ body: (UnsafeRawBufferPointer) throws -> Void
    ) throws {
        try RSAPrivateKeyMaterial.withPKCS1DER(ofPEM: pem, body)
    }

    @discardableResult
    public static func decodeBase64(_ source: UnsafeRawBufferPointer, into destination: UnsafeMutableRawBufferPointer) throws -> Int {
        try RSAPrivateKeyMaterial.decodeBase64(source, into: destination)
    }
}
