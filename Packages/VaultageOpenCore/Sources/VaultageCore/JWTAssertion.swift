import Foundation
import Security

// BL-117 (D51) — the RS256 assertion, signed inside the broker.
//
// `blueprint/design/credential-classes-spec.md` version 2 §7.3 and §2.1 are the
// normative pages, and Google's own documentation is the source of every
// compiled fact below, read first-hand on **2026-09-13**:
//
//   * Using OAuth 2.0 for Server to Server Applications
//     https://developers.google.com/identity/protocols/oauth2/service-account
//     — the header `{"alg":"RS256","typ":"JWT"}` with an optional `kid`,
//       *"the ID of the service account key used to sign the JWT"*;
//     — the claim set `iss` (*"The email address of the service account"*),
//       `scope` (*"A space-delimited list of the permissions that the
//       application requests"*), `aud` (*"When making an access token request
//       this value is always `https://oauth2.googleapis.com/token`"*), `exp`
//       (*"maximum of 1 hour after the issued time"*) and `iat`;
//     — *"Sign the UTF-8 representation of the input using SHA256withRSA"*.
//
// Three things this file is, each of which is a rule rather than a choice:
//
// **1. It is the broker's, not an adapter's.** §2.1: *"the exchange and the
// signing both happen inside the broker, beside `sig` and `kex`, in the process
// the XPC code-signing admission already governs"*. So it lives in
// `VaultageCore` beside `VaultSecret`, it knows no provider, and
// `VaultageProviders` compiles a `JWTAssertionSpec` on a route rather than
// calling a signer of its own.
//
// **2. The `SecKey` is created per signature and released immediately.** This
// is runbook §10 item 4 and §2.1's prohibition, and the reason is PF-9: a
// *persisted* Keychain `SecKey` under an access-control policy would join the
// set any evaluated `LAContext` in the broker already covers, and the key would
// have left the vault — no `value` record, no sync, no recovery kit, no
// `13-MULTI-DEVICE-CUSTODY.md` §10 row. Here the key material is a `VaultSecret`
// read through the ordinary per-credential path, the framework object exists
// only inside one function's innermost scope, nothing caches one, and **no
// function anywhere returns a `SecKey`** — which `ProviderCredentialClassContracts`
// asserts as a source scan, because what is being asserted is that a second way
// in does not exist.
//
// **3. `sub` is not expressible.** Google's `sub` claim is domain-wide
// delegation — *"the email address of the user for which the application is
// requesting delegated access"* — which would make an app-subject connection act
// as a human. §7.3 says it is not used, and the way this file says so is that
// `JWTAssertionSpec` has no field for it and `claimNames` is a closed list of
// five. There is nothing to set.

/// The signing algorithms an assertion may use.
///
/// One case, and that is a compiled fact rather than a placeholder: runbook §10
/// item 2 names a signing scheme as one of the spec's compiled vocabularies, so
/// a second algorithm is a ticket with its own pass.
public enum JWTSigningAlgorithm: String, Sendable, Codable, CaseIterable, Hashable {
    /// RSASSA-PKCS1-v1_5 with SHA-256 — Google's `RS256`, which it spells out as
    /// *"RSA using SHA-256 hashing algorithm"*.
    case rs256 = "RS256"
}

/// The compiled shape of one provider's assertion: which claims it carries,
/// what fills them, and how long it lives.
///
/// Everything here is compiled beside the route. **A caller supplies no claim,
/// no name, no value and no lifetime** — which is the same property
/// `ExchangeBodySpec` has about a body, for the same reason, and it is why the
/// assertion can be produced by the body builder rather than handed to it.
public struct JWTAssertionSpec: Sendable, Hashable {
    public let algorithm: JWTSigningAlgorithm
    /// The `aud` claim. Google: *"this value is always
    /// `https://oauth2.googleapis.com/token`"*. Compiled, and
    /// `ProviderCredentialClassContracts` asserts it equals the token route's
    /// own URL — so the audience and the endpoint cannot drift apart, which is
    /// the drift that would let a signed assertion be replayed elsewhere.
    public let audience: String
    /// The `scope` claim's members, joined with a space. Compiled: this is the
    /// narrowing §1.3 names, *"the assertion's `scope` claim is the
    /// narrowing"*, and a manifest cannot widen it.
    public let scopes: [String]
    /// `exp - iat`. Google bounds it at *"maximum of 1 hour after the issued
    /// time"* and `maximumLifetime` is that hour; a spec declaring more is
    /// **refused at signing time**, not clamped, because a silently shortened
    /// assertion is a compiled fact that no longer means what it says.
    public let lifetime: TimeInterval
    /// Which typed field of the credential fills `iss`.
    public let issuerField: CompositeCredentialField
    /// Which typed field is the signing key. It is never placed anywhere; it is
    /// the key to an arithmetic, exactly as SigV4's secret access key is.
    public let keyField: CompositeCredentialField
    /// Which typed field becomes the header's `kid`, when the credential
    /// carries it. Google documents `kid` as optional and an assertion verifies
    /// without one, because the key is resolved from `iss` and the signature.
    public let keyIDField: CompositeCredentialField?

    /// Google's own bound, and the only one this build will sign inside.
    public static let maximumLifetime: TimeInterval = 3600

    /// The **five** claim names an assertion carries, in the order this type
    /// documents them. Closed, compiled and exposed so the suite asserts the
    /// produced claim set against *this* rather than against a copy kept in a
    /// test — and so that `sub`'s absence is a fact a reader can check rather
    /// than a sentence in a comment.
    public static let claimNames = ["iss", "scope", "aud", "exp", "iat"]

    /// The header names, same rule. `kid` is present exactly when the
    /// credential carries a key id.
    public static let headerNames = ["alg", "typ"]
    public static let optionalHeaderName = "kid"

    public init(
        algorithm: JWTSigningAlgorithm,
        audience: String,
        scopes: [String],
        lifetime: TimeInterval,
        issuerField: CompositeCredentialField,
        keyField: CompositeCredentialField,
        keyIDField: CompositeCredentialField? = nil
    ) {
        self.algorithm = algorithm
        self.audience = audience
        self.scopes = scopes
        self.lifetime = lifetime
        self.issuerField = issuerField
        self.keyField = keyField
        self.keyIDField = keyIDField
    }

    /// The `scope` claim's value, space-delimited as Google documents it.
    public var scopeClaim: String { scopes.joined(separator: " ") }
}

/// What a signed assertion is, beside the bytes.
///
/// The claims are **value-free** — an email, a scope list, a URL and two
/// timestamps — so they may be projected and asserted. The assertion itself may
/// not, and the type says so: it is a `VaultSecret`, it is not `Codable`, and
/// §5.1 lists it among the things a receipt may never carry.
public struct SignedAssertion: Sendable {
    /// The compiled claims this assertion actually carries, for the Activity
    /// view and for the suite. Never the signature and never the key.
    public let issuer: String
    public let scope: String
    public let audience: String
    public let issuedAt: Date
    public let expiresAt: Date
    public let keyID: String?
    /// The `header.payload.signature` bytes, in a buffer the type zeroes.
    public let assertion: VaultSecret

    public init(issuer: String, scope: String, audience: String, issuedAt: Date, expiresAt: Date, keyID: String?, assertion: VaultSecret) {
        self.issuer = issuer
        self.scope = scope
        self.audience = audience
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.keyID = keyID
        self.assertion = assertion
    }
}

public enum JWTAssertionSigner {

    /// The most an issuer may be. A service-account address is well under this.
    public static let maximumIssuerBytes = 256
    /// The largest assertion this build will build. A 2048-bit signature is 256
    /// bytes, 342 in base64url, and the claims are a few hundred more.
    public static let maximumAssertionBytes = 8 * 1024

    /// Builds and signs one assertion.
    ///
    /// - Parameters:
    ///   - spec: the compiled shape. The caller supplies no claim and no name.
    ///   - credential: the stored service-account key, read through the
    ///     ordinary per-credential path.
    ///   - now: the clock. It is a parameter for exactly one reason — a test
    ///     vector needs a fixed `iat` — and it is **not** a claim: it cannot
    ///     name a claim, rename one, reorder them or add one, so §2.4's *"the
    ///     caller supplies no field, no name and no order"* is untouched.
    /// - Throws: `VaultageError.invalidInput` for a spec or a credential this
    ///   cannot sign with. §2.5 fail-closed **(d)** — *"a signature that cannot
    ///   be computed refuses locally, before a `URLSession` task exists"* — is
    ///   this method having no fallback of any kind.
    public static func sign(_ spec: JWTAssertionSpec, credential: VaultSecret, now: Date = Date()) throws -> SignedAssertion {
        guard spec.lifetime > 0, spec.lifetime <= JWTAssertionSpec.maximumLifetime else {
            throw VaultageError.invalidInput("An assertion's lifetime must be positive and at most \(Int(JWTAssertionSpec.maximumLifetime)) seconds.")
        }
        guard !spec.scopes.isEmpty else {
            throw VaultageError.invalidInput("An assertion must request at least one scope, which is what narrows it.")
        }
        guard let audience = URL(string: spec.audience), audience.scheme == "https" else {
            throw VaultageError.invalidInput("An assertion's audience must be an HTTPS URL.")
        }

        let issuer = try issuer(of: credential, field: spec.issuerField)
        let keyID = keyID(of: credential, field: spec.keyIDField)

        // Whole seconds, as Google's claims are: "specified as seconds since
        // 00:00:00 UTC, January 1, 1970". Truncating rather than rounding means
        // `exp` is never a fraction of a second later than the compiled
        // lifetime allows.
        let issuedAt = Date(timeIntervalSince1970: now.timeIntervalSince1970.rounded(.down))
        let expiresAt = issuedAt.addingTimeInterval(spec.lifetime)

        var header: [String: Any] = ["alg": spec.algorithm.rawValue, "typ": "JWT"]
        if let keyID { header[JWTAssertionSpec.optionalHeaderName] = keyID }
        let claims: [String: Any] = [
            "iss": issuer,
            "scope": spec.scopeClaim,
            "aud": spec.audience,
            "exp": Int(expiresAt.timeIntervalSince1970),
            "iat": Int(issuedAt.timeIntervalSince1970)
        ]
        // `.sortedKeys` so one spec, one credential and one clock always
        // produce the same bytes: RSASSA-PKCS1-v1_5 is deterministic, so a
        // deterministic input makes the whole assertion reproducible, which is
        // what lets a reviewer re-derive the suite's vector.
        guard let headerJSON = try? JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]),
              let claimsJSON = try? JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys]) else {
            throw VaultageError.invalidInput("An assertion's claims could not be encoded.")
        }

        // The signing input is public: an email, a scope list, a URL and two
        // integers. Nothing secret is ever the *message*, only ever the key —
        // the same sentence `VaultSecret.hmacSHA256(over:)` carries.
        var signingInput = Data(base64URL(Array(headerJSON)))
        signingInput.append(UInt8(ascii: "."))
        signingInput.append(contentsOf: base64URL(Array(claimsJSON)))

        let assertion = try signed(signingInput, with: credential, field: spec.keyField)
        return SignedAssertion(
            issuer: issuer,
            scope: spec.scopeClaim,
            audience: spec.audience,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            keyID: keyID,
            assertion: assertion
        )
    }

    // MARK: - The signature

    /// `signingInput + "." + base64url(signature)`, in a buffer this function
    /// zeroes.
    ///
    /// The framework key lives only inside the innermost closure. It is created
    /// from a `CFData` that does **not** copy — `kCFAllocatorNull` as the
    /// deallocator, over the DER buffer `withPKCS1DER` owns and zeroes — so the
    /// only unzeroable copy of the key material anywhere on this path is the
    /// one inside the `SecKey` itself, which residual R4b names and which
    /// §2.1 bounds by lifetime rather than removes.
    private static func signed(_ signingInput: Data, with credential: VaultSecret, field: CompositeCredentialField) throws -> VaultSecret {
        var signature: Data?
        var failure: Error?
        try credential.withCompositeField(field) { pem in
            do {
                try RSAPrivateKeyMaterial.withPKCS1DER(ofPEM: pem) { der in
                    guard let base = der.baseAddress else {
                        throw VaultageError.invalidInput("That private key decoded to nothing.")
                    }
                    guard let keyData = CFDataCreateWithBytesNoCopy(
                        kCFAllocatorDefault,
                        base.assumingMemoryBound(to: UInt8.self),
                        der.count,
                        kCFAllocatorNull
                    ) else {
                        throw VaultageError.invalidInput("That private key could not be read.")
                    }
                    var error: Unmanaged<CFError>?
                    let attributes: [CFString: Any] = [
                        kSecAttrKeyType: kSecAttrKeyTypeRSA,
                        kSecAttrKeyClass: kSecAttrKeyClassPrivate
                    ]
                    guard let key = SecKeyCreateWithData(keyData, attributes as CFDictionary, &error) else {
                        error?.release()
                        throw VaultageError.invalidInput("That private key is not an RSA private key this Mac can sign with.")
                    }
                    guard SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureMessagePKCS1v15SHA256) else {
                        throw VaultageError.invalidInput("That private key cannot produce an RS256 signature.")
                    }
                    guard let produced = SecKeyCreateSignature(
                        key,
                        .rsaSignatureMessagePKCS1v15SHA256,
                        signingInput as CFData,
                        &error
                    ) as Data? else {
                        error?.release()
                        throw VaultageError.invalidInput("That private key could not sign this assertion.")
                    }
                    signature = produced
                    // `key` is released here, at the end of the innermost
                    // scope — which is what "create the framework key per
                    // signature and release it immediately" means in practice.
                    // Nothing outside this closure ever holds one.
                }
            } catch {
                failure = error
            }
        }
        if let failure { throw failure }
        guard let signature, !signature.isEmpty else {
            throw VaultageError.invalidInput("That private key produced no signature.")
        }

        let encoded = base64URL(Array(signature))
        let total = signingInput.count + 1 + encoded.count
        guard total <= maximumAssertionBytes else {
            throw VaultageError.invalidInput("That assertion is larger than this build will send.")
        }
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: total, alignment: 1)
        defer {
            SecretMemory.zero(scratch)
            scratch.deallocate()
        }
        SecretMemory.zero(scratch)
        scratch.copyBytes(from: Array(signingInput))
        scratch[signingInput.count] = UInt8(ascii: ".")
        for (offset, byte) in encoded.enumerated() { scratch[signingInput.count + 1 + offset] = byte }
        return VaultSecret(bytes: UnsafeRawBufferPointer(scratch))
    }

    // MARK: - The claim inputs

    /// The `iss` claim, out of the credential's own typed field.
    ///
    /// The charset is the point rather than a formality: it admits neither `"`
    /// nor `\`, so the issuer cannot alter the JSON it is written into, and it
    /// admits no control character, so it cannot alter anything that renders
    /// the claims afterwards. The field is one whose `isSecret` is false, which
    /// is asserted rather than assumed.
    private static func issuer(of credential: VaultSecret, field: CompositeCredentialField) throws -> String {
        guard !field.isSecret else {
            throw VaultageError.invalidInput("An assertion's issuer may not be a secret field.")
        }
        var issuer: String?
        try credential.withCompositeField(field) { raw in
            guard VaultSecret.bytesAreValidUTF8(raw), raw.count <= maximumIssuerBytes, raw.count > 0 else { return }
            let text = String(decoding: raw, as: UTF8.self)
            guard text.range(of: "^[A-Za-z0-9._%+@-]+$", options: .regularExpression) != nil else { return }
            issuer = text
        }
        guard let issuer else {
            throw VaultageError.invalidInput("This credential carries no issuer an assertion can name.")
        }
        return issuer
    }

    /// The `kid` header, when the credential carries one. Absent is a
    /// documented state; present-but-unshaped is a refusal of the *field*, so a
    /// malformed key id produces no header rather than a header nobody
    /// described.
    private static func keyID(of credential: VaultSecret, field: CompositeCredentialField?) -> String? {
        guard let field, !field.isSecret, credential.compositeFields.contains(field) else { return nil }
        var identifier: String?
        try? credential.withCompositeField(field) { raw in
            guard VaultSecret.bytesAreValidUTF8(raw), raw.count > 0, raw.count <= ServiceAccountKey.maximumKeyIDBytes else { return }
            let text = String(decoding: raw, as: UTF8.self)
            guard text.range(of: "^[A-Za-z0-9]+$", options: .regularExpression) != nil else { return }
            identifier = text
        }
        return identifier
    }

    // MARK: - base64url

    /// RFC 7515's base64url: the URL-safe alphabet, **without** padding.
    ///
    /// Written over bytes rather than through `Data.base64EncodedString()` and
    /// three `replacingOccurrences` calls, for the reason the PEM decoder is:
    /// the value being encoded here is a signature, and the intermediate
    /// `String`s that route would produce cannot be zeroed. The header and the
    /// claims are public and would not have needed it; the signature does, and
    /// one encoder is better than two.
    static func base64URL(_ bytes: [UInt8]) -> [UInt8] {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
        var out: [UInt8] = []
        out.reserveCapacity((bytes.count + 2) / 3 * 4)
        var index = 0
        while index + 3 <= bytes.count {
            let quantum = (UInt32(bytes[index]) << 16) | (UInt32(bytes[index + 1]) << 8) | UInt32(bytes[index + 2])
            out.append(alphabet[Int((quantum >> 18) & 0x3F)])
            out.append(alphabet[Int((quantum >> 12) & 0x3F)])
            out.append(alphabet[Int((quantum >> 6) & 0x3F)])
            out.append(alphabet[Int(quantum & 0x3F)])
            index += 3
        }
        let remaining = bytes.count - index
        if remaining == 1 {
            let quantum = UInt32(bytes[index]) << 16
            out.append(alphabet[Int((quantum >> 18) & 0x3F)])
            out.append(alphabet[Int((quantum >> 12) & 0x3F)])
        } else if remaining == 2 {
            let quantum = (UInt32(bytes[index]) << 16) | (UInt32(bytes[index + 1]) << 8)
            out.append(alphabet[Int((quantum >> 18) & 0x3F)])
            out.append(alphabet[Int((quantum >> 12) & 0x3F)])
            out.append(alphabet[Int((quantum >> 6) & 0x3F)])
        }
        return out
    }
}
