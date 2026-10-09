import Foundation

// BL-089 / D32 — composite provider credentials.
//
// Wave 1 had one shape: a provider's credential is one opaque token, held in
// one Keychain record, sent in one header. Wave 2 has providers whose
// credential is *several typed values that are only meaningful together* —
// Twilio's Account SID and Auth Token, MongoDB Atlas's public and private key,
// Auth0's client id and secret, Firebase's service-account document.
//
// Three decisions shape this file, and each is load-bearing:
//
// 1. **One protected item, typed fields — not several loose items.** A Twilio
//    connection is one vault item with two named fields. Storing the SID as
//    one item and the token as another would let a project bind half a
//    credential, would let a rotation update one half, and would give the
//    approval sheet nothing coherent to name.
//
// 2. **The fields are custodied together, in the item's primary record.**
//    BL-079 introduced per-field Keychain custody, and it is the right shape
//    for a *user-authored* item: revealing a password should not hand out the
//    SSH passphrase beside it. A *provider* credential is different, because
//    `Broker.readCredential` resolves exactly one Keychain account per action.
//    Splitting a composite across records would turn one user-presence prompt
//    per provider call into one prompt per field, which is worse security
//    theatre and worse ergonomics for no gain: the fields are used together on
//    every single call, so there is no action that needs one and not the
//    other. The item still carries one `VaultItemField` per typed field, so
//    the vault shows what is inside; the values come out of the envelope
//    below, one field at a time, through a borrow that cannot return a copy.
//
// 3. **The envelope is a compiled binary format, not JSON.** `JSONSerialization`
//    would materialize every field as a `String` that Swift cannot zero, which
//    is exactly what `VaultSecret` exists to avoid. The format here is read
//    and written inside buffers this file zeroes, and no field value is ever
//    a `String` on the way in or out.
//
// Single-token providers are untouched. Their `VaultSecret` is the bare token
// it has always been, `isComposite` is false for it, and every wave-1 path —
// `withAuthorizationHeaderValue`, `withBareHeaderValue`, `occurs(in:)`, the
// runtime delivery value — behaves exactly as before.
//
// **Not to be confused with `VaultageProviders.ProviderCredentialKind`**, which
// BL-084 added for the connect panel. The two answer different questions and
// deliberately stay separate:
//
//   * *this* type answers "how is the value custodied and how does it reach the
//     wire" — it is the shape of the bytes in the Keychain record, and it is
//     compiled per adapter;
//   * the panel type answers "how many fields does the sheet draw, and what are
//     they called" — it is derived from a manifest's human-readable
//     `authModes` strings.
//
// They must agree, and `CompositeCredentialContracts` asserts that for every
// onboarded provider: a provider custodied as a composite must render a
// multi-field panel body, and a single-token provider a single-field one. That
// check is the whole reason two lanes can own the two halves.

/// One typed field of a provider credential.
///
/// The raw values are stable on disk (they are written into the envelope), so
/// they are spelled out rather than derived from the case order.
public enum CompositeCredentialField: UInt8, Codable, Sendable, CaseIterable, Hashable {
    /// The single opaque token of a non-composite credential.
    case token = 1
    /// The public half of a pair: Twilio's Account SID or API Key SID,
    /// MongoDB Atlas's public key, Auth0's client id. Identifying, not secret
    /// on its own — but it is held inside the protected record anyway, because
    /// a half-credential in plaintext metadata is a fingerprint of the other
    /// half's owner and because the two must rotate together.
    case identifier = 2
    /// The secret half: Twilio's Auth Token or API Key Secret, Atlas's private
    /// key, Auth0's client secret.
    case secret = 3
    /// A whole document whose contents are secret — Firebase's service-account
    /// JSON. It is one field like any other; nothing here parses it.
    case document = 4
    // BL-117 (D51), spec §1.3. The three raw values the two new credential
    // classes need. **All three are reserved in the AWS commit even though only
    // `.accessKeyPair`'s existing fields are used by it**, because a raw value
    // is on-disk stable: a later slot that picked 5 for something else would
    // make two writers of the same envelope disagree about what tag 5 means,
    // and the envelope has no version byte beyond `VLTC1` to tell them apart.
    /// OCI's composed `keyId`: `<TENANCY_OCID>/<USER_OCID>/<KEY_FINGERPRINT>`
    /// (Oracle, read 2026-09-14). Published, not secret — see `isSecret`.
    case keyIdentifier = 5
    /// A PEM private key: OCI's API signing key, Google's service-account key.
    /// Secret.
    case privateKey = 6
    /// The durable half of an authorization-code grant. Secret, and it is the
    /// connection: it is what a revocation revokes (§2.2).
    case refreshToken = 7

    /// Whether a projection that contains this field's value is a leak.
    ///
    /// The identifier half deliberately is not. Twilio's Account SID, Atlas's
    /// public key and Auth0's client id are *published* identifiers: the SID
    /// appears in every Twilio resource URI and is the account's name in the
    /// Console. It is held inside the protected record because it must rotate
    /// with its secret and because a half-credential in plaintext metadata
    /// fingerprints the other half's owner — but refusing to project it would
    /// mean a Twilio connection could never record which account it is, which
    /// is the one thing verification exists to establish.
    public var isSecret: Bool {
        switch self {
        case .token, .secret, .document, .privateKey, .refreshToken: true
        // BL-117 §1.3, on exactly the reasoning the `identifier` comment above
        // gives. OCI's `keyId` is "<TENANCY_OCID>/<USER_OCID>/<KEY_FINGERPRINT>"
        // (Oracle, read 2026-09-14), all three of which are published
        // identifiers; refusing to project it would leave an OCI connection
        // unable to say which tenancy it is, which is the one thing
        // verification exists to establish.
        case .identifier, .keyIdentifier: false
        }
    }

    /// What the connect panel labels the field. The panel is the UI lane's
    /// (BL-084); this is the manifest side of the same contract.
    public var defaultLabel: String {
        switch self {
        case .token: "API key"
        case .identifier: "Account SID"
        case .secret: "Auth token"
        case .document: "Service account JSON"
        case .keyIdentifier: "Key ID"
        case .privateKey: "Private key"
        case .refreshToken: "Refresh token"
        }
    }
}

/// What a provider's credential is made of.
///
/// A kind is a compiled list of typed fields plus the rule for how they reach
/// the wire. Adding a provider whose credential is a digest key pair, an
/// OAuth2 client-credentials pair or a service-account document is a new case
/// here and a manifest line — not a change to the envelope, the vault, the
/// broker or the transport, all of which see one `VaultSecret` either way.
public enum CompositeCredentialKind: String, Codable, Sendable, CaseIterable, Hashable {
    /// One opaque token. Every wave-1 provider, and most of wave 2.
    case singleToken
    /// An identifier and a secret, sent together as HTTP basic authentication.
    /// Twilio's Account SID plus Auth Token is the wave-2 example, and
    /// Twilio's own API Key SID plus Secret has the same shape.
    case identifierAndSecret
    /// BL-117 §1.3. An AWS access key ID and secret access key, which sign
    /// rather than travel.
    ///
    /// **Deliberately not `.identifierAndSecret`**, whose documented rule one
    /// case above is *"sent together as HTTP basic authentication"*. An AWS
    /// pair is never sent at all: the secret access key is the key to the
    /// four-step HMAC chain and the access key ID appears only inside the
    /// `Credential=` scope of the computed `Authorization` value. Reusing the
    /// case would make the custody type lie about the wire, which is what
    /// PW-H2 — say where the credential actually goes — exists to stop.
    case accessKeyPair
    /// BL-117 §1.3. A Microsoft Entra application (client) ID and client
    /// secret, which are **exchanged** at a token endpoint rather than sent to
    /// the resource host.
    ///
    /// Deliberately not `.identifierAndSecret` for the same reason
    /// `.accessKeyPair` is not: that case's documented rule is *"sent together
    /// as HTTP basic authentication"*, and this pair is never sent that way.
    /// Microsoft's own documented request puts `client_id` and `client_secret`
    /// in an `application/x-www-form-urlencoded` **body** (read 2026-09-13) —
    /// though the page notes the basic form is *also* supported, which is
    /// exactly the ambiguity that makes reusing the basic case a lie about the
    /// wire this connection uses. And the resource host never sees either half:
    /// it sees the minted token. PW-H2 — say where the credential actually
    /// goes — is what this separation exists for.
    case clientIDAndSecret
    /// BL-117's Google Cloud slot (D51, spec §7.3). A Google service-account
    /// key: the account's `client_email`, the RSA `private_key` that signs the
    /// assertion, and the `private_key_id` that becomes the JWT's `kid`.
    ///
    /// **A deliberate correction to §1.3, which names `.serviceAccountDocument`
    /// with a single `document` field.** The argument for one field is that the
    /// key arrives as a JSON file and storing it whole loses nothing. Building
    /// it found three reasons it loses something, and the third is a security
    /// property rather than an ergonomic one:
    ///
    ///   1. **`token_uri` has to be pinned, and pinning is only meaningful at
    ///      paste.** The document carries a customer-supplied `token_uri`. A
    ///      doctored key file would aim a signed assertion — a bearer of the
    ///      service account's own identity — at another host. The compiled
    ///      route table would refuse the URL, so nothing would leave the Mac;
    ///      but the refusal would land on every request, and the human would
    ///      read it as a broken connection rather than as a bad file. Refusing
    ///      the paste is the fail-closed answer, and it needs the parse.
    ///   2. **A `document` field means a JSON parse over secret bytes on every
    ///      signature.** §2.1 requires the PEM to be read inside the borrow, so
    ///      a stored document would put `JSONSerialization` inside that borrow
    ///      once per request, each time materialising the PEM as a Swift
    ///      `String` that cannot be zeroed. Parsing once, at paste, through
    ///      `ServiceAccountKey`'s byte lift means it is never a `String` at all.
    ///   3. **This is what BL-089 wrote the envelope for** — *"several typed
    ///      values that are only meaningful together"*, in its own words, with
    ///      Firebase's service-account document named as an example.
    ///
    /// What the correction gives up is recorded rather than glossed: the fields
    /// Google's file carries and Vaultage drops — `project_id`, `client_id`,
    /// `auth_uri`, `auth_provider_x509_cert_url`, `client_x509_cert_url`,
    /// `universe_domain` — are not recoverable from the vault afterwards. None
    /// is read by a compiled route, runbook §4 step 7 says to drop what the
    /// connection does not need, and re-pasting the file is the recovery path a
    /// rotated key needs in any case.
    case serviceAccountKey
    /// BL-117's GitHub slot (D51, spec §1.3 and §2.2). The two halves of an
    /// **authorization-code grant**: the access token the provider issued and
    /// the refresh token that renews it.
    ///
    /// **What custody means here is §2.2's split, and it is the reason this kind
    /// exists at all.** An authorization-code grant yields two things and only
    /// one of them is a vault value:
    ///
    /// > *"The durable half of a grant is a vault value. The short-lived half
    /// > never is."*
    ///
    /// So the `.refreshToken` field **is** the connection — it is long-lived, it
    /// is what a revocation revokes, and it is sealed exactly as a pasted API
    /// key is. The `.token` field is the access token as it stood at the last
    /// exchange; it is stored beside its sibling rather than derived afresh on
    /// every call for one reason, which is that GitHub's user access token
    /// lasts eight hours and re-running a **browser ceremony** to get one is not
    /// a thing a background read can do. It is still never a delivery source
    /// (§4.4 item 4) and Rule C still bounds the copy the broker holds in
    /// memory.
    ///
    /// **Both fields are required, deliberately.** Slack's shape — a bot token
    /// that does not expire, so the durable half *is* the access token and there
    /// is no refresh at all (§8.2) — is a **different** custody kind and will be
    /// one when Slack's slot lands. Declaring `.refreshToken` optional here to
    /// accommodate it in advance would let a GitHub connection be sealed with no
    /// way to renew, which is a connection that silently dies in eight hours.
    /// `optionalFields` stays empty and the envelope refuses a missing half.
    ///
    /// **Not `.identifierAndSecret`, and not `.clientIDAndSecret`**, for the
    /// reason every kind in this file is its own: neither half is an identifier,
    /// both are secret, and neither is ever sent as basic authentication. PW-H2
    /// — say where the credential actually goes — is what the separation is for.
    case userGrant

    public var fields: [CompositeCredentialField] {
        switch self {
        case .singleToken: [.token]
        case .identifierAndSecret: [.identifier, .secret]
        // The same two typed fields, because an access key ID *is* an
        // identifier and a secret access key *is* a secret. What differs is the
        // class that operates them, which is why this is a separate kind and
        // not a separate field list.
        case .accessKeyPair: [.identifier, .secret]
        // Again the same two, and again the class is what differs: the
        // identifier is the application (client) ID, which appears in every
        // token request and is not secret, and the secret is the client secret,
        // which is the only thing in the body a byte scan must never see come
        // back.
        case .clientIDAndSecret: [.identifier, .secret]
        // The service account's email, the id of the key that signs, and the
        // PEM itself. The order is the order the signer reads them in: `iss`,
        // then the `kid` header, then the key.
        case .serviceAccountKey: [.identifier, .keyIdentifier, .privateKey]
        // The order is the order §2.2 reasons about them in: the short-lived
        // half first, because it is what a request carries, and the durable half
        // second, because it is what the connection *is*.
        case .userGrant: [.token, .refreshToken]
        }
    }

    /// BL-117 §7.3. Fields a credential of this kind **may** omit.
    ///
    /// The envelope format has always tolerated an absent field — `layout`
    /// reads whatever tags are present and `withCompositeField` refuses one
    /// that is not — but `envelope(kind:values:)` insisted on every declared
    /// field, which is right for every kind that shipped before this one: a
    /// Twilio connection with no auth token is not half a credential, it is no
    /// credential.
    ///
    /// `private_key_id` is different, and Google is why. The `kid` header is
    /// documented as *optional* — *"the ID of the service account key used to
    /// sign the JWT"* (read 2026-09-13) — and an assertion verifies without it,
    /// because Google resolves the key from `iss` and the signature. A key file
    /// downloaded from the console always carries one, so this is a tolerance
    /// rather than a shape anybody will meet; declaring it optional is how the
    /// type says "absent is a documented state" instead of a builder guessing
    /// at a placeholder to keep `envelope` happy.
    ///
    /// It is deliberately **not** a general escape: the set is empty for every
    /// other kind, a required field's absence is still refused, and an optional
    /// field that *is* supplied is bounded exactly like a required one.
    public var optionalFields: Set<CompositeCredentialField> {
        switch self {
        case .singleToken, .identifierAndSecret, .accessKeyPair, .clientIDAndSecret: []
        case .serviceAccountKey: [.keyIdentifier]
        // Empty on purpose — see the case's own comment. A user grant with no
        // refresh token is a connection that dies in eight hours with nothing
        // able to renew it, and an absent half must not be the way that ships.
        case .userGrant: []
        }
    }

    /// The fields a credential of this kind must carry, which is what
    /// `envelope` refuses without.
    public var requiredFields: [CompositeCredentialField] {
        fields.filter { !optionalFields.contains($0) }
    }

    public var isComposite: Bool { fields.count > 1 }
}

/// The canonical envelope for a composite credential.
///
/// ```
/// "VLTC1" | fieldCount (1 byte) | ( tag (1 byte) | length (4 bytes, big-endian) | bytes ) *
/// ```
///
/// Fixed-width, self-describing and order-preserving, so decoding needs no
/// parser and no allocation beyond the one buffer it is handed. The magic
/// exists so a *single-token* credential that happens to start with the same
/// bytes cannot be mistaken for an envelope: a token must match the magic, the
/// declared field count and every declared length exactly, or it is read as
/// what it is, one opaque token.
public enum CompositeCredential {

    /// The most bytes one field may hold. A service-account document is a few
    /// kilobytes; anything larger is a file, and files have their own home
    /// (BL-079's attachment store).
    public static let maximumFieldBytes = 64 * 1024
    /// The most fields one credential may hold.
    public static let maximumFields = 8

    static let magic: [UInt8] = Array("VLTC1".utf8)
    private static let header = magic.count + 1
    private static let fieldHeader = 5

    // MARK: - Writing

    /// Builds the envelope for a kind's fields, in a buffer this function
    /// zeroes before it returns.
    ///
    /// The values arrive as `VaultSecret`s — one per field, each already
    /// custodied — so no field value is ever a `String` or a `Data` on this
    /// path. The result is one `VaultSecret` that the vault stores in the
    /// item's primary Keychain record.
    public static func envelope(
        kind: CompositeCredentialKind,
        values: [CompositeCredentialField: VaultSecret]
    ) throws -> VaultSecret {
        let fields = kind.fields
        guard fields.count <= maximumFields else {
            throw VaultageError.invalidInput("A credential may hold at most \(maximumFields) fields.")
        }
        var ordered: [(CompositeCredentialField, VaultSecret)] = []
        for field in fields {
            guard let value = values[field], value.byteCount > 0 else {
                // BL-117 §7.3. An **optional** field may be absent, and only
                // absent: a field supplied as zero bytes is still the caller
                // saying "here is the value" and is still refused, so an empty
                // text box cannot become a silently omitted key id.
                if kind.optionalFields.contains(field), values[field] == nil { continue }
                throw VaultageError.invalidInput("\(field.defaultLabel) is required for this provider.")
            }
            guard value.byteCount <= maximumFieldBytes else {
                throw VaultageError.invalidInput("\(field.defaultLabel) is larger than \(maximumFieldBytes) bytes.")
            }
            ordered.append((field, value))
        }
        guard !ordered.isEmpty else {
            throw VaultageError.invalidInput("A credential must carry at least one field.")
        }
        // A single-token credential is stored bare, exactly as wave 1 stored
        // it. Wrapping it would rewrite every existing Keychain record for no
        // benefit, and `withBytes` on it must keep returning the token.
        guard kind.isComposite else { return ordered[0].1 }

        let total = header + ordered.reduce(0) { $0 + fieldHeader + $1.1.byteCount }
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: total, alignment: 1)
        defer {
            SecretMemory.zero(scratch)
            scratch.deallocate()
        }
        SecretMemory.zero(scratch)
        var offset = 0
        for byte in magic {
            scratch[offset] = byte
            offset += 1
        }
        scratch[offset] = UInt8(ordered.count)
        offset += 1
        for (field, value) in ordered {
            scratch[offset] = field.rawValue
            offset += 1
            let length = UInt32(value.byteCount)
            for shift in stride(from: 24, through: 0, by: -8) {
                scratch[offset] = UInt8((length >> UInt32(shift)) & 0xFF)
                offset += 1
            }
            value.withBytes { raw in
                if let base = raw.baseAddress, raw.count > 0 {
                    scratch.baseAddress!.advanced(by: offset).copyMemory(from: base, byteCount: raw.count)
                }
            }
            offset += value.byteCount
        }
        return VaultSecret(bytes: UnsafeRawBufferPointer(scratch))
    }

    // MARK: - Reading

    /// The field layout inside an envelope: what is there and where, never a
    /// value. Returns nil for bytes that are not an envelope, which is what a
    /// single-token credential is.
    static func layout(_ raw: UnsafeRawBufferPointer) -> [(field: CompositeCredentialField, offset: Int, length: Int)]? {
        guard raw.count >= header else { return nil }
        for (index, byte) in magic.enumerated() where raw[index] != byte { return nil }
        let count = Int(raw[magic.count])
        guard count > 0, count <= maximumFields else { return nil }
        var entries: [(CompositeCredentialField, Int, Int)] = []
        var offset = header
        var seen = Set<UInt8>()
        for _ in 0 ..< count {
            guard offset + fieldHeader <= raw.count else { return nil }
            let tag = raw[offset]
            guard let field = CompositeCredentialField(rawValue: tag), seen.insert(tag).inserted else { return nil }
            offset += 1
            var length = 0
            for _ in 0 ..< 4 {
                length = (length << 8) | Int(raw[offset])
                offset += 1
            }
            guard length > 0, length <= maximumFieldBytes, offset + length <= raw.count else { return nil }
            entries.append((field, offset, length))
            offset += length
        }
        // Trailing bytes mean this is not the envelope it claims to be.
        guard offset == raw.count else { return nil }
        return entries
    }
}

public extension VaultSecret {

    /// Whether these bytes are a composite envelope. False for every
    /// single-token credential, including one that starts with the magic but
    /// does not decode — the check is the whole structure, not a prefix.
    var isComposite: Bool {
        var composite = false
        withBytes { composite = CompositeCredential.layout($0) != nil }
        return composite
    }

    /// Which typed fields this credential carries. Names only: no length, no
    /// offset and certainly no value crosses this boundary, so a caller that
    /// wants to render "Account SID • Auth token" can, and a caller that wants
    /// the values has to go through `withCompositeField`.
    var compositeFields: [CompositeCredentialField] {
        var fields: [CompositeCredentialField] = []
        withBytes { raw in
            fields = CompositeCredential.layout(raw)?.map(\.field) ?? [.token]
        }
        return fields
    }

    /// The scoped borrow of one typed field, with exactly the contract
    /// `withBytes` has: `Void`-returning, over an `UnsafeRawBufferPointer`, so
    /// the only way a value leaves is a deliberate copy into a caller-owned
    /// buffer.
    ///
    /// Asking a single-token credential for `.token` borrows the whole value,
    /// which is what a bare token is; asking it for anything else refuses.
    func withCompositeField(
        _ field: CompositeCredentialField,
        _ body: (UnsafeRawBufferPointer) throws -> Void
    ) throws {
        var failure: Error?
        var found = false
        try withBytes { raw in
            guard let layout = CompositeCredential.layout(raw) else {
                guard field == .token else { return }
                found = true
                do { try body(raw) } catch { failure = error }
                return
            }
            guard let entry = layout.first(where: { $0.field == field }) else { return }
            found = true
            let slice = UnsafeRawBufferPointer(
                start: raw.baseAddress!.advanced(by: entry.offset),
                count: entry.length
            )
            do { try body(slice) } catch { failure = error }
        }
        if let failure { throw failure }
        guard found else {
            throw VaultageError.invalidInput("This credential has no \(field.defaultLabel).")
        }
    }

    /// Whether any **secret** field of this credential occurs in a candidate
    /// string.
    ///
    /// `occurs(in:)` compares the *whole* stored value, which for a composite
    /// is the envelope — a shape no provider will ever echo. Every projection
    /// and every byte scan must therefore ask this instead, or a provider that
    /// returns the auth token it was authenticated with would sail straight
    /// through. Twilio does exactly that: its documented Account resource
    /// includes `auth_token`.
    ///
    /// The identifier half is excluded on purpose; see
    /// `CompositeCredentialField.isSecret`.
    func anySecretFieldOccurs(in candidate: String) -> Bool {
        let haystack = Array(candidate.utf8)
        var hit = false
        withBytes { raw in
            guard let layout = CompositeCredential.layout(raw) else {
                hit = Self.bytesOccur(raw, in: haystack)
                return
            }
            for entry in layout where !hit && entry.field.isSecret {
                let slice = UnsafeRawBufferPointer(
                    start: raw.baseAddress!.advanced(by: entry.offset),
                    count: entry.length
                )
                hit = Self.bytesOccur(slice, in: haystack)
            }
        }
        return hit
    }

    /// Byte-substring search with no allocation and no `String` copy of the
    /// needle — the same search `occurs(in:)` performs, factored out so a
    /// composite can run it once per field.
    ///
    /// BL-117 makes it `public` for the second needle (§2.5): a signed
    /// request's other live secret is the **computed signature**, which is not
    /// a field of any credential and therefore has no `VaultSecret` to ask.
    /// `ProviderContractSupportForSignedReplies` scans for it with exactly this
    /// search rather than writing a third one — the hoist `AccountAPITokens`
    /// records as the right answer when a scanner is about to be written twice.
    public static func bytesOccur(_ needle: UnsafeRawBufferPointer, in haystack: [UInt8]) -> Bool {
        guard needle.count > 0, haystack.count >= needle.count, let needleBase = needle.baseAddress else { return false }
        let limit = haystack.count - needle.count
        var found = false
        haystack.withUnsafeBytes { hay in
            guard let hayBase = hay.baseAddress else { return }
            var offset = 0
            while offset <= limit {
                if memcmp(hayBase.advanced(by: offset), needleBase, needle.count) == 0 {
                    found = true
                    return
                }
                offset += 1
            }
        }
        return found
    }

    /// `Basic base64(<username>:<credential>)`, built in buffers this method
    /// zeroes, for a provider that documents HTTP basic authentication with a
    /// fixed username — Mailgun's `api` is the wave-2 example.
    ///
    /// Residual: Swift `String` storage cannot be zeroed, the same residual
    /// `withAuthorizationHeaderValue` documents. The credential is never a
    /// `String` on the way in: it is copied into the scratch buffer as bytes
    /// and base64-encoded there.
    func withBasicAuthorizationHeaderValue(username: String, _ body: (String) -> Void) throws {
        guard username.range(of: "^[A-Za-z0-9._-]{1,64}$", options: .regularExpression) != nil else {
            throw VaultageError.invalidInput("A basic-auth username must be a short ASCII token.")
        }
        try withCompositeField(.token) { secret in
            try Self.emitBasic(username: Array(username.utf8), secret: secret, body)
        }
    }

    /// `Basic base64(<identifier field>:<secret field>)` for a composite
    /// credential — Twilio's Account SID and Auth Token.
    ///
    /// Both halves are borrowed, never copied into a `String`, and the joined
    /// plaintext exists only inside the buffer this method zeroes.
    func withCompositeBasicAuthorizationHeaderValue(_ body: (String) -> Void) throws {
        var identifier: [UInt8] = []
        defer { identifier.withUnsafeMutableBytes { SecretMemory.zero($0) } }
        try withCompositeField(.identifier) { raw in identifier = Array(raw) }
        try withCompositeField(.secret) { secret in
            try Self.emitBasic(username: identifier, secret: secret, body)
        }
    }

    private static func emitBasic(
        username: [UInt8],
        secret: UnsafeRawBufferPointer,
        _ body: (String) -> Void
    ) throws {
        guard bytesAreValidUTF8(secret) else {
            throw VaultageError.invalidInput("The protected credential is not valid UTF-8.")
        }
        let joinedCount = username.count + 1 + secret.count
        let joined = UnsafeMutableRawBufferPointer.allocate(byteCount: joinedCount, alignment: 1)
        defer {
            SecretMemory.zero(joined)
            joined.deallocate()
        }
        SecretMemory.zero(joined)
        joined.copyBytes(from: username)
        joined[username.count] = 0x3A // ':'
        if let base = secret.baseAddress, secret.count > 0 {
            joined.baseAddress!.advanced(by: username.count + 1).copyMemory(from: base, byteCount: secret.count)
        }
        // `Data(bytesNoCopy:)` with `.none` does not take ownership, so the
        // only buffer holding the joined plaintext is still the one zeroed
        // above; the base64 text it produces is credential-derived and is
        // handed straight to the header and dropped.
        var encoded = Data(bytesNoCopy: joined.baseAddress!, count: joinedCount, deallocator: .none)
            .base64EncodedString()
        var value = "Basic " + encoded
        body(value)
        value = ""
        encoded = ""
    }
}

// MARK: - The window scan

/// BL-117's GitHub slot (§2.5, §5.1) — **the partial-echo scan, hoisted.**
///
/// The Google slot found the gap and closed it for one credential:
/// `VaultSecret.anySecretFieldOccurs(in:)` looks for a stored field's bytes
/// *inside* a candidate, so it sees a reply that echoes a credential **whole**
/// and is structurally blind to one that echoes **part** of it. For every
/// credential before an RSA key that was academic — a bearer token is short, and
/// half of one is not a credential. It stopped being academic at 1.7 KiB, and
/// `RSAPrivateKeyMaterial` grew a 32-byte window scan over the key's base64
/// body.
///
/// **This slot is where that scan stops being about RSA keys.** §5.1 says a
/// receipt may never carry the `id_token`, *"or any prefix or length"* of the
/// things it lists — and an `id_token` is a JWT: hundreds of bytes, three
/// dot-separated spans, each of which is on its own a long run of base64url
/// that a provider error body or a debug field could echo without echoing the
/// whole token. That is the same shape as the key and it needs the same scan, so
/// the scan is hoisted here rather than written a second time. That is the
/// `AccountAPITokens` rule applied to a scanner for the third time in this
/// ticket, and the reason the file it lands in is this one: it sits beside
/// `bytesOccur`, which is the whole-needle search it generalises.
///
/// **Why thirty-two bytes.** It is the number the Google slot chose and the
/// reason carries: thirty-two base64 characters are twenty-four bytes of
/// entropy, and a false positive would need a reply to contain twenty-four
/// contiguous bytes of this exact secret by coincidence. Keeping one window for
/// both callers is deliberate — two numbers would be two things to justify.
///
/// **Why Rabin-Karp.** One linear pass over each side. The naive form is one
/// search per window, which for a 1.7 KiB key against a 512 KiB body is sixteen
/// hundred searches of half a megabyte — the kind of cost that gets a control
/// removed later rather than kept. Every hash hit is verified byte for byte, so
/// a collision cannot produce a refusal.
public enum SecretWindowScan {

    /// Thirty-two bytes — see above.
    public static let window = 32

    /// Whether any `window`-byte run of `needle` occurs in `haystack`.
    ///
    /// - Parameter ignoringWhitespace: strips spaces, tabs, CR and LF from
    ///   **both** sides first, so a provider that echoed a secret with its own
    ///   line breaks is caught as readily as one that echoed it verbatim. That
    ///   is strictly stronger than matching the stored layout and it costs one
    ///   linear pass. The PEM caller needs it; the JWT caller sets it too,
    ///   because a JSON pretty-printer wrapping a long string is exactly the
    ///   shape it would otherwise miss.
    public static func occurs(
        needle: UnsafeRawBufferPointer,
        in haystack: [UInt8],
        ignoringWhitespace: Bool = true
    ) -> Bool {
        var stripped: [UInt8] = []
        stripped.reserveCapacity(needle.count)
        for byte in needle where !ignoringWhitespace || !isWhitespace(byte) { stripped.append(byte) }
        defer { stripped.withUnsafeMutableBytes { SecretMemory.zero($0) } }
        var hay: [UInt8] = []
        hay.reserveCapacity(haystack.count)
        for byte in haystack where !ignoringWhitespace || !isWhitespace(byte) { hay.append(byte) }
        return occurs(strippedNeedle: stripped, strippedHaystack: hay)
    }

    /// The same scan over two arrays whose whitespace the caller has already
    /// removed. `RSAPrivateKeyMaterial` uses this arm because it strips the PEM
    /// armour at the same pass and must not strip it twice.
    public static func occurs(strippedNeedle needle: [UInt8], strippedHaystack hay: [UInt8]) -> Bool {
        guard needle.count >= window, hay.count >= window else { return false }

        let base: UInt64 = 257
        var power: UInt64 = 1
        for _ in 1 ..< window { power = power &* base }

        var offsets: [UInt64: [Int]] = [:]
        var rolling: UInt64 = 0
        for index in 0 ..< window { rolling = rolling &* base &+ UInt64(needle[index]) }
        offsets[rolling, default: []].append(0)
        for index in window ..< needle.count {
            rolling = (rolling &- UInt64(needle[index - window]) &* power) &* base &+ UInt64(needle[index])
            offsets[rolling, default: []].append(index - window + 1)
        }

        var current: UInt64 = 0
        for index in 0 ..< window { current = current &* base &+ UInt64(hay[index]) }
        if verified(current, at: 0, offsets: offsets, needle: needle, hay: hay) { return true }
        for index in window ..< hay.count {
            current = (current &- UInt64(hay[index - window]) &* power) &* base &+ UInt64(hay[index])
            if verified(current, at: index - window + 1, offsets: offsets, needle: needle, hay: hay) { return true }
        }
        return false
    }

    /// A hash hit, verified byte for byte. A collision produces no refusal.
    private static func verified(_ hash: UInt64, at start: Int, offsets: [UInt64: [Int]], needle: [UInt8], hay: [UInt8]) -> Bool {
        guard let candidates = offsets[hash] else { return false }
        for candidate in candidates {
            var equal = true
            for offset in 0 ..< window where needle[candidate + offset] != hay[start + offset] {
                equal = false
                break
            }
            if equal { return true }
        }
        return false
    }

    static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }
}

public extension VaultSecret {
    /// Whether any 32-byte run of this secret occurs in a candidate body.
    ///
    /// The partial-echo sibling of `occurs(in:)`, and the shape §5.1's *"or any
    /// prefix or length of any of them"* actually needs. The needle stays a
    /// `VaultSecret` and is borrowed once, for the reason
    /// `ProviderContractSupportForSignedReplies` gives about the minted token:
    /// materialising a live secret as a `String` in order to scan for it is the
    /// exact leak the scan exists to catch.
    func partiallyOccurs(in body: Data) -> Bool {
        let haystack = Array(body)
        var found = false
        withBytes { raw in found = SecretWindowScan.occurs(needle: raw, in: haystack) }
        return found
    }
}
