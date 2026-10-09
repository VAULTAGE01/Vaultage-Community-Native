import CryptoKit
import Foundation
import Darwin

/// Deterministic zeroing primitives for credential-bearing allocations.
///
/// `memset_s` is the platform's non-elidable zeroing call: unlike `memset`, the
/// C standard forbids the compiler from removing it as a dead store, so a
/// buffer that is about to be deallocated is still cleared.
public enum SecretMemory {
    public static func zero(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = memset_s(base, buffer.count, 0, buffer.count)
    }

    /// Best-effort page pinning so credential bytes are not written to the swap
    /// file. It fails silently: `mlock` needs no privilege for small regions on
    /// macOS, but a failure must not make a credential unusable.
    static func lock(_ buffer: UnsafeMutableRawBufferPointer) -> Bool {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return false }
        return mlock(base, buffer.count) == 0
    }

    static func unlock(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = munlock(base, buffer.count)
    }
}

/// One manually managed credential allocation.
///
/// `Data` cannot be used for custody: its storage is copy-on-write, Foundation
/// may reallocate it, and there is no supported way to zero the buffer it hands
/// back. This class owns exactly one allocation, pins it where the OS allows,
/// and zeroes it before deallocation.
final class SecretStorage: @unchecked Sendable {
    let bytes: UnsafeMutableRawBufferPointer
    private let pinned: Bool

    init(copying source: UnsafeRawBufferPointer) {
        bytes = UnsafeMutableRawBufferPointer.allocate(byteCount: max(source.count, 1), alignment: 1)
        SecretMemory.zero(bytes)
        if let base = source.baseAddress, source.count > 0 {
            bytes.baseAddress!.copyMemory(from: base, byteCount: source.count)
        }
        pinned = SecretMemory.lock(bytes)
        count = source.count
    }

    /// The logical length. The allocation is at least one byte so an empty
    /// credential still has a stable, zeroable address.
    let count: Int

    var readable: UnsafeRawBufferPointer {
        UnsafeRawBufferPointer(start: bytes.baseAddress, count: count)
    }

    deinit {
        SecretMemory.zero(bytes)
        if pinned { SecretMemory.unlock(bytes) }
        bytes.deallocate()
    }
}

/// Credential bytes with no `Codable`, no printable form, and no borrow API
/// that can return a copy.
///
/// The scoped borrow is deliberately `Void`-returning over an
/// `UnsafeRawBufferPointer`, so a caller cannot write
/// `let token = secret.withBytes { String(...) }`. Trusted provider code asks
/// for the exact derived form it needs — an authentication header value, a JSON
/// string encoding, a byte comparison — and Vaultage builds that form in a
/// buffer it zeroes itself.
public struct VaultSecret: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let storage: SecretStorage

    public init(_ bytes: Data) {
        storage = bytes.withUnsafeBytes { SecretStorage(copying: $0) }
    }

    public init(bytes: UnsafeRawBufferPointer) {
        storage = SecretStorage(copying: bytes)
    }

    public var byteCount: Int { storage.count }

    public var isEmpty: Bool { storage.count == 0 }

    /// Whether the bytes are well-formed UTF-8, decided **without building a
    /// `String`** (RP-09).
    ///
    /// This used to be `String(bytes: raw, encoding: .utf8) != nil`, which
    /// materialized a full copy of the bare credential and discarded it. Swift
    /// `String` storage cannot be zeroed, so every validity check left an
    /// unzeroable plaintext copy in freed heap memory — on the hot custody
    /// paths, including `withAuthorizationHeaderValue`, which exists precisely
    /// to avoid materializing the bare credential and then did so on its first
    /// line.
    ///
    /// The scan below accepts exactly what Unicode's UTF-8 definition accepts:
    /// no overlong encodings, no surrogate code points, nothing above U+10FFFF,
    /// no truncated sequence. It allocates nothing.
    public var isValidUTF8: Bool {
        var valid = false
        withBytes { raw in valid = Self.bytesAreValidUTF8(raw) }
        return valid
    }

    /// PW-L4. Whether any byte is an ASCII control character — C0, DEL, or a
    /// C1 byte that a UTF-8 credential cannot legitimately begin a sequence
    /// with. A tab and a leading space survive Foundation's header API and a
    /// NUL becomes a space, so "it happened to work" is not a reason to allow
    /// any of them in a value that must be sent verbatim.
    var carriesControlCharacter: Bool {
        var found = false
        withBytes { raw in
            for byte in raw where byte < 0x20 || byte == 0x7F {
                found = true
                break
            }
        }
        return found
    }

    static func bytesAreValidUTF8(_ raw: UnsafeRawBufferPointer) -> Bool {
        var index = 0
        let count = raw.count
        while index < count {
            let byte = raw[index]
            let length: Int
            var scalar: UInt32
            switch byte {
            case 0x00 ... 0x7F:
                index += 1
                continue
            // 0xC0 and 0xC1 are excluded: they can only begin an overlong
            // two-byte encoding of an ASCII scalar.
            case 0xC2 ... 0xDF:
                length = 2
                scalar = UInt32(byte & 0x1F)
            case 0xE0 ... 0xEF:
                length = 3
                scalar = UInt32(byte & 0x0F)
            case 0xF0 ... 0xF4:
                length = 4
                scalar = UInt32(byte & 0x07)
            default:
                return false
            }
            guard count - index >= length else { return false }
            for offset in 1 ..< length {
                let continuation = raw[index + offset]
                guard continuation & 0xC0 == 0x80 else { return false }
                scalar = (scalar << 6) | UInt32(continuation & 0x3F)
            }
            switch length {
            case 2:
                guard scalar >= 0x80 else { return false }
            case 3:
                guard scalar >= 0x800, !(0xD800 ... 0xDFFF).contains(scalar) else { return false }
            default:
                guard scalar >= 0x1_0000, scalar <= 0x10_FFFF else { return false }
            }
            index += length
        }
        return true
    }

    /// The narrow scoped borrow. The closure returns `Void` on purpose: the
    /// only way to move credential bytes out of this call is to copy them
    /// deliberately into a caller-owned buffer, which is reviewable, rather
    /// than accidentally through a returned `Data` or `String`.
    public func withBytes(_ body: (UnsafeRawBufferPointer) throws -> Void) rethrows {
        try body(storage.readable)
    }

    /// Byte equality with a candidate string, used to reject provider responses
    /// that echo the credential. No `String` copy of the credential is made.
    public func matches(_ candidate: String) -> Bool {
        var equal = false
        let candidateBytes = Array(candidate.utf8)
        withBytes { raw in
            guard raw.count == candidateBytes.count else { return }
            equal = candidateBytes.withUnsafeBytes { other in
                guard let left = raw.baseAddress, let right = other.baseAddress else { return raw.count == 0 }
                return memcmp(left, right, raw.count) == 0
            }
        }
        return equal
    }

    /// Substring containment of the credential bytes inside a candidate string,
    /// used to reject provider fields that embed the credential. This replaces
    /// the previous `candidate.contains(tokenString)` checks, which required a
    /// full `String` copy of the credential on every provider response.
    public func occurs(in candidate: String) -> Bool {
        let haystack = Array(candidate.utf8)
        var found = false
        withBytes { needle in
            guard needle.count > 0, haystack.count >= needle.count else { return }
            let limit = haystack.count - needle.count
            haystack.withUnsafeBytes { hay in
                guard let hayBase = hay.baseAddress, let needleBase = needle.baseAddress else { return }
                var offset = 0
                while offset <= limit {
                    if memcmp(hayBase.advanced(by: offset), needleBase, needle.count) == 0 {
                        found = true
                        return
                    }
                    offset += 1
                }
            }
        }
        return found
    }

    /// Builds `"<scheme> <credential>"` in a buffer this method zeroes, hands it
    /// to the transport as the one `String` Foundation's header API requires,
    /// and drops the reference immediately afterwards.
    ///
    /// Residual: Swift `String` storage cannot be zeroed. See
    /// IMPLEMENTATION.md, "Secret material in memory".
    public func withAuthorizationHeaderValue(scheme: String, _ body: (String) -> Void) throws {
        guard scheme.range(of: "^[A-Za-z]{1,16}$", options: .regularExpression) != nil else {
            throw VaultageError.invalidInput("An authentication scheme must be a short ASCII token.")
        }
        try withPrefixedHeaderValue(prefix: "\(scheme) ", body)
    }

    /// BL-088. The credential as a header value with **no** scheme prefix, for
    /// the providers whose documented credential header is not `Authorization`
    /// — Google Gemini's `x-goog-api-key` is the wave-1 example. The buffer
    /// discipline, the UTF-8 guard and the residual `String` limitation are
    /// exactly those of `withAuthorizationHeaderValue(scheme:)`; only the
    /// prefix differs. There is deliberately no way to pass an arbitrary
    /// prefix from outside this type.
    public func withBareHeaderValue(_ body: (String) -> Void) throws {
        try withPrefixedHeaderValue(prefix: "", body)
    }

    private func withPrefixedHeaderValue(prefix scheme: String, _ body: (String) -> Void) throws {
        guard isValidUTF8 else {
            throw VaultageError.invalidInput("The protected credential is not valid UTF-8.")
        }
        // PW-L4, from the independent pass over the provider waves. There is no
        // header-injection path — `URLRequest.setValue` with a CR or an LF in
        // the value drops the header entirely, which the pass proved against
        // Foundation directly — and that is precisely the problem: the request
        // then goes to the provider with **no credential**, the provider answers
        // 401, and the user is told their token was refused. They mint another
        // token with the same trailing newline. A pasted credential carrying a
        // control character is refused here instead, as the input error it is.
        guard !carriesControlCharacter else {
            throw VaultageError.invalidInput("The saved credential contains a control character, so it cannot be sent as a header. Re-copy it without a line break or a tab.")
        }
        let prefix = Array(scheme.utf8)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: prefix.count + byteCount, alignment: 1)
        defer {
            SecretMemory.zero(scratch)
            scratch.deallocate()
        }
        scratch.copyBytes(from: prefix)
        withBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 {
                scratch.baseAddress!.advanced(by: prefix.count).copyMemory(from: base, byteCount: raw.count)
            }
        }
        var value = String(decoding: UnsafeRawBufferPointer(scratch), as: UTF8.self)
        body(value)
        value = ""
    }

    /// The child-process environment value for `--run` delivery. This is the one
    /// mode that deliberately gives up the no-secret-to-process property, so the
    /// `String` is created here, handed straight to the spawn call, and released.
    ///
    /// Residual: the same `String` limitation as the header value applies, and
    /// the kernel copies the value into the child's environment block.
    public func withRuntimeEnvironmentValue(_ body: (String) -> Void) throws {
        guard isValidUTF8 else {
            throw VaultageError.invalidInput("The protected credential is not valid UTF-8.")
        }
        var value = ""
        withBytes { raw in
            value = String(decoding: raw, as: UTF8.self)
        }
        guard !value.contains("\0") else {
            throw VaultageError.invalidInput("The protected credential cannot be delivered as an environment value.")
        }
        body(value)
        value = ""
    }

    /// BL-062. The one human-facing disclosure form: the value as text, for an
    /// on-screen reveal or a concealed pasteboard write. It exists so that the
    /// two human destinations share one bounded, validated conversion rather
    /// than each inventing their own.
    ///
    /// It is deliberately the same shape as the other two derived forms — a
    /// `Void`-returning closure — so a caller cannot write
    /// `let text = secret.withDisclosureText { $0 }`. A UI that needs to display
    /// the text copies it deliberately, inside the closure, into state it owns
    /// and clears.
    ///
    /// Residual: Swift `String` storage cannot be zeroed. See
    /// IMPLEMENTATION.md, "Secret material in memory".
    public func withDisclosureText(_ body: (String) -> Void) throws {
        guard isValidUTF8 else {
            throw VaultageError.invalidInput("The protected value is not text and cannot be revealed or copied.")
        }
        guard byteCount > 0, byteCount <= humanDisclosureMaximumBytes else {
            throw VaultageError.invalidInput("The protected value is empty or too large to reveal or copy.")
        }
        var value = ""
        withBytes { raw in
            value = String(decoding: raw, as: UTF8.self)
        }
        body(value)
        value = ""
    }

    // MARK: - BL-117 (D51) §7.1: deriving with the secret rather than sending it

    /// The HMAC-SHA256 of `message` under these bytes, **as a new
    /// `VaultSecret`**, so each link of a derivation chain is itself zeroed on
    /// release.
    ///
    /// This is the whole of what SigV4 needs from the secret access key, and it
    /// is deliberately the whole of what BL-117 adds. The alternative every
    /// signing implementation reaches for first is a raw-bytes accessor —
    /// `var bytes: Data` — so the signer can build the four-step chain itself.
    /// That would hand every caller in the process a zeroable-copy-free path to
    /// the stored secret, for the benefit of one adapter, and it is why the
    /// spec asks for the derivation to stay inside the type: *"Not a raw-bytes
    /// accessor. Two additions that keep the derivation inside the type."*
    ///
    /// `message` is a `Data` on purpose: the message of every link in SigV4's
    /// chain is public — a date stamp, a region code, a service code, the
    /// literal `aws4_request`, and the string to sign, which contains only the
    /// algorithm, a timestamp, the credential scope and a hash. No secret is
    /// ever the *message*, only ever the key.
    ///
    /// Residual R4a, judged small by the independent pass and unchanged here:
    /// `SymmetricKey` copies the key bytes into storage CryptoKit zeroes on
    /// release, and `HashedAuthenticationCode` is a fixed-size value type.
    /// Neither is a `String`, and neither outlives this call.
    public func hmacSHA256(over message: Data) -> VaultSecret {
        var derived: VaultSecret?
        withBytes { raw in
            let key = SymmetricKey(data: raw)
            var code = HMAC<SHA256>.authenticationCode(for: message, using: key)
            derived = code.withUnsafeBytes { VaultSecret(bytes: $0) }
            // Overwrite the local before it goes out of scope. The value is a
            // fixed-size struct rather than a heap allocation, so this is the
            // most that can be done for it and is worth the line.
            code = HMAC<SHA256>.authenticationCode(for: Data(), using: SymmetricKey(size: .bits256))
            _ = code
        }
        // Unreachable: `withBytes` always calls its closure. Refusing to invent
        // an empty secret is still the right failure, because an empty key
        // would produce a *valid-looking* HMAC that no provider would accept.
        guard let derived else { return VaultSecret(Data()) }
        return derived
    }

    /// `"AWS4" + self`, in a buffer this method zeroes — the first link of
    /// SigV4's derivation, whose key is the literal `AWS4` concatenated with
    /// the secret access key (AWS, read 2026-09-13).
    ///
    /// There is deliberately no way to pass an arbitrary prefix from outside
    /// the type, which is the same rule `withPrefixedHeaderValue` already
    /// follows and for the same reason: a general `prefixed(_:)` would be a
    /// way to build any string that happens to contain the credential, which is
    /// precisely the shape this type exists to refuse.
    public func aws4Prefixed() -> VaultSecret {
        let prefix = Array("AWS4".utf8)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: prefix.count + byteCount, alignment: 1)
        defer {
            SecretMemory.zero(scratch)
            scratch.deallocate()
        }
        SecretMemory.zero(scratch)
        scratch.copyBytes(from: prefix)
        withBytes { raw in
            if let base = raw.baseAddress, raw.count > 0 {
                scratch.baseAddress!.advanced(by: prefix.count).copyMemory(from: base, byteCount: raw.count)
            }
        }
        return VaultSecret(bytes: UnsafeRawBufferPointer(scratch))
    }

    public var description: String { "VaultSecret(redacted)" }
    public var debugDescription: String { "VaultSecret(redacted)" }
    /// An empty mirror keeps `dump`, `String(describing:)` and any reflective
    /// logger away from the backing allocation.
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// Derived secret material — currently a provider request body that embeds a
/// credential. It has the same custody properties as `VaultSecret`: one owned
/// allocation, zeroed on release, no `Codable`, no printable form.
public struct SecretPayload: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let storage: SecretStorage

    init(copying bytes: UnsafeRawBufferPointer) {
        storage = SecretStorage(copying: bytes)
    }

    /// Wraps already-assembled bytes. `SecretPayloadBuilder` is the credential
    /// path; this initializer exists for structural, credential-free bodies and
    /// for deterministic test fixtures.
    public init(copying bytes: Data) {
        storage = bytes.withUnsafeBytes { SecretStorage(copying: $0) }
    }

    public var byteCount: Int { storage.count }

    public func withBytes(_ body: (UnsafeRawBufferPointer) throws -> Void) rethrows {
        try body(storage.readable)
    }

    public var description: String { "SecretPayload(redacted)" }
    public var debugDescription: String { "SecretPayload(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// Builds a bounded JSON request body that embeds one credential.
///
/// The builder owns a fixed-capacity allocation, so appending never reallocates
/// and never leaves a stale plaintext copy behind, and it zeroes that
/// allocation when it is released.
public final class SecretPayloadBuilder {
    private var buffer: UnsafeMutableRawBufferPointer
    private var count = 0

    public init(capacity: Int) {
        buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: max(capacity, 1), alignment: 1)
        SecretMemory.zero(buffer)
    }

    deinit {
        SecretMemory.zero(buffer)
        buffer.deallocate()
    }

    public var byteCount: Int { count }

    /// Appends non-secret structural text. The caller is responsible for having
    /// validated any interpolated identifier against its own allowlist.
    public func append(_ text: String) throws {
        try appendBytes(Array(text.utf8))
    }

    /// Appends the JSON string encoding of the credential, including the
    /// surrounding quotation marks, without ever materializing the credential
    /// as a `String`.
    public func appendJSONString(of secret: VaultSecret) throws {
        guard secret.isValidUTF8 else {
            throw VaultageError.invalidInput("The protected credential is not valid UTF-8.")
        }
        try appendBytes([0x22])
        var failure: Error?
        secret.withBytes { raw in
            for byte in raw {
                do {
                    try appendBytes(Self.jsonEscape(byte))
                } catch {
                    failure = error
                    return
                }
            }
        }
        if let failure { throw failure }
        try appendBytes([0x22])
    }

    public func finish() -> SecretPayload {
        SecretPayload(copying: UnsafeRawBufferPointer(start: buffer.baseAddress, count: count))
    }

    /// BL-117 (D51) §2.4. Internal rather than private since the exchange body
    /// builder: `appendFormValue(of:field:)` lives in `TokenExchange.swift`
    /// beside the compiled unreserved set it encodes against, and `private`
    /// here is file scope. The capacity bound below is what it relies on, and
    /// nothing outside this module can reach either.
    func appendBytes(_ bytes: [UInt8]) throws {
        guard count + bytes.count <= buffer.count else {
            throw VaultageError.invalidInput("The provider request body exceeds its fixed capacity.")
        }
        guard !bytes.isEmpty, let base = buffer.baseAddress else { return }
        bytes.withUnsafeBytes { source in
            base.advanced(by: count).copyMemory(from: source.baseAddress!, byteCount: bytes.count)
        }
        count += bytes.count
    }

    /// Conservative JSON string escaping. Bytes above 0x7F are UTF-8
    /// continuation bytes of an already validated sequence and pass through.
    private static func jsonEscape(_ byte: UInt8) -> [UInt8] {
        switch byte {
        case 0x22: return Array("\\\"".utf8)
        case 0x5C: return Array("\\\\".utf8)
        case 0x08: return Array("\\b".utf8)
        case 0x0C: return Array("\\f".utf8)
        case 0x0A: return Array("\\n".utf8)
        case 0x0D: return Array("\\r".utf8)
        case 0x09: return Array("\\t".utf8)
        case 0x00 ... 0x1F: return Array(String(format: "\\u%04x", Int(byte)).utf8)
        default: return [byte]
        }
    }
}
