import CryptoKit
import Darwin
import Foundation
import Security

// BL-079 — the encrypted attachment store.
//
// This is the third place in Vaultage where credential-class bytes exist, and
// the only one where they are written to disk. The argument that makes it
// acceptable is structural, and it is stated once here.
//
// **The disk holds ciphertext and nothing else.** A blob is an AES-256-GCM
// envelope sealed under a key derived from a 256-bit content key that lives in
// a user-presence Keychain record. Vaultage cannot open a blob without the OS
// asking the human first, and neither can anything that copies the metadata
// directory: there is no key material, no plaintext, no length-preserving
// encoding and no thumbnail anywhere under `attachments/`.
//
// **Import is hostile-file-safe because it does not interpret the file.** The
// bytes are bounded (10 MiB), sniffed by comparing a handful of leading bytes
// against fixed signatures, and sealed. Nothing decodes an image, renders a
// PDF, or parses a key before the seal. The one parser that does run —
// `Security.framework`'s X.509 reader, for a certificate's subject, issuer and
// expiry — runs on a file that already passed the DER/PEM sniff, produces
// metadata only, and cannot fail the import: an unparseable certificate is
// still sealed, and is simply filed as key material with no summary.
//
// **The content address is keyed.** `id` is an HMAC of the plaintext under the
// vault's content key, not a bare hash. That gives deduplication — the same
// screenshot imported twice is one blob — without giving anyone holding the
// directory the ability to confirm a guessed file. Donor: v1 native
// `VaultAttachmentSealer`, which derives its id and its per-attachment key the
// same way.
//
// **Nothing here decides whether a human may see anything.** Reading a blob
// needs the vault's content key, and that record's access control is what makes
// the OS prompt. `HumanDisclosureService` owns the authentication, the receipt
// and the bounded window; this file owns bytes, files and locks.

/// What `VaultAttachmentStore` refuses, and why.
///
/// Each case is a distinct refusal so a caller can say something true to the
/// human. None of them can be reached by a partially-written file: every
/// failure path below leaves the store exactly as it found it.
public enum VaultAttachmentError: Error, Equatable, Sendable, LocalizedError {
    case empty
    case tooLarge(limit: Int)
    case unsupportedType
    case notFound
    case authenticationFailed
    case storage(String)

    public var errorDescription: String? {
        switch self {
        case .empty: "That file is empty, so there is nothing to attach."
        case .tooLarge(let limit): "An attachment may be at most \(limit / (1024 * 1024)) MiB."
        case .unsupportedType: "Vaultage attaches PNG, JPEG, HEIC, PDF, PEM and DER files. That file is none of them."
        case .notFound: "That attachment is no longer stored on this Mac."
        case .authenticationFailed: "The sealed attachment could not be opened."
        case .storage(let detail): detail
        }
    }
}

/// The file types the store accepts, decided by leading bytes only.
///
/// This is a sniffer, not a parser: it reads at most the first 16 bytes plus,
/// for PEM, one bounded ASCII prefix, and it never decodes the file. A file
/// whose extension says PNG and whose bytes say something else is what the
/// bytes say.
public enum VaultAttachmentSniffer {
    /// The bound the ticket sets. It is a constant rather than a preference:
    /// there is no setting, argument or environment variable that raises it.
    public static let maximumBytes = 10 * 1024 * 1024

    /// The signatures, in the order they are tried. Each is a fixed byte prefix
    /// except HEIC, which is identified by its ISO-BMFF brand at offset 4.
    public static func mediaType(of bytes: Data) -> (mediaType: String, role: VaultAttachmentRole)? {
        guard !bytes.isEmpty else { return nil }
        let head = [UInt8](bytes.prefix(16))

        if head.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            return ("image/png", .image)
        }
        // JPEG: SOI marker. The rest of the file is never decoded.
        if head.count >= 3, head[0] == 0xFF, head[1] == 0xD8, head[2] == 0xFF {
            return ("image/jpeg", .image)
        }
        // HEIC: an ISO base media file whose major brand is one of the HEIF
        // still-image brands. Bytes 4...7 are "ftyp".
        if head.count >= 12, head[4] == 0x66, head[5] == 0x74, head[6] == 0x79, head[7] == 0x70 {
            let brand = String(decoding: head[8 ..< 12], as: UTF8.self)
            if ["heic", "heix", "heim", "heis", "hevc", "mif1", "msf1"].contains(brand) {
                return ("image/heic", .image)
            }
        }
        if head.starts(with: [0x25, 0x50, 0x44, 0x46, 0x2D]) {  // "%PDF-"
            return ("application/pdf", .document)
        }
        // PEM: the armour line, which is ASCII and bounded. A certificate
        // armour is filed as a certificate so the X.509 read is attempted;
        // every other armour is key material and is never parsed.
        let prefix = String(decoding: bytes.prefix(64), as: UTF8.self)
        if prefix.hasPrefix("-----BEGIN ") {
            let isCertificate = prefix.hasPrefix("-----BEGIN CERTIFICATE") || prefix.hasPrefix("-----BEGIN TRUSTED CERTIFICATE")
            return ("application/x-pem-file", isCertificate ? .certificate : .keyMaterial)
        }
        // DER: an X.509 certificate is a SEQUENCE in definite long form, so the
        // first two bytes are 0x30 followed by 0x81/0x82/0x83. This is a shape
        // check on two bytes, not a parse.
        if head.count >= 2, head[0] == 0x30, (0x81 ... 0x83).contains(head[1]) {
            return ("application/pkix-cert", .certificate)
        }
        return nil
    }

    /// Bounds and sniffs one candidate file in one place, so no caller can
    /// accept bytes the store would not.
    public static func inspect(_ bytes: Data) throws -> (mediaType: String, role: VaultAttachmentRole) {
        guard !bytes.isEmpty else { throw VaultAttachmentError.empty }
        guard bytes.count <= maximumBytes else { throw VaultAttachmentError.tooLarge(limit: maximumBytes) }
        guard let sniffed = mediaType(of: bytes) else { throw VaultAttachmentError.unsupportedType }
        return sniffed
    }

    /// A display name reduced to something that is only ever a label: no path
    /// separators, no control characters, bounded length.
    ///
    /// The blob is stored under its content address, so this string never
    /// becomes a file-system path. Sanitising it anyway is what keeps it from
    /// becoming one by accident later.
    public static func sanitizedFileName(_ raw: String) -> String {
        let stripped = raw
            .components(separatedBy: CharacterSet(charactersIn: "/\\:\0"))
            .joined(separator: "-")
            .unicodeScalars
            .filter { !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0) }
        let trimmed = String(String.UnicodeScalarView(stripped)).trimmingCharacters(in: .whitespaces)
        let name = trimmed.isEmpty ? "Attachment" : trimmed
        return String(name.prefix(VaultItemAttachment.maximumFileNameLength))
    }
}

/// Reads the value-free facts out of an X.509 certificate.
///
/// Everything it returns is metadata a human needs to manage the file: who it
/// is for, who signed it, and when it stops working. The parse runs on bytes
/// that already passed the sniff, it cannot fail the import, and it produces no
/// key material of any kind — `SecCertificate` is a public certificate, and
/// nothing here touches a private key.
public enum CertificateReader {

    /// Parses DER, or PEM by extracting the first certificate armour block.
    /// Returns nil when `Security.framework` does not accept the bytes as a
    /// certificate; the caller seals the file regardless and files it as key
    /// material.
    public static func summary(of bytes: Data) -> CertificateSummary? {
        guard let der = derBytes(from: bytes), let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return nil }

        let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "Unknown subject"
        var issuer = "Unknown issuer"
        var notBefore: Date?
        var notAfter: Date?
        var serial: String?

        // **BL-096 slice 1.** `SecCertificateCopyValues` and the `kSecOID*` /
        // `kSecPropertyKey*` constants it returns are macOS-only Security
        // symbols; iOS has no public accessor for a certificate's issuer name
        // or validity window. The subject summary and the serial number below
        // are on both platforms, so a phone build reads the two facts it can
        // and leaves the other three at the same defaults a certificate
        // `Security.framework` declines to describe already produces. **No
        // macOS behaviour changes**: this is the identical code, guarded.
        #if canImport(AppKit)
        if let values = SecCertificateCopyValues(certificate, nil, nil) as? [String: Any] {
            if let issuerName = values[kSecOIDX509V1IssuerName as String] as? [String: Any] {
                issuer = commonNameOrJoined(issuerName) ?? issuer
            }
            notBefore = absoluteDate(values[kSecOIDX509V1ValidityNotBefore as String])
            notAfter = absoluteDate(values[kSecOIDX509V1ValidityNotAfter as String])
        }
        #endif
        if let serialData = SecCertificateCopySerialNumberData(certificate, nil) as Data? {
            serial = serialData.map { String(format: "%02X", $0) }.joined()
        }
        return CertificateSummary(
            subject: String(subject.prefix(256)),
            issuer: String(issuer.prefix(256)),
            notBefore: notBefore,
            notAfter: notAfter,
            serialNumber: serial.map { String($0.prefix(64)) }
        )
    }

    /// DER passes through; PEM has its first certificate block base64-decoded.
    /// Anything else returns nil rather than being guessed at.
    private static func derBytes(from bytes: Data) -> Data? {
        let head = [UInt8](bytes.prefix(2))
        if head.count == 2, head[0] == 0x30, (0x81 ... 0x83).contains(head[1]) { return bytes }
        guard let text = String(data: bytes, encoding: .utf8) else { return nil }
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let startRange = text.range(of: begin), let endRange = text.range(of: end, range: startRange.upperBound ..< text.endIndex) else { return nil }
        let base64 = text[startRange.upperBound ..< endRange.lowerBound]
            .components(separatedBy: .newlines)
            .joined()
            .trimmingCharacters(in: .whitespaces)
        return Data(base64Encoded: base64, options: [.ignoreUnknownCharacters])
    }

    #if canImport(AppKit)
    /// `SecCertificateCopyValues` returns names as a list of OID/value pairs.
    /// The common name is preferred; otherwise the labelled values are joined,
    /// which is what a human reads on a certificate's "issued by" line.
    private static func commonNameOrJoined(_ name: [String: Any]) -> String? {
        guard let entries = name[kSecPropertyKeyValue as String] as? [[String: Any]] else { return nil }
        var parts: [String] = []
        for entry in entries {
            guard let value = entry[kSecPropertyKeyValue as String] as? String else { continue }
            if (entry[kSecPropertyKeyLabel as String] as? String) == (kSecOIDCommonName as String) { return value }
            parts.append(value)
        }
        return parts.isEmpty ? nil : parts.joined(separator: ", ")
    }

    /// Validity dates come back as a CFNumber of seconds since the Core
    /// Foundation epoch (2001-01-01), not since 1970.
    private static func absoluteDate(_ value: Any?) -> Date? {
        guard let entry = value as? [String: Any], let number = entry[kSecPropertyKeyValue as String] as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: number.doubleValue)
    }
    #endif
}

/// The per-vault content key and the sealed blobs it protects.
///
/// An actor, for the same reason `MetadataStore` is one: the read-modify-write
/// around a blob file must be serialized inside this process, and the atomic
/// write plus the 0600 mode is what protects it from every other process that
/// is not this user.
public actor VaultAttachmentStore {
    /// The Keychain service the content keys live under. Deliberately distinct
    /// from the item service, so a content key can never be returned by a query
    /// that was looking for an item's value.
    public static let keychainService = "com.vaultage.foundation20260910.attachment-key"
    /// Bumped when the envelope format or the derivation changes. It is part of
    /// the sealed AAD, so a blob written by another revision fails
    /// authentication rather than being opened under the wrong assumption.
    public static let formatRevision = "vaultage.attachment.v1"

    private static let idDomain = Data("vaultage.attachment.id.v1\0".utf8)
    private static let keyDomain = Data("vaultage.attachment.key.v1\0".utf8)

    private let directory: URL
    private let vault: any SecretVault
    private let makeContentKey: @Sendable () -> Data

    /// - Parameters:
    ///   - directory: the metadata directory. Blobs live in `attachments/`
    ///     under it, which is why an override of the metadata directory moves
    ///     the attachments with it and a screenshot run never touches the
    ///     owner's real store.
    ///   - vault: where the per-vault content key lives. In production this is
    ///     `KeychainVault`, so the key is a user-presence record and opening a
    ///     blob costs an OS prompt.
    public init(
        directory: URL,
        vault: any SecretVault,
        makeContentKey: @escaping @Sendable () -> Data = { Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }) }
    ) {
        self.directory = directory
        self.vault = vault
        self.makeContentKey = makeContentKey
    }

    /// Where one vault's blobs live. One directory per vault, so a vault's
    /// attachments can be enumerated and cleaned without walking anything else.
    public nonisolated func vaultDirectory(_ vaultID: UUID) -> URL {
        directory
            .appendingPathComponent("attachments", isDirectory: true)
            .appendingPathComponent(vaultID.uuidString, isDirectory: true)
    }

    /// The Keychain account holding a vault's content key.
    public nonisolated static func contentKeyAccount(_ vaultID: UUID) -> String {
        "vault-content-key.\(vaultID.uuidString)"
    }

    /// The accounts an owner authentication must be allowed to unlock for a
    /// seal or an open in this vault. Handing this to
    /// `OwnerAuthenticating.authenticateOwner(reason:unlocking:)` is what keeps
    /// an attachment operation at **one** OS prompt.
    public nonisolated static func unlockedAccounts(_ vaultID: UUID) -> Set<String> {
        [contentKeyAccount(vaultID)]
    }

    // MARK: - Sealing

    /// Seals one file for one vault and returns its metadata record.
    ///
    /// The order is deliberate: bound and sniff first, so a hostile file is
    /// rejected before a key is read and before anything is written; derive the
    /// content address; and only then, if no blob with that address exists,
    /// write one. Re-importing the same file is therefore free and produces the
    /// same record, which is the deduplication the ticket asks for.
    ///
    /// `plaintext` is taken `inout` and zeroed here, so the caller cannot be
    /// left holding a copy it forgot about.
    public func seal(
        _ plaintext: inout Data,
        fileName: String,
        vaultID: UUID,
        authentication: OwnerAuthentication? = nil,
        at now: Date = .now
    ) throws -> VaultItemAttachment {
        var bytes = plaintext
        plaintext.resetBytes(in: plaintext.startIndex ..< plaintext.endIndex)
        plaintext = Data()
        defer { bytes.resetBytes(in: bytes.startIndex ..< bytes.endIndex) }

        let sniffed = try VaultAttachmentSniffer.inspect(bytes)

        // The certificate read happens on sniffed bytes, produces metadata
        // only, and cannot fail the import: an unparseable armour is filed as
        // key material rather than refused, because the file is still the
        // owner's and still worth sealing.
        var role = sniffed.role
        var summary: CertificateSummary?
        if role == .certificate {
            summary = CertificateReader.summary(of: bytes)
            if summary == nil { role = .keyMaterial }
        }

        var contentKey = try contentKey(for: vaultID, authentication: authentication)
        defer { contentKey.resetBytes(in: contentKey.startIndex ..< contentKey.endIndex) }

        let id = contentAddress(of: bytes, mediaType: sniffed.mediaType, contentKey: contentKey)
        let record = VaultItemAttachment(
            id: id,
            vaultID: vaultID,
            mediaType: sniffed.mediaType,
            fileName: VaultAttachmentSniffer.sanitizedFileName(fileName),
            byteCount: bytes.count,
            role: role,
            certificate: summary,
            addedAt: now
        )

        let blobURL = vaultDirectory(vaultID).appendingPathComponent("\(id).blob")
        // Deduplication. The address is a function of the bytes and the key, so
        // an existing blob at this address *is* this file.
        if FileManager.default.fileExists(atPath: blobURL.path) { return record }

        var blobKey = derivedKey(for: id, contentKey: contentKey)
        defer { blobKey.resetBytes(in: blobKey.startIndex ..< blobKey.endIndex) }
        let sealed: Data
        do {
            let box = try AES.GCM.seal(bytes, using: SymmetricKey(data: blobKey), authenticating: Data(aad(id: id, mediaType: sniffed.mediaType).utf8))
            guard let combined = box.combined else { throw VaultAttachmentError.storage("The attachment could not be sealed.") }
            sealed = combined
        } catch let error as VaultAttachmentError {
            throw error
        } catch {
            throw VaultAttachmentError.storage("The attachment could not be sealed.")
        }
        try write(sealed, to: blobURL)
        return record
    }

    // MARK: - Opening

    /// Opens one sealed blob and hands back its plaintext as a `VaultSecret` —
    /// the same manually-zeroed allocation every credential in this product
    /// lives in, with no `Codable`, no printable form and a scoped borrow that
    /// cannot return a copy.
    ///
    /// This does not decide whether a human may see it. The caller has already
    /// authenticated, or the `.userPresence` control on the content key is
    /// about to make the OS ask.
    public func open(_ attachment: VaultItemAttachment, authentication: OwnerAuthentication? = nil) throws -> VaultSecret {
        guard attachment.isWellFormed else { throw VaultAttachmentError.notFound }
        let blobURL = vaultDirectory(attachment.vaultID).appendingPathComponent("\(attachment.id).blob")
        guard let sealed = try? Data(contentsOf: blobURL) else { throw VaultAttachmentError.notFound }

        var contentKey = try contentKey(for: attachment.vaultID, authentication: authentication)
        defer { contentKey.resetBytes(in: contentKey.startIndex ..< contentKey.endIndex) }
        var blobKey = derivedKey(for: attachment.id, contentKey: contentKey)
        defer { blobKey.resetBytes(in: blobKey.startIndex ..< blobKey.endIndex) }

        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            var opened = try AES.GCM.open(box, using: SymmetricKey(data: blobKey), authenticating: Data(aad(id: attachment.id, mediaType: attachment.mediaType).utf8))
            defer { opened.resetBytes(in: opened.startIndex ..< opened.endIndex) }
            return VaultSecret(opened)
        } catch {
            // A tampered blob, a blob from another vault, or a record whose
            // media type was edited all land here. Authentication failure is
            // the honest answer to every one of them.
            throw VaultAttachmentError.authenticationFailed
        }
    }

    // MARK: - Cleanup

    /// Removes every blob in a vault that nothing references any more.
    ///
    /// The caller passes the referenced set from committed metadata
    /// (`VaultItemTypes.referencedAttachmentIDs`), so a blob two items share
    /// survives the deletion of one of them, and a blob no item names is gone
    /// the moment its last item is deleted. Returns how many files were
    /// removed, so a status line can say something true.
    ///
    /// Audit M-23. A blob is sealed **before** the metadata that names it is
    /// committed, so for that window it is unreferenced by construction. A
    /// cleanup running in another process in that window would remove it and
    /// leave the new item pointing at nothing. A blob younger than
    /// `publicationGrace` is therefore left alone unless the caller names it
    /// in `alsoRemove` — which is what a failed add does with the blobs it
    /// sealed itself, and nothing else does.
    ///
    /// Audit M-26. A blob that could not be removed is not forgotten: its id
    /// is written to the vault's cleanup-debt file and retried on every later
    /// call, and the call still reports the failure.
    @discardableResult
    public func removeUnreferenced(vaultID: UUID, referenced: Set<String>, alsoRemove: Set<String> = [], now: Date = Date()) throws -> Int {
        let folder = vaultDirectory(vaultID)
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: folder.path) else { return 0 }
        var removed = 0
        var debt = Self.readCleanupDebt(in: folder)
        var failed: Set<String> = []
        for name in names {
            guard name.hasSuffix(".blob") else { continue }
            let id = String(name.dropLast(5))
            guard VaultItemAttachment.isWellFormedID(id), !referenced.contains(id) else { continue }
            let url = folder.appendingPathComponent(name)
            if !alsoRemove.contains(id), !debt.contains(id), Self.isWithinPublicationGrace(url, now: now) { continue }
            do {
                try FileManager.default.removeItem(at: url)
                removed += 1
                debt.remove(id)
            } catch {
                failed.insert(id)
                debt.insert(id)
            }
        }
        // Debt for a blob that is gone by now is settled.
        debt = debt.filter { FileManager.default.fileExists(atPath: folder.appendingPathComponent("\($0).blob").path) }
        Self.writeCleanupDebt(debt, in: folder)
        guard failed.isEmpty else { throw VaultAttachmentError.storage("A sealed attachment could not be removed. It is recorded for the next cleanup.") }
        return removed
    }

    /// Audit M-23. How long a freshly sealed blob is exempt from cleanup by
    /// anyone but the add that sealed it.
    public nonisolated static let publicationGrace: TimeInterval = 10 * 60

    /// The blob ids this vault still owes a removal. Read by the status line
    /// and by the contracts; never by anything that opens a blob.
    public func cleanupDebt(vaultID: UUID) -> Set<String> { Self.readCleanupDebt(in: vaultDirectory(vaultID)) }

    private nonisolated static func isWithinPublicationGrace(_ url: URL, now: Date) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let modified = attributes[.modificationDate] as? Date else { return false }
        return now.timeIntervalSince(modified) < publicationGrace
    }

    private nonisolated static func debtURL(in folder: URL) -> URL { folder.appendingPathComponent("cleanup-debt.json") }

    private nonisolated static func readCleanupDebt(in folder: URL) -> Set<String> {
        guard let data = try? Data(contentsOf: debtURL(in: folder)),
              let ids = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return Set(ids.filter(VaultItemAttachment.isWellFormedID))
    }

    private nonisolated static func writeCleanupDebt(_ debt: Set<String>, in folder: URL) {
        let url = debtURL(in: folder)
        if debt.isEmpty { try? FileManager.default.removeItem(at: url); return }
        if let data = try? JSONEncoder().encode(debt.sorted()) { try? data.write(to: url, options: .atomic) }
    }

    /// Every blob id this vault currently holds on disk. Used by the orphan
    /// contracts and by a repair pass; it reads no bytes and needs no key.
    public func storedIDs(vaultID: UUID) -> Set<String> {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: vaultDirectory(vaultID).path) else { return [] }
        return Set(names.filter { $0.hasSuffix(".blob") }.map { String($0.dropLast(5)) }.filter(VaultItemAttachment.isWellFormedID))
    }

    // MARK: - Keys

    /// The vault's 256-bit content key, created on first use.
    ///
    /// Creation writes a fresh random key into a user-presence Keychain record;
    /// every later call reads it back, which is what raises the OS prompt
    /// unless the caller carried an authentication bound to this exact account.
    private func contentKey(for vaultID: UUID, authentication: OwnerAuthentication?) throws -> Data {
        let account = Self.contentKeyAccount(vaultID)
        do {
            let secret = try vault.read(account: account, prompt: "Open sealed attachments in this vault", authentication: authentication)
            var key = Data()
            secret.withBytes { key = Data($0) }
            guard key.count == 32 else { throw VaultAttachmentError.authenticationFailed }
            return key
        } catch let error as VaultAttachmentError {
            throw error
        } catch VaultageError.approvalDenied {
            throw VaultAttachmentError.authenticationFailed
        } catch VaultageError.destinationNotFound {
            // No record yet: this vault has never held an attachment. Create
            // the key, then read it back through the same path so the value
            // returned is always one the Keychain actually holds. Only the
            // typed "no such record" comes here (audit M-22): any other
            // failure to read is a failure, never a reason to mint a second
            // key beside ciphertext sealed under the first.
            var fresh = makeContentKey()
            defer { fresh.resetBytes(in: fresh.startIndex ..< fresh.endIndex) }
            guard fresh.count == 32 else { throw VaultAttachmentError.storage("Could not create an attachment key.") }
            do { try vault.save(fresh, account: account) }
            catch { throw VaultAttachmentError.storage("Could not create an attachment key for this vault.") }
            let secret = try vault.read(account: account, prompt: "Open sealed attachments in this vault", authentication: authentication)
            var key = Data()
            secret.withBytes { key = Data($0) }
            guard key.count == 32 else { throw VaultAttachmentError.authenticationFailed }
            return key
        } catch {
            throw VaultAttachmentError.storage("The attachment key for this vault could not be read: \(Redactor.publicError(error))")
        }
    }

    /// The keyed content address: HMAC-SHA256 over a domain tag, the media type
    /// with its length, and the plaintext.
    ///
    /// Keying it is what separates this from a bare content hash. Two identical
    /// files in one vault share an address (so they share a blob); the same
    /// file in two vaults does not (so one vault's key cannot confirm the
    /// other's contents); and nobody holding the directory can confirm a
    /// guessed file at all.
    private func contentAddress(of bytes: Data, mediaType: String, contentKey: Data) -> String {
        var input = Self.idDomain
        var length = UInt16(mediaType.utf8.count).bigEndian
        withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
        input.append(Data(mediaType.utf8))
        input.append(bytes)
        defer { input.resetBytes(in: input.startIndex ..< input.endIndex) }
        let code = HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: contentKey))
        return code.map { String(format: "%02x", $0) }.joined()
    }

    /// One key per blob, derived from the content key and the address, so two
    /// blobs in a vault are never sealed under the same key.
    private func derivedKey(for id: String, contentKey: Data) -> Data {
        var input = Self.keyDomain
        input.append(Data(id.utf8))
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: contentKey)))
    }

    /// The additional authenticated data. It binds the envelope to its format
    /// revision, its address and its media type, so a blob cannot be renamed
    /// into another record's place or re-labelled as a different type.
    private func aad(id: String, mediaType: String) -> String {
        "\(Self.formatRevision)\n\(id)\n\(mediaType)"
    }

    // MARK: - Files

    /// Atomic, 0600, inside a 0700 directory.
    ///
    /// The temporary file is created with the final mode *before* any bytes
    /// reach it, so there is no window in which a world-readable file holds
    /// ciphertext, and the rename is what makes a half-written blob impossible
    /// to observe.
    private func write(_ data: Data, to url: URL) throws {
        let folder = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.deletingLastPathComponent().path)
            let temporary = folder.appendingPathComponent("attachment-\(UUID().uuidString).tmp")
            guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw VaultAttachmentError.storage("Could not create the sealed attachment file.")
            }
            do {
                let handle = try FileHandle(forWritingTo: temporary)
                defer { try? handle.close() }
                try handle.write(contentsOf: data)
                try handle.synchronize()
            } catch {
                try? FileManager.default.removeItem(at: temporary)
                throw VaultAttachmentError.storage("Could not write the sealed attachment.")
            }
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary, backupItemName: nil, options: [])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch let error as VaultAttachmentError {
            throw error
        } catch {
            throw VaultAttachmentError.storage("Could not write the sealed attachment.")
        }
    }
}
