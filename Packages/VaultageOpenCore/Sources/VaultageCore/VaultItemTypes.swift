import Foundation

// BL-079 / D24 — general secret types, per-field custody, and the metadata
// half of encrypted attachments.
//
// Four properties hold everywhere in this file, and every bound below exists to
// keep one of them true:
//
// 1. **A secret field is a Keychain record, not a metadata field.** Every field
//    flagged `isSecret` carries a `keychainAccount` and nothing else: there is
//    no property on `VaultItemField` that a value could be written into, and
//    `text` is cleared on any field that claims to be secret. A non-secret
//    field (a username, a URL, a note heading) is ordinary metadata and is
//    stored in `metadata.json` like a label always was.
// 2. **The account is per field, not per item.** Two fields of one item are two
//    independent user-presence records under two opaque accounts, so revealing
//    a password never hands out its URL's record and never hands out the SSH
//    passphrase that sits beside the private key.
// 3. **The legacy primary field is preserved exactly.** Schema 12 and earlier
//    stored one value per item under `VaultItem.keychainAccount`, and the
//    broker, every connection, every binding, every runtime authorization and
//    every deletion reservation resolve an item through that one account. That
//    account keeps its meaning: it is the account of the item's *primary*
//    field, and the schema-13 migration expresses the old shape as a one-field
//    list rather than moving anything.
// 4. **An item may legitimately have no protected value at all.** A certificate
//    item is a sealed file plus parsed, value-free metadata; there is no scalar
//    to put in a Keychain record. Such an item still owns an opaque
//    `keychainAccount` so that deletion reservations, digests and references
//    keep their existing shape, but no record exists under it, and
//    `hasProtectedValue` is false so every disclosure path refuses *before* it
//    prompts rather than after a failed Keychain read.

/// What kind of thing an item is.
///
/// Stored as its raw name, in the same idiom as `VaultKind` and for the same
/// reason: a build that does not understand a type must re-encode the record it
/// read rather than flatten it into a type it does understand. An item of an
/// unknown type renders as "a type this version cannot open" and refuses every
/// write, which is the fail-closed reading.
public enum VaultItemType: Hashable, Sendable, CaseIterable {
    /// The only type schema 12 had: one provider token or API key.
    case apiKey
    case password
    case secureNote
    case sshKey
    /// A certificate file plus its parsed subject, issuer and expiry. The
    /// parse is metadata only: no private key is implied and none is stored.
    case certificate
    /// Fields the owner names, each flagged secret or not.
    case custom
    case unsupported(String)

    /// The six types this build can create. `unsupported` is deliberately not
    /// in it: nothing offers it, only decoding produces it.
    public static var allCases: [VaultItemType] { [.apiKey, .password, .secureNote, .sshKey, .certificate, .custom] }

    public var rawName: String {
        switch self {
        case .apiKey: "apiKey"
        case .password: "password"
        case .secureNote: "secureNote"
        case .sshKey: "sshKey"
        case .certificate: "certificate"
        case .custom: "custom"
        case .unsupported(let name): name
        }
    }

    public init(rawName: String) {
        switch rawName {
        case "apiKey": self = .apiKey
        case "password": self = .password
        case "secureNote": self = .secureNote
        case "sshKey": self = .sshKey
        case "certificate": self = .certificate
        case "custom": self = .custom
        default: self = .unsupported(rawName)
        }
    }

    /// v1 Electron's own labels (`SECRET_TYPE_LABELS` in
    /// `renderer/src/types.ts`), which D27 ports rather than reinterprets.
    public var title: String {
        switch self {
        case .apiKey: "API Key"
        case .password: "Password"
        case .secureNote: "Secure Note"
        case .sshKey: "SSH Key"
        case .certificate: "Certificate"
        case .custom: "Custom"
        case .unsupported: "Not supported by this version"
        }
    }

    /// One sentence saying what the type holds, for the picker card and for the
    /// VoiceOver description.
    public var summary: String {
        switch self {
        case .apiKey: "A provider token or API key, with the service it belongs to."
        case .password: "A username, a password, a site and a note."
        case .secureNote: "A title and a note held as a protected value."
        case .sshKey: "A private key, its public half and an optional passphrase."
        case .certificate: "A certificate file, sealed, with its subject, issuer and expiry read at import."
        case .custom: "Fields you name yourself, each marked secret or not."
        case .unsupported: "This item was written by a newer version of Vaultage."
        }
    }

    /// SF Symbols chosen to match v1's lucide glyphs one for one:
    /// `Key`, `KeyRound`, `FileText`, `Terminal`, and `Settings2`.
    public var symbolName: String {
        switch self {
        case .apiKey: "key.fill"
        case .password: "person.badge.key.fill"
        case .secureNote: "doc.text.fill"
        case .sshKey: "terminal.fill"
        case .certificate: "checkmark.seal.fill"
        case .custom: "slider.horizontal.3"
        case .unsupported: "questionmark.square.dashed"
        }
    }

    /// True when this build may create and edit items of this type.
    public var isSupported: Bool {
        if case .unsupported = self { return false }
        return true
    }

    /// Whether an item of this type normally carries an attachment, which is
    /// what makes the Add sheet show the file well rather than hide it.
    public var expectsAttachment: Bool {
        if case .certificate = self { return true }
        return false
    }

    /// The fields a new item of this type starts with, in v1's order
    /// (`SECRET_TEMPLATES`), extended by BL-079 where v1 had no equivalent.
    ///
    /// The first secret field in the template becomes the item's *primary*
    /// field: the one whose Keychain account is `VaultItem.keychainAccount`,
    /// and therefore the one a connection, a binding or a runtime delivery
    /// reads. A template with no secret field (certificate) produces an item
    /// with no protected value at all.
    public var template: [VaultItemFieldTemplate] {
        switch self {
        case .apiKey:
            [.init(key: "Service", isSecret: false), .init(key: "API Key", isSecret: true), .init(key: "Secret", isSecret: true)]
        case .password:
            [.init(key: "Username", isSecret: false), .init(key: "Password", isSecret: true), .init(key: "URL", isSecret: false), .init(key: "Notes", isSecret: false, isMultiline: true)]
        case .secureNote:
            [.init(key: "Title", isSecret: false), .init(key: "Note", isSecret: true, isMultiline: true)]
        case .sshKey:
            [.init(key: "Private Key", isSecret: true, isMultiline: true), .init(key: "Public Key", isSecret: false, isMultiline: true), .init(key: "Passphrase", isSecret: true)]
        case .certificate, .custom, .unsupported:
            []
        }
    }

    /// The key the schema-12 migration gives the single field it synthesizes.
    /// Every migrated item is an `apiKey`, so in practice this is "API Key";
    /// the other cases exist so the function is total.
    var migratedPrimaryKey: String {
        switch self {
        case .apiKey: "API Key"
        case .password: "Password"
        case .secureNote: "Note"
        case .sshKey: "Private Key"
        case .certificate, .custom, .unsupported: "Value"
        }
    }
}

/// One row of a type's starting field list. It is a template, not a field: it
/// has no identity, no account and no value.
public struct VaultItemFieldTemplate: Hashable, Sendable {
    public let key: String
    public let isSecret: Bool
    /// Whether the Add sheet gives this field a text view rather than a single
    /// line. A private key, a note and a URL list are not one-line values.
    public let isMultiline: Bool

    public init(key: String, isSecret: Bool, isMultiline: Bool = false) {
        self.key = key
        self.isSecret = isSecret
        self.isMultiline = isMultiline
    }
}

/// One field of one item.
///
/// A secret field carries a Keychain account and nothing else; a non-secret
/// field carries text and no account. The two are mutually exclusive and the
/// decoder enforces it, so a hand-edited file cannot produce a field that
/// claims to be secret while holding a value in `metadata.json`.
public struct VaultItemField: Codable, Identifiable, Hashable, Sendable {
    /// The longest field name the UI will accept, matching `Folder` and
    /// `Vault`. A name is a label, not a document.
    public static let maximumKeyLength = 128
    /// The longest *non-secret* value held in metadata. Notes and URL lists fit
    /// comfortably; anything larger is either a secret in the wrong field or a
    /// file, and both have their own home.
    public static let maximumTextLength = 4096
    /// The most fields one item may hold. The bound exists because every field
    /// is a row in a sheet and, when secret, a Keychain record that must be
    /// deleted with the item.
    public static let maximumFieldsPerItem = 32
    /// **BL-100 slice A — the cap the model never had**
    /// (`13-MULTI-DEVICE-CUSTODY.md` §3.1). It matches the field bound, and it
    /// stays in slice A because it is a **model** bound that belongs beside the
    /// field bound whether or not anything counts tombs: deleting one item is
    /// at most `1 + 32 + 32` = **65** records touched, which is what bounds
    /// what one delete enqueues in §7.3 part A's local deletion queue.
    ///
    /// It bounds an item's attachment **count** and **not** one attachment's
    /// size — `VaultAttachmentSniffer.maximumBytes` does that — which is the
    /// distinction `VaultRecordBudget.maximumSealedRecordBytes` is derived
    /// from (fifteenth pass, DB15-H3).
    public static let maximumAttachmentsPerItem = 32

    public let id: UUID
    public var key: String
    public var isSecret: Bool
    /// The Keychain account holding this field's value. Non-nil exactly when
    /// the field is secret and a value was actually written.
    public var keychainAccount: String?
    /// Opaque local revision of that record, exactly as `VaultItem` has always
    /// carried one. Never a hash of the value.
    public var credentialVersion: UUID?
    /// The non-secret value. Always nil on a secret field.
    public var text: String?

    public init(
        id: UUID = UUID(),
        key: String,
        isSecret: Bool,
        keychainAccount: String? = nil,
        credentialVersion: UUID? = nil,
        text: String? = nil
    ) {
        self.id = id
        self.key = key
        self.isSecret = isSecret
        self.keychainAccount = isSecret ? keychainAccount : nil
        self.credentialVersion = isSecret ? credentialVersion : nil
        self.text = isSecret ? nil : text
    }

    /// True when this field has something a human could reveal or copy.
    public var hasValue: Bool {
        isSecret ? keychainAccount != nil : !(text ?? "").isEmpty
    }

    /// What the detail view shows in place of the value. A secret field is
    /// always masked; an empty field says so rather than showing blank space.
    public var maskedDisplay: String {
        guard hasValue else { return "—" }
        return isSecret ? String(repeating: "•", count: 12) : (text ?? "")
    }

    private enum CodingKeys: String, CodingKey { case id, key, isSecret, keychainAccount, credentialVersion, text }

    /// A field written by a newer build, or by hand, is straightened rather
    /// than rejected: the whole metadata file must stay readable, and a
    /// malformed field must never widen what may be read.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        let decodedKey = (try c.decodeIfPresent(String.self, forKey: .key))?.trimmingCharacters(in: .whitespacesAndNewlines)
        key = (decodedKey?.isEmpty == false ? decodedKey! : "Field")
        isSecret = try c.decodeIfPresent(Bool.self, forKey: .isSecret) ?? true
        let account = try c.decodeIfPresent(String.self, forKey: .keychainAccount)
        let version = try c.decodeIfPresent(UUID.self, forKey: .credentialVersion)
        let decodedText = try c.decodeIfPresent(String.self, forKey: .text)
        // The mutual exclusion, applied on the way in. A record that claims to
        // be secret loses any text it carried, because a secret value has no
        // business in this file; a record that claims not to be loses its
        // account, because a plain field must not be able to name a
        // user-presence record.
        keychainAccount = isSecret ? account : nil
        credentialVersion = isSecret ? version : nil
        text = isSecret ? nil : decodedText
    }
}

/// What a sealed attachment is for. It is derived from the sniffed media type
/// and the certificate parse at import, never from the file's name.
public enum VaultAttachmentRole: String, Codable, Sendable {
    /// A PNG, JPEG or HEIC — v1's screenshots.
    case image
    /// A PEM or DER that `Security.framework` accepted as an X.509 certificate.
    case certificate
    /// A PDF.
    case document
    /// A PEM this build could not read as a certificate. It is sealed like
    /// everything else and previewed as bytes, never parsed further.
    case keyMaterial

    public var title: String {
        switch self {
        case .image: "Image"
        case .certificate: "Certificate"
        case .document: "Document"
        case .keyMaterial: "Key file"
        }
    }

    public var symbolName: String {
        switch self {
        case .image: "photo.fill"
        case .certificate: "checkmark.seal.fill"
        case .document: "doc.fill"
        case .keyMaterial: "key.horizontal.fill"
        }
    }
}

/// The value-free facts read out of an X.509 certificate at import.
///
/// Every field here is metadata a human needs in order to recognise and manage
/// the file: who it is for, who signed it, and when it stops working. None of
/// it is secret, and no part of the file's bytes is derivable from it.
public struct CertificateSummary: Codable, Hashable, Sendable {
    public var subject: String
    public var issuer: String
    public var notBefore: Date?
    public var notAfter: Date?
    /// The serial number as uppercase hexadecimal, or nil when the parse could
    /// not produce one. Identifying, not secret.
    public var serialNumber: String?

    public init(subject: String, issuer: String, notBefore: Date? = nil, notAfter: Date? = nil, serialNumber: String? = nil) {
        self.subject = subject
        self.issuer = issuer
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.serialNumber = serialNumber
    }

    /// How the expiry chip reads. Three states, each with its own words, so the
    /// chip never depends on colour alone.
    public enum Expiry: Sendable, Hashable {
        case unknown
        case expired(daysAgo: Int)
        case expiring(inDays: Int)
        case valid(inDays: Int)

        public var title: String {
            switch self {
            case .unknown: "Expiry unknown"
            case .expired(let days): days == 0 ? "Expired today" : "Expired \(days) day\(days == 1 ? "" : "s") ago"
            case .expiring(let days): days == 0 ? "Expires today" : "Expires in \(days) day\(days == 1 ? "" : "s")"
            case .valid(let days): "Valid for \(days) day\(days == 1 ? "" : "s")"
            }
        }
    }

    /// Anything inside this many days of expiry is reported as expiring rather
    /// than valid, which is the window a human can still act in.
    public static let expiringSoonDays = 30

    public func expiry(at now: Date = .now) -> Expiry {
        guard let notAfter else { return .unknown }
        let seconds = notAfter.timeIntervalSince(now)
        let days = Int((abs(seconds) / 86_400).rounded(.down))
        if seconds < 0 { return .expired(daysAgo: days) }
        return days <= Self.expiringSoonDays ? .expiring(inDays: days) : .valid(inDays: days)
    }
}

/// The metadata half of one sealed attachment.
///
/// The bytes live in the attachment store as an AES-256-GCM envelope; this
/// record says only what the store needs to find that envelope and what a human
/// needs to recognise the file. `id` is the content address — an HMAC of the
/// plaintext under the vault's content key — so two identical files share one
/// blob and neither the id nor anything else here can be used to confirm a
/// guessed file without the key.
public struct VaultItemAttachment: Codable, Identifiable, Hashable, Sendable {
    /// The most attachments one item may hold.
    public static let maximumPerItem = 8
    /// The longest display name kept. A file name is a label here: it never
    /// reaches the file system, because the blob is stored under `id`.
    public static let maximumFileNameLength = 128

    /// 64 lowercase hexadecimal characters: HMAC-SHA256 under the vault's
    /// content key.
    public let id: String
    /// The vault whose content key seals this blob. An attachment cannot be
    /// read with another vault's key, so moving an item between vaults keeps
    /// this field pointing at the vault that sealed it.
    public var vaultID: UUID
    public var mediaType: String
    public var fileName: String
    /// Plaintext length. Metadata: it is already implied by the envelope's
    /// size, and a human needs it to recognise the file.
    public var byteCount: Int
    public var role: VaultAttachmentRole
    /// Present only for `.certificate`, and parsed at import.
    public var certificate: CertificateSummary?
    public var addedAt: Date

    public init(
        id: String,
        vaultID: UUID,
        mediaType: String,
        fileName: String,
        byteCount: Int,
        role: VaultAttachmentRole,
        certificate: CertificateSummary? = nil,
        addedAt: Date = .now
    ) {
        self.id = id
        self.vaultID = vaultID
        self.mediaType = mediaType
        self.fileName = fileName
        self.byteCount = byteCount
        self.role = role
        self.certificate = certificate
        self.addedAt = addedAt
    }

    /// Whether `id` is the shape the store writes. A hand-edited id that is not
    /// 64 hexadecimal characters names no blob and is dropped by the repair
    /// pass rather than turned into a file-system path.
    public static func isWellFormedID(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    public var isWellFormed: Bool { Self.isWellFormedID(id) }
}

/// Validation and repair for an item's fields and attachments.
///
/// It is written in the same shape as `VaultOrganization`: pure functions over
/// records, refusing without writing, with the repair pass and the migration
/// sharing one definition of "coherent" so there is only one place that decides
/// what a well-formed item is.
public enum VaultItemTypes {

    // MARK: - Validation

    public static func validatedKey(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultageError.invalidInput("A field name is required.") }
        guard trimmed.count <= VaultItemField.maximumKeyLength else {
            throw VaultageError.invalidInput("A field name may be at most \(VaultItemField.maximumKeyLength) characters.")
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("A field name cannot contain control characters.")
        }
        return trimmed
    }

    /// The non-secret value bound. Newlines and tabs are allowed — a note and a
    /// public key are multi-line — and every other control character is not.
    public static func validatedText(_ raw: String) throws -> String {
        guard raw.count <= VaultItemField.maximumTextLength else {
            throw VaultageError.invalidInput("A field that is not marked secret may be at most \(VaultItemField.maximumTextLength) characters. Mark it secret, or attach it as a file.")
        }
        guard !raw.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0) && $0 != "\t" }) else {
            throw VaultageError.invalidInput("A field value cannot contain control characters.")
        }
        return raw
    }

    /// Checks a whole field list before it is written: bounds, unique names,
    /// and at most one primary.
    ///
    /// It returns the cleaned list rather than mutating in place, so a refusal
    /// leaves the caller's state untouched — the same contract every
    /// `VaultOrganization` operation has.
    public static func validatedFields(_ fields: [VaultItemField]) throws -> [VaultItemField] {
        guard fields.count <= VaultItemField.maximumFieldsPerItem else {
            throw VaultageError.invalidInput("An item may hold at most \(VaultItemField.maximumFieldsPerItem) fields.")
        }
        var seenKeys = Set<String>()
        var seenIDs = Set<UUID>()
        var cleaned: [VaultItemField] = []
        for field in fields {
            let key = try validatedKey(field.key)
            guard seenKeys.insert(key.lowercased()).inserted else {
                throw VaultageError.invalidInput("Two fields are both called \(key). Field names must differ.")
            }
            guard seenIDs.insert(field.id).inserted else {
                throw VaultageError.invalidInput("Two fields share an identifier.")
            }
            var cleanedField = field
            cleanedField.key = key
            if field.isSecret {
                cleanedField.text = nil
            } else {
                cleanedField.keychainAccount = nil
                cleanedField.credentialVersion = nil
                if let text = field.text { cleanedField.text = try validatedText(text) }
            }
            cleaned.append(cleanedField)
        }
        return cleaned
    }

    // MARK: - Migration and repair

    /// Makes one item's fields and attachments coherent, in place.
    ///
    /// Like `VaultOrganization.normalize`, this is both the schema-13 migration
    /// tail and the repair pass for a hand-edited file, and it **never drops a
    /// Keychain account it cannot prove is unreferenced**. What it does drop is
    /// structure that names nothing: a field with no account and no text on a
    /// type that did not ask for it, an attachment whose id is not the shape
    /// the store writes, and duplicates beyond the bounds.
    public static func normalize(_ item: inout VaultItem) {
        // Field names: trimmed, non-empty, and unique within the item. A
        // duplicate is suffixed rather than removed, because the record behind
        // it is real.
        var seenKeys = Set<String>()
        var seenIDs = Set<UUID>()
        var fields: [VaultItemField] = []
        for var field in item.fields {
            let trimmed = field.key.trimmingCharacters(in: .whitespacesAndNewlines)
            var key = trimmed.isEmpty ? "Field" : String(trimmed.prefix(VaultItemField.maximumKeyLength))
            var suffix = 2
            while !seenKeys.insert(key.lowercased()).inserted {
                key = "\(trimmed.isEmpty ? "Field" : trimmed) \(suffix)"
                suffix += 1
            }
            field.key = key
            if !seenIDs.insert(field.id).inserted {
                // A duplicate identifier would make the per-field reveal path
                // ambiguous, so the later field is re-identified. Its account
                // is untouched: the record behind it is real.
                field = VaultItemField(id: UUID(), key: field.key, isSecret: field.isSecret, keychainAccount: field.keychainAccount, credentialVersion: field.credentialVersion, text: field.text)
                seenIDs.insert(field.id)
            }
            if field.isSecret {
                field.text = nil
            } else {
                field.keychainAccount = nil
                field.credentialVersion = nil
                if let text = field.text, text.count > VaultItemField.maximumTextLength {
                    field.text = String(text.prefix(VaultItemField.maximumTextLength))
                }
            }
            fields.append(field)
            if fields.count == VaultItemField.maximumFieldsPerItem { break }
        }

        // Exactly one field may claim the item's primary account. A second one
        // is demoted to its own account rather than deleted: two fields
        // pointing at one record would let a reveal of either disclose the
        // other, and clearing the account outright would orphan a real record.
        var primarySeen = false
        for index in fields.indices where fields[index].keychainAccount == item.keychainAccount {
            if primarySeen {
                fields[index].keychainAccount = nil
                fields[index].credentialVersion = nil
            } else {
                // `VaultItem.credentialVersion` is the authoritative revision of
                // the primary record — it is what rotation, the deletion
                // reservation and every pre-BL-079 caller write. The primary
                // field mirrors it rather than keeping a second copy that could
                // drift, so a rotation is visible through either spelling and a
                // disclosure digest computed from the field cannot go stale.
                fields[index].credentialVersion = item.credentialVersion
                primarySeen = true
            }
        }
        item.fields = fields

        // Attachments: well-formed id, inside the per-item bound, and no
        // duplicate content address. A certificate summary on a non-certificate
        // attachment is dropped, because it would describe a file that was
        // never parsed.
        var seenAttachments = Set<String>()
        var attachments: [VaultItemAttachment] = []
        for var attachment in item.attachments {
            guard attachment.isWellFormed, seenAttachments.insert(attachment.id).inserted else { continue }
            if attachment.role != .certificate { attachment.certificate = nil }
            attachment.fileName = String(attachment.fileName.prefix(VaultItemAttachment.maximumFileNameLength))
            attachments.append(attachment)
            if attachments.count == VaultItemAttachment.maximumPerItem { break }
        }
        item.attachments = attachments
    }

    /// Every Keychain account one item owns: the primary and every secret
    /// field's. Deleting an item must delete all of them, and nothing else.
    public static func keychainAccounts(of item: VaultItem) -> [String] {
        var accounts: [String] = []
        if item.hasProtectedValue { accounts.append(item.keychainAccount) }
        for field in item.fields {
            guard let account = field.keychainAccount, account != item.keychainAccount else { continue }
            accounts.append(account)
        }
        return accounts
    }

    /// The attachment ids still referenced by any item in a vault. The
    /// attachment store deletes every blob that is not in this set, so an
    /// orphan cannot survive an item delete and a blob two items share cannot
    /// be removed by deleting one of them.
    public static func referencedAttachmentIDs(vaultID: UUID, in state: VaultageMetadata) -> Set<String> {
        var referenced = Set<String>()
        for item in state.vaultItems {
            for attachment in item.attachments where attachment.vaultID == vaultID {
                referenced.insert(attachment.id)
            }
        }
        return referenced
    }
}
