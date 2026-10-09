import Foundation

// BL-078 — CSV import, ported from v1 native's `VaultCredentialCSVImporter`
// (bounds, parser shape and header mapping) and v1 Electron's `ImportModal.tsx`
// (the value-free preview as a separate step before anything is written).
//
// The rules that make this safe to run on a hostile file, all inherited from
// the donor and all asserted by the self-tests:
//
// - **Bounded before parsed.** 512 KiB of file, 1,000 data rows, 64 columns,
//   64 KiB per field. A file that exceeds any of them is refused whole; no
//   partial import is ever committed from a refused file.
// - **The preview carries no value.** `CredentialImportPreviewItem` has a
//   label, a kind and a value-free detail line. There is no field on it that
//   could hold a secret, so a preview cannot leak one however it is rendered,
//   logged or screenshotted.
// - **Values live in `Data` and are zeroed.** The parser wipes every cell it
//   allocates, and `CredentialImportPlan.clear()` wipes the records. Nothing
//   here converts a secret to `String`: only public text (labels, headers,
//   URLs used to name a row) is ever bridged.
// - **Nothing here writes anything.** The plan is pure; the caller saves each
//   record as its own user-presence Keychain item and appends metadata. A row
//   that fails to save leaves the rows before it saved and says so.

public enum CredentialImportSource: String, CaseIterable, Sendable, Identifiable {
    case generic, chrome, safari
    public var id: String { rawValue }
    public var title: String {
        switch self { case .generic: "Generic CSV"; case .chrome: "Chrome export"; case .safari: "Safari export" }
    }
    /// What the file must contain, said before a file is chosen.
    public var expectation: String {
        switch self {
        case .generic: "A header row with at least `name` and `value`. Optional: `type`, `username`, `url`, `notes`."
        case .chrome: "Chrome's password export: `name`, `url`, `username`, `password`."
        case .safari: "Safari's password export: `Title`, `URL`, `Username`, `Password`, optionally `OTPAuth`."
        }
    }
}

public struct CredentialImportPreviewItem: Sendable, Hashable, Identifiable {
    /// The line in the file, which is also what an error names.
    public let line: Int
    public let label: String
    /// `password`, `apiKey`, `sshKey`, `secureNote` or `custom`. v2 stores one
    /// protected value per item until BL-079 adds typed fields; the kind is
    /// carried so the preview can say what the row *was*.
    public let kind: String
    /// A value-free sentence: which optional columns were present, and what
    /// this release will not keep.
    public let detail: String
    public var id: Int { line }

    public init(line: Int, label: String, kind: String, detail: String) {
        self.line = line
        self.label = label
        self.kind = kind
        self.detail = detail
    }
}

public struct CredentialImportPreview: Sendable {
    public let source: CredentialImportSource
    public let items: [CredentialImportPreviewItem]
    public var count: Int { items.count }

    public init(source: CredentialImportSource, items: [CredentialImportPreviewItem]) {
        self.source = source
        self.items = items
    }
}

/// One row ready to be saved. The value is the only secret here and it is
/// `Data`, never `String`.
public struct CredentialImportRecord: Sendable {
    public let line: Int
    public let label: String
    public let kind: String
    public var secret: Data

    public init(line: Int, label: String, kind: String, secret: Data) {
        self.line = line
        self.label = label
        self.kind = kind
        self.secret = secret
    }
}

/// A parsed file: the preview a human approves, and the records behind it.
public struct CredentialImportPlan: Sendable {
    public let preview: CredentialImportPreview
    public private(set) var records: [CredentialImportRecord]

    public init(preview: CredentialImportPreview, records: [CredentialImportRecord]) {
        self.preview = preview
        self.records = records
    }

    /// Zeroes every value. Called after a commit, after a cancel, and on every
    /// failure path — a plan that is dropped without this leaves credential
    /// bytes in memory for the allocator to hand out again.
    public mutating func clear() {
        for index in records.indices {
            records[index].secret.resetBytes(in: records[index].secret.startIndex..<records[index].secret.endIndex)
        }
        records.removeAll(keepingCapacity: false)
    }
}

public enum CredentialImportError: LocalizedError, Equatable, Sendable {
    case fileTooLarge
    case emptyFile
    case tooManyRows(line: Int)
    case tooManyColumns(line: Int)
    case fieldTooLarge(line: Int)
    case missingRequiredHeader(String)
    case unterminatedQuotedField(line: Int)
    case invalidRow(line: Int, reason: String)

    public var errorDescription: String? {
        switch self {
        case .fileTooLarge: "That file is larger than \(CredentialImport.maximumBytes / 1024) KiB. Nothing was imported."
        case .emptyFile: "That file has no rows. Nothing was imported."
        case .tooManyRows(let line): "That file has more than \(CredentialImport.maximumRows) rows (line \(line)). Nothing was imported."
        case .tooManyColumns(let line): "Line \(line) has more than \(CredentialImport.maximumColumns) columns. Nothing was imported."
        case .fieldTooLarge(let line): "A field on line \(line) is larger than \(CredentialImport.maximumFieldBytes / 1024) KiB. Nothing was imported."
        case .missingRequiredHeader(let header): "That file has no `\(header)` column. Nothing was imported."
        case .unterminatedQuotedField(let line): "A quoted field starting on line \(line) is never closed. Nothing was imported."
        case .invalidRow(let line, let reason): "Line \(line): \(reason) Nothing was imported."
        }
    }
}

public enum CredentialImport {
    public static let maximumBytes = 512 * 1024
    public static let maximumRows = 1_000
    public static let maximumColumns = 64
    public static let maximumFieldBytes = 64 * 1024

    /// The one entry point. `csv` is consumed and zeroed: the caller's copy of
    /// the file bytes does not outlive this call.
    public static func plan(csv: inout Data, source: CredentialImportSource) throws -> CredentialImportPlan {
        var bytes = Data(csv)
        csv.resetBytes(in: csv.startIndex..<csv.endIndex)
        defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
        guard bytes.count <= maximumBytes else { throw CredentialImportError.fileTooLarge }

        var rows = try parse(bytes)
        defer { clear(&rows) }
        rows = rows.filter { row in !row.cells.allSatisfy(\.isEmpty) }
        guard !rows.isEmpty else { throw CredentialImportError.emptyFile }
        guard rows.count - 1 <= maximumRows else { throw CredentialImportError.tooManyRows(line: rows[maximumRows + 1].line) }
        for row in rows {
            guard row.cells.count <= maximumColumns else { throw CredentialImportError.tooManyColumns(line: row.line) }
            guard row.cells.allSatisfy({ $0.count <= maximumFieldBytes }) else { throw CredentialImportError.fieldTooLarge(line: row.line) }
        }

        var headers: [String] = []
        for (index, raw) in rows[0].cells.enumerated() {
            var cell = trimmed(raw)
            // A UTF-8 BOM on the first header is what Safari and Excel write.
            if index == 0, cell.starts(with: [0xef, 0xbb, 0xbf]) { cell.removeFirst(3) }
            guard let header = String(data: cell, encoding: .utf8) else {
                throw CredentialImportError.invalidRow(line: rows[0].line, reason: "the header row is not valid UTF-8.")
            }
            headers.append(header.lowercased())
        }
        if source == .generic {
            for required in ["name", "value"] where !headers.contains(required) {
                throw CredentialImportError.missingRequiredHeader(required)
            }
        }

        var records: [CredentialImportRecord] = []
        var previews: [CredentialImportPreviewItem] = []
        do {
            for row in rows.dropFirst() {
                var values: [String: Data] = [:]
                for (index, header) in headers.enumerated() where !header.isEmpty && index < row.cells.count {
                    let value = trimmed(row.cells[index])
                    if !value.isEmpty { values[header] = value }
                }
                let mapped = try record(values, source: source, line: row.line)
                records.append(mapped.record)
                previews.append(mapped.preview)
            }
        } catch {
            for index in records.indices {
                records[index].secret.resetBytes(in: records[index].secret.startIndex..<records[index].secret.endIndex)
            }
            throw error
        }
        return CredentialImportPlan(preview: CredentialImportPreview(source: source, items: previews), records: records)
    }

    // MARK: Mapping

    private static func record(_ row: [String: Data], source: CredentialImportSource, line: Int) throws -> (record: CredentialImportRecord, preview: CredentialImportPreviewItem) {
        switch source {
        case .generic: return try genericRecord(row, line: line)
        case .chrome, .safari: return try browserRecord(row, source: source, line: line)
        }
    }

    private static func genericRecord(_ row: [String: Data], line: Int) throws -> (record: CredentialImportRecord, preview: CredentialImportPreviewItem) {
        guard let rawName = row["name"], let name = text(rawName), !name.isEmpty else {
            throw CredentialImportError.invalidRow(line: line, reason: "this row has no name.")
        }
        guard let rawValue = row["value"], !rawValue.isEmpty else {
            throw CredentialImportError.invalidRow(line: line, reason: "this row has no value.")
        }
        let declared = (row["type"].flatMap(text) ?? "apiKey")
        let kind = normalizedKind(declared)
        guard ["password", "apiKey", "sshKey", "secureNote", "custom"].contains(kind) else {
            throw CredentialImportError.invalidRow(line: line, reason: "`\(declared)` is not a supported type.")
        }
        // A secure note's body is its notes column when it has one, exactly as
        // v1 read it; everything else takes `value`.
        let secret = (kind == "secureNote" ? (row["notes"] ?? rawValue) : rawValue)
        var extras: [String] = []
        if row["username"] != nil { extras.append("username") }
        if row["url"] != nil { extras.append("URL") }
        if row["notes"] != nil && kind != "secureNote" { extras.append("notes") }
        return (
            CredentialImportRecord(line: line, label: name, kind: kind, secret: Data(secret)),
            CredentialImportPreviewItem(line: line, label: name, kind: kind, detail: detail(extras: extras))
        )
    }

    private static func browserRecord(_ row: [String: Data], source: CredentialImportSource, line: Int) throws -> (record: CredentialImportRecord, preview: CredentialImportPreviewItem) {
        let url = first(row, ["url", "origin", "website"])
        let username = first(row, ["username", "user", "login", "email"])
        guard url != nil || username != nil else {
            throw CredentialImportError.invalidRow(line: line, reason: "this row has neither a URL nor a username.")
        }
        guard let password = first(row, ["password", "pass"]), !password.isEmpty else {
            throw CredentialImportError.invalidRow(line: line, reason: "this row has no password.")
        }
        let preferred = source == .safari ? ["title", "name"] : ["name", "title"]
        let label: String
        if let title = first(row, preferred).flatMap(text), !title.isEmpty {
            label = title
        } else if let fallback = browserFallbackName(url: url, username: username) {
            label = fallback
        } else {
            label = "Imported password"
        }
        var extras: [String] = []
        if username != nil { extras.append("username") }
        if url != nil { extras.append("URL") }
        if first(row, ["notes", "note"]) != nil { extras.append("notes") }
        if first(row, ["otpauth", "otp", "totp"]) != nil { extras.append("one-time-password secret") }
        return (
            CredentialImportRecord(line: line, label: label, kind: "password", secret: Data(password)),
            CredentialImportPreviewItem(line: line, label: label, kind: "password", detail: detail(extras: extras))
        )
    }

    /// The one honest sentence about this release's limits: v2 saves one
    /// protected value per item, so the other columns are read for the preview
    /// and then dropped rather than quietly stored somewhere unprotected.
    /// BL-079 adds the typed fields that will keep them.
    private static func detail(extras: [String]) -> String {
        guard !extras.isEmpty else { return "One protected value. No value is shown here." }
        return "One protected value. \(extras.map(\.capitalized).joined(separator: ", ")) present in the file and not stored in this release. No value is shown here."
    }

    private static func browserFallbackName(url: Data?, username: Data?) -> String? {
        if let raw = url.flatMap(text), !raw.isEmpty {
            if let host = URL(string: raw)?.host, !host.isEmpty {
                return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
            }
            return raw
        }
        return username.flatMap(text)
    }

    private static func normalizedKind(_ value: String) -> String {
        switch value.lowercased().filter(\.isLetter) {
        case "password": "password"
        case "apikey", "token", "apitoken": "apiKey"
        case "sshkey": "sshKey"
        case "securenote", "note": "secureNote"
        case "custom": "custom"
        default: value
        }
    }

    private static func first(_ row: [String: Data], _ keys: [String]) -> Data? {
        keys.lazy.compactMap { row[$0] }.first
    }

    /// Public text only. A secret never goes through here: the two callers pass
    /// a name, a title, a URL or a username.
    private static func text(_ data: Data) -> String? {
        String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: Parser

    struct Row { var line: Int; var cells: [Data] }

    private enum State { case start, unquoted, quoted, quoteInQuoted }

    /// RFC 4180 with the tolerances a real export needs: CRLF or LF, a quoted
    /// field may contain either, and a doubled quote is one quote. A quoted
    /// field that is never closed is an error rather than a silent truncation.
    static func parse(_ bytes: Data) throws -> [Row] {
        var rows: [Row] = []
        var cells: [Data] = []
        var field = Data()
        var state = State.start
        var line = 1
        var fieldStartLine = 1
        var sawAnything = false

        func endField() {
            cells.append(field)
            field = Data()
            state = .start
        }
        func endRow(at rowLine: Int) {
            endField()
            rows.append(Row(line: rowLine, cells: cells))
            cells = []
        }

        var rowLine = 1
        for byte in bytes {
            sawAnything = true
            switch state {
            case .start:
                if byte == 0x22 { state = .quoted; fieldStartLine = line }
                else if byte == 0x2c { endField() }
                else if byte == 0x0a { endRow(at: rowLine); line += 1; rowLine = line }
                else if byte == 0x0d { continue }
                else { field.append(byte); state = .unquoted }
            case .unquoted:
                if byte == 0x2c { endField() }
                else if byte == 0x0a { endRow(at: rowLine); line += 1; rowLine = line }
                else if byte == 0x0d { continue }
                else { field.append(byte) }
            case .quoted:
                if byte == 0x22 { state = .quoteInQuoted }
                else {
                    if byte == 0x0a { line += 1 }
                    field.append(byte)
                }
            case .quoteInQuoted:
                if byte == 0x22 { field.append(0x22); state = .quoted }
                else if byte == 0x2c { endField() }
                else if byte == 0x0a { endRow(at: rowLine); line += 1; rowLine = line }
                else if byte == 0x0d { state = .unquoted }
                else { field.append(byte); state = .unquoted }
            }
            // A single row cannot exceed the column bound even mid-parse: a
            // hostile file must not be able to grow an unbounded array here.
            if cells.count > maximumColumns {
                var partial = rows
                clear(&partial)
                field.resetBytes(in: field.startIndex..<field.endIndex)
                throw CredentialImportError.tooManyColumns(line: rowLine)
            }
            if rows.count > maximumRows + 1 {
                var partial = rows
                clear(&partial)
                field.resetBytes(in: field.startIndex..<field.endIndex)
                throw CredentialImportError.tooManyRows(line: rowLine)
            }
        }
        if state == .quoted {
            var partial = rows
            clear(&partial)
            field.resetBytes(in: field.startIndex..<field.endIndex)
            throw CredentialImportError.unterminatedQuotedField(line: fieldStartLine)
        }
        if sawAnything && (!field.isEmpty || !cells.isEmpty || state != .start) {
            endRow(at: rowLine)
        }
        return rows
    }

    static func trimmed(_ data: Data) -> Data {
        var lower = data.startIndex
        var upper = data.endIndex
        while lower < upper, [0x09, 0x0a, 0x0d, 0x20].contains(data[lower]) { data.formIndex(after: &lower) }
        while upper > lower {
            let before = data.index(before: upper)
            guard [0x09, 0x0a, 0x0d, 0x20].contains(data[before]) else { break }
            upper = before
        }
        return Data(data[lower..<upper])
    }

    static func clear(_ rows: inout [Row]) {
        for rowIndex in rows.indices {
            for cellIndex in rows[rowIndex].cells.indices {
                rows[rowIndex].cells[cellIndex].resetBytes(in: rows[rowIndex].cells[cellIndex].startIndex..<rows[rowIndex].cells[cellIndex].endIndex)
            }
        }
        rows.removeAll(keepingCapacity: false)
    }
}
