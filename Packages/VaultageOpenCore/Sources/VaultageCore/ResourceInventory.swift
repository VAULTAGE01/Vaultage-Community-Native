import Foundation

// BL-092 / owner decision D34 — the cross-provider Resources inventory.
//
// D34 says the unit of value is the provider resource, and its third clause
// says discovery is a first-class surface: "we also help you discover and
// connect to them with ease." BL-091 gave Vaultage typed operations on a
// resource the human had already named. This file is the other half — a
// **cache of what the connected providers say already exists**, so a human can
// find a resource without opening a dashboard and an agent can find one before
// proposing to create a second.
//
// Four rules shape every type here, and each one is a property of the model
// rather than of the care taken by whoever writes the next adapter:
//
// 1. **A record is never a value.** `ResourceRecord` has no field a credential
//    could be put in: identifiers, a display name, a parent, a region, and a
//    bounded map of documented attributes whose keys are checked against the
//    same denylist BL-091 applies inside the transport. A byte-scan test with a
//    positive control proves it for the metadata file as well as the type.
//
// 2. **The inventory is a cache, so every failure degrades to "not cached".**
//    A record this build cannot decode is dropped; a corrupt array becomes an
//    empty inventory; a record whose connection is gone is dropped. None of
//    that can make `metadata.json` unreadable, and none of it can *add*
//    authority — nothing here is ever consulted by a policy decision.
//
// 3. **Nothing here authorizes anything.** An inventory row is not a capability.
//    Acting on a resource still needs a binding, a scope the human attached,
//    and the approval class `ApprovalRequirement` assigns. `inventory.bind`
//    goes through `VaultageBroker.bindProviderResource`, which is desktop-only
//    and raises its own sheet.
//
// 4. **Refresh is on demand, never a poll.** There is no timer, no background
//    task and no refresh-on-launch. `minimumRefreshInterval` bounds how often a
//    human can ask, so a held-down button cannot become one.

// MARK: - The denylist

/// Attribute keys a cached record may never carry.
///
/// This is BL-091's `ResourceValueFree.forbiddenKeys`, restated in Core because
/// Core cannot import the provider module. `ResourceInventoryContracts` pins the
/// two sets together through `ResourceValueFreeProbe`, so they cannot drift.
///
/// The bare name `key` is deliberately **absent**, for the reason BL-091
/// recorded: Vercel calls an environment variable's *name* `key`, and denying it
/// would drop the one field the list exists to report. The compound names that
/// do mean a secret are denied individually.
public enum ResourceInventoryDenylist {
    public static let forbiddenAttributeKeys: Set<String> = [
        "value", "decrypted", "vsmvalue", "text", "secret", "plaintext", "password",
        "token", "content_value", "privatekey", "apikey", "secretkey",
        "accesstoken", "refreshtoken", "clientsecret", "signingsecret"
    ]

    /// True when this key may never be stored. Compared case-insensitively and
    /// with separators removed, so `Access-Token`, `access_token` and
    /// `accessToken` are all the same denied name.
    public static func isForbidden(_ key: String) -> Bool {
        let folded = key.lowercased().filter { $0 != "_" && $0 != "-" && $0 != "." && $0 != " " }
        if forbiddenAttributeKeys.contains(key.lowercased()) { return true }
        return forbiddenAttributeKeys.contains { candidate in
            candidate.filter { $0 != "_" && $0 != "-" } == folded
        }
    }
}

// MARK: - The record

/// What a resource's container is, when the provider names one.
///
/// D34's inventory has to be able to say "this environment variable is on
/// *that* project" and "this DNS record is in *that* zone", because a bare name
/// is ambiguous across a builder's accounts. Every field is an identifier or a
/// label the provider already returned through a value-free projection.
public struct ResourceParent: Codable, Hashable, Sendable {
    /// The ticket names account, team and project. Three more are here because
    /// the wave-1 reads genuinely return them and a row without its container is
    /// ambiguous: a DNS record's container is a **zone**, a Worker secret's is
    /// the **Worker script**, and Sentry's and Supabase's lists hang off an
    /// **organization**.
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case account, team, project, zone, organization
        case workerScript = "worker_script"
        /// BL-128 slice 3b. An Actions secret's container is its repository.
        case repository
        public var label: String {
            switch self {
            case .account: "Account"
            case .team: "Team"
            case .project: "Project"
            case .zone: "Zone"
            case .organization: "Organization"
            case .workerScript: "Worker script"
            case .repository: "Repository"
            }
        }
    }

    public let kind: Kind
    public let id: String
    public let label: String?

    public init(kind: Kind, id: String, label: String? = nil) {
        self.kind = kind
        self.id = id
        self.label = label
    }

    /// The words a row shows: "Project checkout-web", or the id when the
    /// provider gave no label.
    public var display: String { "\(kind.label) \(label ?? id)" }
}

/// One provider resource Vaultage has seen, cached value-free.
///
/// `id` is Vaultage's own local identifier and is stable across refreshes for
/// the same provider resource, so a binding made from a row does not break when
/// the inventory is refreshed. It is derived from the identity of the resource
/// (connection, kind, provider id, parent) rather than randomly assigned, which
/// is also what makes `normalize` able to de-duplicate.
public struct ResourceRecord: Codable, Identifiable, Hashable, Sendable {
    /// The most attributes a record keeps. Small on purpose: attributes are for
    /// recognising a row, not for mirroring a provider object.
    public static let maximumAttributes = 6
    public static let maximumIdentifierBytes = 255
    public static let maximumNameBytes = 255
    public static let maximumAttributeValueBytes = 96
    public static let maximumRegionBytes = 32

    public let id: UUID
    public let connectionID: UUID
    public let provider: Provider
    public let kind: ResourceKind
    /// The display name, or the provider id when the provider named nothing a
    /// value-free projection would accept.
    public let name: String
    /// The provider's own identifier. Opaque, bounded, closed charset.
    public let providerResourceID: String
    /// The account, team, project, zone or organization this lives in.
    public let parent: ResourceParent?
    /// Where applicable, and only where the provider documents it as a region.
    public let region: String?
    /// Bounded, value-free, denylisted documented attributes: a DNS record's
    /// type and content, a Supabase project's status, a Vercel variable's
    /// target. Never a value and never free provider text.
    public let attributes: [String: String]
    public let fetchedAt: Date
    /// When this row stops being presented as current. It is a display and
    /// hinting fact only: nothing refuses to act because a row is stale, because
    /// a row authorizes nothing in the first place.
    public let staleAfter: Date

    public init(
        id: UUID,
        connectionID: UUID,
        provider: Provider,
        kind: ResourceKind,
        name: String,
        providerResourceID: String,
        parent: ResourceParent? = nil,
        region: String? = nil,
        attributes: [String: String] = [:],
        fetchedAt: Date,
        staleAfter: Date
    ) {
        self.id = id
        self.connectionID = connectionID
        self.provider = provider
        self.kind = kind
        self.name = name
        self.providerResourceID = providerResourceID
        self.parent = parent
        self.region = region
        self.attributes = attributes
        self.fetchedAt = fetchedAt
        self.staleAfter = staleAfter
    }

    /// The only constructor a refresh uses. It validates every field and returns
    /// nil rather than storing something that failed a shape — a dropped row is
    /// always a safe outcome for a cache, and a stored row that nobody checked
    /// is not.
    public static func make(
        connectionID: UUID,
        provider: Provider,
        kind: ResourceKind,
        name: String?,
        providerResourceID: String,
        parent: ResourceParent? = nil,
        region: String? = nil,
        attributes: [String: String] = [:],
        fetchedAt: Date,
        staleAfter: Date
    ) -> ResourceRecord? {
        guard let identifier = ResourceInventory.identifier(providerResourceID, maxBytes: maximumIdentifierBytes) else { return nil }
        guard fetchedAt.timeIntervalSince1970.isFinite, staleAfter.timeIntervalSince1970.isFinite else { return nil }
        let cleanedParent = parent.flatMap(ResourceInventory.repairedParent)
        let display = name.flatMap { ResourceInventory.displayText($0, maxBytes: maximumNameBytes) } ?? identifier
        let cleanedRegion = region.flatMap { ResourceInventory.identifier($0, maxBytes: maximumRegionBytes) }
        return ResourceRecord(
            id: ResourceInventory.localIdentity(connectionID: connectionID, kind: kind, providerResourceID: identifier, parent: cleanedParent),
            connectionID: connectionID,
            provider: provider,
            kind: kind,
            name: display,
            providerResourceID: identifier,
            parent: cleanedParent,
            region: cleanedRegion,
            attributes: ResourceInventory.repairedAttributes(attributes),
            fetchedAt: fetchedAt,
            staleAfter: max(staleAfter, fetchedAt)
        )
    }

    /// The tuple that makes two rows the same resource. `id` is derived from it,
    /// so this is also what `normalize` de-duplicates on.
    public var identityKey: String {
        "\(connectionID.uuidString)|\(kind.rawValue)|\(providerResourceID)|\(parent?.id ?? "")"
    }

    public func isStale(at instant: Date) -> Bool { staleAfter <= instant }

    /// The repair pass for one record, applied on every decode. It cleans what
    /// can be cleaned and refuses what cannot: a record with no usable provider
    /// identifier is not a resource, so it is dropped rather than kept as a row
    /// nobody could act on.
    public var repaired: ResourceRecord? {
        ResourceRecord.make(
            connectionID: connectionID,
            provider: provider,
            kind: kind,
            name: name,
            providerResourceID: providerResourceID,
            parent: parent,
            region: region,
            attributes: attributes,
            fetchedAt: fetchedAt,
            staleAfter: staleAfter
        )
    }
}

/// Decodes a `ResourceRecord` without ever throwing.
///
/// One record written by a newer build — a resource kind this one does not
/// know, a provider it has never heard of — must not make the whole metadata
/// file unreadable. The inventory is a cache: a row this build cannot read is a
/// row it does not have.
struct DecodedResourceRecord: Decodable {
    let record: ResourceRecord?
    init(from decoder: Decoder) throws {
        record = try? ResourceRecord(from: decoder)
    }
}

// MARK: - The refresh ledger

/// What one on-demand refresh of one connection did.
///
/// It is the rate-limit claim, the "last refreshed" the UI shows, and the
/// per-provider error list the ticket requires ("provider errors shown per
/// provider without hiding the rest"). One record per connection: a refresh
/// replaces the previous record rather than appending, so this cannot grow.
public struct InventoryRefreshRecord: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public let connectionID: UUID
    public let startedAt: Date
    /// Nil while a refresh is in flight. A claim that was never completed — the
    /// app was quit mid-refresh — still holds the rate-limit window and is
    /// reported as interrupted rather than as a success.
    public let finishedAt: Date?
    public let operations: [InventoryOperationOutcome]

    public init(id: UUID = UUID(), connectionID: UUID, startedAt: Date, finishedAt: Date? = nil, operations: [InventoryOperationOutcome] = []) {
        self.id = id
        self.connectionID = connectionID
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.operations = operations
    }

    public var isInFlight: Bool { finishedAt == nil }
    public var failures: [InventoryOperationOutcome] { operations.filter { $0.failure != nil } }
    public var succeeded: [InventoryOperationOutcome] { operations.filter { $0.failure == nil } }
    public var recordCount: Int { operations.reduce(0) { $0 + $1.recordCount } }
}

/// One read the refresh ran, and what came back. `failure` is already
/// `Redactor.safeError`-bounded by the broker; nothing here is provider text.
public struct InventoryOperationOutcome: Codable, Hashable, Sendable {
    public let operation: String
    public let bindingID: UUID
    /// How many records this read contributed.
    public let recordCount: Int
    /// The count reported by the projection; may be a page count rather than
    /// an account total. Coverage is recorded separately.
    public let reportedCount: Int?
    /// Optional for backward decoding of pre-coverage metadata. True means
    /// this read covers only its first page, not the whole account.
    public let firstPageOnly: Bool?
    /// Nil on success.
    public let failure: String?

    public init(operation: String, bindingID: UUID, recordCount: Int, reportedCount: Int? = nil, failure: String? = nil, firstPageOnly: Bool? = nil) {
        self.operation = operation
        self.bindingID = bindingID
        self.recordCount = recordCount
        self.reportedCount = reportedCount
        self.firstPageOnly = firstPageOnly
        self.failure = failure
    }

    public var isTruncated: Bool {
        if firstPageOnly == true { return true }
        guard let reportedCount else { return false }
        return reportedCount > recordCount
    }
}

/// Decodes a refresh record without ever throwing, for the same reason
/// `DecodedResourceRecord` does.
struct DecodedInventoryRefresh: Decodable {
    let record: InventoryRefreshRecord?
    init(from decoder: Decoder) throws {
        record = try? InventoryRefreshRecord(from: decoder)
    }
}

// MARK: - The model's rules

public enum ResourceInventory {
    /// How long a refreshed row is presented as current. An hour: long enough
    /// that a working session does not spend its time refreshing, short enough
    /// that a row nobody has refreshed today says so on its face. Nothing
    /// refuses to act on a stale row — it is a display fact, and the MCP tool
    /// turns it into a "refresh needed" hint rather than an error.
    public static let freshness: TimeInterval = 60 * 60

    /// D34's "refresh on demand per provider (never a background poll)". A
    /// human may ask again after a minute; `force` is for the case where they
    /// have just changed something at the provider and know the cache is wrong.
    public static let minimumRefreshInterval: TimeInterval = 60

    public static let maximumRecordsPerConnection = 500
    public static let maximumRecords = 2_000

    /// The namespace that makes a local record id stable and non-guessable
    /// across refreshes for the same provider resource.
    private static let identityNamespace = "vaultage.inventory.record.v1"

    static func localIdentity(connectionID: UUID, kind: ResourceKind, providerResourceID: String, parent: ResourceParent?) -> UUID {
        let hex = CanonicalDigest.hex([identityNamespace, connectionID.uuidString, kind.rawValue, providerResourceID, parent?.kind.rawValue ?? "none", parent?.id ?? "none"])
        return uuid(fromHex: hex) ?? UUID()
    }

    /// The first 32 hexadecimal characters of the digest, laid out as a UUID.
    /// It is a name, not a secret, and it is derived rather than random so the
    /// same resource keeps the same row id between refreshes.
    private static func uuid(fromHex hex: String) -> UUID? {
        let characters = Array(hex.prefix(32))
        guard characters.count == 32 else { return nil }
        let grouped = String(characters[0..<8]) + "-" + String(characters[8..<12]) + "-" + String(characters[12..<16]) + "-" + String(characters[16..<20]) + "-" + String(characters[20..<32])
        return UUID(uuidString: grouped)
    }

    // MARK: Bounded shapes

    /// Opaque provider identifiers. The same charset `ValueFree.identifier`
    /// applies in the provider module, restated here because Core cannot import
    /// it and because a record decoded from disk is input again on arrival.
    static func identifier(_ value: String?, maxBytes: Int) -> String? {
        bounded(value, maxBytes: maxBytes, pattern: "^[A-Za-z0-9._:/@-]+$")
    }

    /// Human-authored display text. Wider than an identifier, still closed, so
    /// provider text can never carry a control character, markup or a newline
    /// into a row, a sheet or an MCP reply.
    ///
    /// `+` is here and is not in `ValueFree.displayText`'s charset: BL-091's
    /// Vercel projection joins a variable's targets as `preview+production`,
    /// and that attribute is one of the few facts that makes an
    /// environment-variable row recognisable.
    static func displayText(_ value: String?, maxBytes: Int) -> String? {
        bounded(value, maxBytes: maxBytes, pattern: "^[A-Za-z0-9 ._:/@()'*+-]+$")
    }

    private static func bounded(_ value: String?, maxBytes: Int, pattern: String) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= maxBytes,
              trimmed.range(of: pattern, options: .regularExpression) != nil else { return nil }
        return trimmed
    }

    static func repairedParent(_ parent: ResourceParent) -> ResourceParent? {
        guard let id = identifier(parent.id, maxBytes: ResourceRecord.maximumIdentifierBytes) else { return nil }
        return ResourceParent(kind: parent.kind, id: id, label: parent.label.flatMap { displayText($0, maxBytes: ResourceRecord.maximumNameBytes) })
    }

    /// Drops every attribute that is denied, malformed, or over the cap. A bad
    /// attribute costs the row nothing: it is dropped, the row is kept, and the
    /// row was never going to be read for that key anyway.
    static func repairedAttributes(_ attributes: [String: String]) -> [String: String] {
        var cleaned: [String: String] = [:]
        for key in attributes.keys.sorted() {
            guard cleaned.count < ResourceRecord.maximumAttributes else { break }
            guard !ResourceInventoryDenylist.isForbidden(key) else { continue }
            guard key.utf8.count <= 32, key.range(of: "^[a-z][a-z0-9_]*$", options: .regularExpression) != nil else { continue }
            guard let value = displayText(attributes[key], maxBytes: ResourceRecord.maximumAttributeValueBytes) else { continue }
            cleaned[key] = value
        }
        return cleaned
    }

    // MARK: The repair pass

    /// The schema-15 migration and the repair pass, in one function, run on
    /// every decode exactly as `VaultOrganization.normalize` is.
    ///
    /// It is idempotent — running it twice changes nothing the first run did not
    /// — and it only ever *removes*. An inventory that has been hand-edited, was
    /// written by a newer build, or refers to a connection that has since been
    /// deleted comes back as a smaller inventory, never as an unreadable file
    /// and never as a row that claims more than it did before.
    public static func normalize(_ state: inout VaultageMetadata) {
        let connections = Dictionary(uniqueKeysWithValues: state.connections.map { ($0.id, $0) })

        var deduplicated: [String: ResourceRecord] = [:]
        for record in state.resources {
            // A row whose connection is gone is not "a resource you have": the
            // credential that could see it has been removed.
            guard let connection = connections[record.connectionID], connection.provider == record.provider else { continue }
            guard let repaired = record.repaired else { continue }
            if let existing = deduplicated[repaired.identityKey] {
                // The newest observation wins; a tie is broken on the id so the
                // outcome does not depend on array order.
                let newer = existing.fetchedAt == repaired.fetchedAt
                    ? (existing.id.uuidString <= repaired.id.uuidString ? existing : repaired)
                    : (existing.fetchedAt > repaired.fetchedAt ? existing : repaired)
                deduplicated[repaired.identityKey] = newer
            } else {
                deduplicated[repaired.identityKey] = repaired
            }
        }

        var kept: [ResourceRecord] = []
        var perConnection: [UUID: Int] = [:]
        // Newest first while capping, so a cap drops the oldest rows.
        for record in deduplicated.values.sorted(by: freshestFirst) {
            guard kept.count < maximumRecords else { break }
            let count = perConnection[record.connectionID, default: 0]
            guard count < maximumRecordsPerConnection else { continue }
            perConnection[record.connectionID] = count + 1
            kept.append(record)
        }
        state.resources = kept.sorted(by: displayOrder)

        // One refresh record per connection, and none for a connection that is
        // gone. A record with a non-finite date is dropped rather than becoming
        // a rate-limit window that never opens.
        var newest: [UUID: InventoryRefreshRecord] = [:]
        for refresh in state.inventoryRefreshes {
            guard connections[refresh.connectionID] != nil else { continue }
            guard refresh.startedAt.timeIntervalSince1970.isFinite else { continue }
            if let finished = refresh.finishedAt, !finished.timeIntervalSince1970.isFinite { continue }
            if let existing = newest[refresh.connectionID], existing.startedAt >= refresh.startedAt { continue }
            newest[refresh.connectionID] = refresh
        }
        state.inventoryRefreshes = newest.values.sorted { $0.connectionID.uuidString < $1.connectionID.uuidString }
    }

    static func freshestFirst(_ left: ResourceRecord, _ right: ResourceRecord) -> Bool {
        if left.fetchedAt != right.fetchedAt { return left.fetchedAt > right.fetchedAt }
        return left.id.uuidString < right.id.uuidString
    }

    /// The order every surface shows: provider, then kind, then name, then the
    /// provider id. Deterministic, so two builds render the same list.
    static func displayOrder(_ left: ResourceRecord, _ right: ResourceRecord) -> Bool {
        if left.provider != right.provider { return left.provider.rawValue < right.provider.rawValue }
        if left.kind != right.kind { return left.kind.rawValue < right.kind.rawValue }
        let order = left.name.localizedCaseInsensitiveCompare(right.name)
        if order != .orderedSame { return order == .orderedAscending }
        if left.providerResourceID != right.providerResourceID { return left.providerResourceID < right.providerResourceID }
        return left.id.uuidString < right.id.uuidString
    }

    // MARK: Merging a refresh

    /// Replaces the rows for exactly the (connection, kind) pairs a refresh
    /// actually re-read, and leaves every other row alone.
    ///
    /// That is the whole error-isolation rule, stated once: an operation that
    /// failed contributes no kind, so its previous rows survive the refresh
    /// rather than being deleted by a provider outage. A kind that was re-read
    /// and came back empty *does* clear, because an empty answer from a
    /// successful read is a fact.
    public static func merge(
        _ fresh: [ResourceRecord],
        connectionID: UUID,
        refreshedKinds: Set<ResourceKind>,
        into state: inout VaultageMetadata
    ) {
        state.resources.removeAll { $0.connectionID == connectionID && refreshedKinds.contains($0.kind) }
        state.resources.append(contentsOf: fresh.filter { $0.connectionID == connectionID && refreshedKinds.contains($0.kind) })
        normalize(&state)
    }

    // MARK: The rate limit

    /// The instant a connection may be refreshed again without `force`.
    public static func nextRefreshAllowed(for connectionID: UUID, in state: VaultageMetadata) -> Date? {
        guard let record = state.inventoryRefreshes.first(where: { $0.connectionID == connectionID }) else { return nil }
        return record.startedAt.addingTimeInterval(minimumRefreshInterval)
    }

    public static func isRateLimited(_ connectionID: UUID, in state: VaultageMetadata, at instant: Date) -> Bool {
        guard let next = nextRefreshAllowed(for: connectionID, in: state) else { return false }
        return next > instant
    }

    public static func lastRefresh(of connectionID: UUID, in state: VaultageMetadata) -> InventoryRefreshRecord? {
        state.inventoryRefreshes.first { $0.connectionID == connectionID }
    }
}
