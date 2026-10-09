import Foundation

// BL-092 — searching the inventory, and binding a row to an environment.
//
// Everything in this file is pure: it takes metadata by value and returns
// value types. That is deliberate for the same reason `ProvisioningPolicy` is
// separate from the broker — every row, every filter and every refusal is
// reachable in a self-test without a Keychain, a network or a modal sheet, and
// the UI lane and the MCP tool read the *same* function rather than two
// restatements of the same rules.

// MARK: - The query

/// `inventory.search(query, filters: project, provider, kind)`.
///
/// The text is a local substring match over already-cached, already-value-free
/// rows. It is never sent anywhere, never becomes part of a URL and never
/// reaches a provider — it is bounded here anyway, because an unbounded string
/// from an agent reaches an approval sheet.
public struct InventoryQuery: Codable, Hashable, Sendable {
    public static let maximumTextBytes = 128
    public static let maximumLimit = 100
    public static let defaultLimit = 50

    public let text: String
    public let projectID: UUID?
    public let environmentID: UUID?
    public let provider: Provider?
    public let kind: ResourceKind?
    public let limit: Int

    public init(text: String = "", projectID: UUID? = nil, environmentID: UUID? = nil, provider: Provider? = nil, kind: ResourceKind? = nil, limit: Int = InventoryQuery.defaultLimit) {
        self.text = text
        self.projectID = projectID
        self.environmentID = environmentID
        self.provider = provider
        self.kind = kind
        self.limit = limit
    }

    /// Refuses what cannot be a query and clamps what can. An oversized text is
    /// a refusal rather than a truncation, because silently searching for
    /// something other than what was asked is worse than saying no.
    public func validated() throws -> InventoryQuery {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count <= Self.maximumTextBytes else {
            throw VaultageError.invalidInput("A resource search is at most \(Self.maximumTextBytes) characters.")
        }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("A resource search cannot contain control characters.")
        }
        guard limit >= 1 else { throw VaultageError.invalidInput("A resource search returns at least one row.") }
        return InventoryQuery(text: trimmed, projectID: projectID, environmentID: environmentID, provider: provider, kind: kind, limit: min(limit, Self.maximumLimit))
    }

    /// The filters, in the words an approval sheet and a log line use.
    public var description: String {
        var parts: [String] = []
        if !text.isEmpty { parts.append("matching \"\(text)\"") }
        if let provider { parts.append("on \(provider.title)") }
        if let kind { parts.append("of kind \(kind.label.lowercased())") }
        if projectID != nil { parts.append("in one project") }
        if environmentID != nil { parts.append("bound to one environment") }
        return parts.isEmpty ? "every cached resource" : parts.joined(separator: ", ")
    }
}

// MARK: - The rows

/// One inventory row, as every surface shows it and as MCP returns it.
public struct InventoryRow: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let provider: String
    public let providerTitle: String
    public let kind: String
    public let kindLabel: String
    public let name: String
    public let providerResourceID: String
    /// "Project checkout-web", or nil when the read was account-level.
    public let parent: String?
    public let region: String?
    public let attributes: [String: String]
    public let connectionID: UUID
    public let connectionLabel: String
    public let fetchedAt: Date
    public let isStale: Bool
    /// The environments this resource is already bound into, through a
    /// binding's resource scope. An empty list is the "not connected to any of
    /// your environments yet" state the Resources module shows.
    public let boundEnvironmentIDs: [UUID]
    /// True when this row is a thing a binding can be *scoped to* — a Vercel
    /// project, a Cloudflare Worker script. A DNS record is a resource but not
    /// a scope, so binding it is refused rather than offered and ignored.
    public let bindable: Bool

    public init(record: ResourceRecord, connectionLabel: String, isStale: Bool, boundEnvironmentIDs: [UUID], bindable: Bool) {
        id = record.id
        provider = record.provider.rawValue
        providerTitle = record.provider.title
        kind = record.kind.rawValue
        kindLabel = record.kind.label
        name = record.name
        providerResourceID = record.providerResourceID
        parent = record.parent?.display
        region = record.region
        attributes = record.attributes
        connectionID = record.connectionID
        self.connectionLabel = connectionLabel
        fetchedAt = record.fetchedAt
        self.isStale = isStale
        self.boundEnvironmentIDs = boundEnvironmentIDs
        self.bindable = bindable
    }
}

/// One provisioned resource, for the per-environment view. BL-074 records these
/// separately — they are things Vaultage *created*, not things it discovered —
/// and the Project detail has to show both or it is not "the resources in this
/// environment".
public struct InventoryProvisionedRow: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let provider: String
    public let kind: String
    public let label: String
    public let providerResourceID: String
    public let createdAt: Date
    public let status: String

    public init(id: UUID, provider: String, kind: String, label: String, providerResourceID: String, createdAt: Date, status: String) {
        self.id = id
        self.provider = provider
        self.kind = kind
        self.label = label
        self.providerResourceID = providerResourceID
        self.createdAt = createdAt
        self.status = status
    }
}

/// What one connection's slice of the inventory looks like: how much is
/// cached, when it was refreshed, and what failed last time.
///
/// This is the ticket's "provider errors shown per provider without hiding the
/// rest": a failing connection contributes a status with failures and the other
/// connections' rows are unaffected.
public struct InventoryConnectionStatus: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let provider: String
    public let providerTitle: String
    public let connectionLabel: String
    public let recordCount: Int
    public let staleCount: Int
    public let lastRefreshedAt: Date?
    /// Nil when the last refresh completed. Set when it was interrupted.
    public let refreshInterrupted: Bool
    public let failures: [InventoryOperationOutcome]
    /// True when this connection has reads the inventory knows how to run but
    /// no binding allows any of them, so refreshing would refuse.
    public let hasNoRefreshableBinding: Bool
    public let firstPageOnly: Bool?

    public init(id: UUID, provider: String, providerTitle: String, connectionLabel: String, recordCount: Int, staleCount: Int, lastRefreshedAt: Date?, refreshInterrupted: Bool, failures: [InventoryOperationOutcome], hasNoRefreshableBinding: Bool, firstPageOnly: Bool? = nil) {
        self.id = id
        self.provider = provider
        self.providerTitle = providerTitle
        self.connectionLabel = connectionLabel
        self.recordCount = recordCount
        self.staleCount = staleCount
        self.lastRefreshedAt = lastRefreshedAt
        self.refreshInterrupted = refreshInterrupted
        self.failures = failures
        self.hasNoRefreshableBinding = hasNoRefreshableBinding
        self.firstPageOnly = firstPageOnly
    }

    /// Never refreshed, everything stale, or the last refresh failed.
    public var needsRefresh: Bool {
        lastRefreshedAt == nil || refreshInterrupted || !failures.isEmpty || (recordCount > 0 && staleCount == recordCount)
    }

    /// The one sentence the Resources module shows under the provider's name.
    public var statusLine: String {
        if hasNoRefreshableBinding {
            return "No binding allows a read that would list resources here. Bind this connection to an environment first."
        }
        guard let lastRefreshedAt else { return "Never refreshed." }
        var line = "\(recordCount) resource\(recordCount == 1 ? "" : "s") · refreshed \(lastRefreshedAt.formatted(date: .abbreviated, time: .shortened))"
        if firstPageOnly == true { line += " · first page only; additional resources may exist" }
        if refreshInterrupted { line += " · that refresh was interrupted" }
        if !failures.isEmpty { line += " · \(failures.count) read\(failures.count == 1 ? "" : "s") failed" }
        else if staleCount > 0 { line += " · \(staleCount) stale" }
        return line
    }
}

/// The answer to one search.
public struct InventoryPage: Codable, Hashable, Sendable {
    public let rows: [InventoryRow]
    /// Every row that matched, before `limit`.
    public let totalMatching: Int
    public let staleCount: Int
    /// True when something a refresh would fix is wrong: a stale row, a
    /// connection that has never been refreshed, or a failed read last time.
    public let refreshNeeded: Bool
    public let connections: [InventoryConnectionStatus]
    /// Set only for a per-environment view.
    public let provisioned: [InventoryProvisionedRow]
    /// The instruction an agent acts on, in words. It is the "refresh needed"
    /// hint the ticket requires, and it always says who has to do it: refresh is
    /// a human action in Vaultage, never something an agent can trigger.
    public let message: String

    public init(rows: [InventoryRow], totalMatching: Int, staleCount: Int, refreshNeeded: Bool, connections: [InventoryConnectionStatus], provisioned: [InventoryProvisionedRow], message: String) {
        self.rows = rows
        self.totalMatching = totalMatching
        self.staleCount = staleCount
        self.refreshNeeded = refreshNeeded
        self.connections = connections
        self.provisioned = provisioned
        self.message = message
    }
}

// MARK: - The rules

public extension ResourceInventory {
    /// The non-secret identifiers a bound scope pins.
    static func identifiers(of scope: ProviderResourceScope) -> Set<String> {
        Set([scope.accountID, scope.zoneID, scope.scriptName, scope.projectID].compactMap { $0 })
    }

    /// The environments a resource is already reachable in, through a binding
    /// whose scope either *is* this resource or *contains* it.
    static func boundEnvironmentIDs(of record: ResourceRecord, in state: VaultageMetadata) -> [UUID] {
        var found: [UUID] = []
        for binding in state.bindings where binding.connectionID == record.connectionID {
            guard let scope = binding.resourceScope else { continue }
            let pinned = identifiers(of: scope)
            let isTheResource = pinned.contains(record.providerResourceID)
            let containsTheResource = record.parent.map { pinned.contains($0.id) } ?? false
            guard isTheResource || containsTheResource, !found.contains(binding.environmentID) else { continue }
            found.append(binding.environmentID)
        }
        return found.sorted { $0.uuidString < $1.uuidString }
    }

    /// The bound scope this row would become, or nil when the row is a resource
    /// but not a container a binding can be scoped to.
    ///
    /// Three kinds qualify today. A GitHub repository (BL-128 slice 3c, from
    /// `github.list_repositories`) joined the first two, which are the
    /// containers a wave-1 read can discover: a Vercel project (from
    /// `vercel.list_projects`, which needs no scope of its own — this is the
    /// flagship path, and D34's own example) and a Cloudflare Worker script
    /// (from `cloudflare.worker.script.list`, whose parent account the scoped
    /// read already recorded).
    static func scope(for record: ResourceRecord) -> ProviderResourceScope? {
        let label = ResourceInventory.scopeLabel(for: record)
        let candidate: ProviderResourceScope?
        switch (record.provider, record.kind) {
        case (.vercel, .deploymentProject):
            candidate = ProviderResourceScope(kind: .vercelProject, projectID: record.providerResourceID, label: label)
        case (.cloudflare, .workerScript):
            guard let parent = record.parent, parent.kind == .account else { return nil }
            candidate = ProviderResourceScope(kind: .cloudflareWorkerScript, accountID: parent.id, scriptName: record.providerResourceID, label: label)
        case (.github, .repository):
            // BL-128 slice 3c. A repository from `github.list_repositories`,
            // whose identifier is its `owner/name`: the container of its
            // Actions secrets. The scope is refused below unless that is
            // exactly a canonical repository.
            candidate = ProviderResourceScope(kind: .githubRepository, repository: record.providerResourceID, label: label)
        default:
            candidate = nil
        }
        guard let candidate, candidate.isWellFormed else { return nil }
        return candidate
    }

    /// A scope label is narrower than a record name — it goes on an approval
    /// sheet — so a name that would not pass falls back to the provider id
    /// rather than making an otherwise bindable row unbindable.
    static func scopeLabel(for record: ResourceRecord) -> String {
        let allowed = "^[A-Za-z0-9 ._:/@()'-]+$"
        if record.name.utf8.count <= 96, record.name.range(of: allowed, options: .regularExpression) != nil { return record.name }
        return record.providerResourceID
    }

    /// The read operations a binding scoped to this row would be given by
    /// default: its reads, and nothing that changes provider state. A mutation
    /// is added only when a human ticks it, and the binding sheet names it.
    static func defaultOperations(for scope: ProviderResourceScope) -> Set<Operation> {
        Set(Operation.allCases.filter {
            $0.isResourceOperation
                && $0.taxonomy.kind == .read
                && $0.provider == scope.provider
                && ProviderResourceScope.kinds(for: $0).contains(scope.kind)
        })
    }

    /// The connections a project can reach, through its bindings.
    static func connectionIDs(inProject projectID: UUID, in state: VaultageMetadata) -> Set<UUID> {
        Set(state.bindings.filter { $0.projectID == projectID }.map(\.connectionID))
    }

    // MARK: Search

    static func search(_ query: InventoryQuery, in state: VaultageMetadata, at instant: Date) -> InventoryPage {
        let connectionsByID = Dictionary(uniqueKeysWithValues: state.connections.map { ($0.id, $0) })
        let projectConnections = query.projectID.map { connectionIDs(inProject: $0, in: state) }
        let needle = query.text.lowercased()

        var matched: [(record: ResourceRecord, bound: [UUID])] = []
        for record in state.resources {
            guard let connection = connectionsByID[record.connectionID] else { continue }
            if let provider = query.provider, record.provider != provider { continue }
            if let kind = query.kind, record.kind != kind { continue }
            if let projectConnections, !projectConnections.contains(record.connectionID) { continue }
            let bound = boundEnvironmentIDs(of: record, in: state)
            if let environmentID = query.environmentID, !bound.contains(environmentID) { continue }
            if !needle.isEmpty {
                let haystack = [record.name, record.providerResourceID, record.parent?.label ?? "", record.parent?.id ?? "", connection.label]
                guard haystack.contains(where: { $0.lowercased().contains(needle) }) else { continue }
            }
            matched.append((record, bound))
        }

        let rows = matched.prefix(query.limit).map { pair in
            InventoryRow(
                record: pair.record,
                connectionLabel: connectionsByID[pair.record.connectionID]?.label ?? "",
                isStale: pair.record.isStale(at: instant),
                boundEnvironmentIDs: pair.bound,
                bindable: scope(for: pair.record) != nil
            )
        }
        let staleCount = matched.filter { $0.record.isStale(at: instant) }.count

        // Which connections the page reports on. A page filtered to one
        // provider or one project reports that slice; an unfiltered page
        // reports every connection, including the ones with nothing cached —
        // because "this provider has never been refreshed" is exactly what the
        // Resources module and the agent need to be told.
        let reported = state.connections.filter { connection in
            if let provider = query.provider, connection.provider != provider { return false }
            if let projectConnections, !projectConnections.contains(connection.id) { return false }
            return true
        }
        let statuses = reported.map { connection in
            status(of: connection, in: state, at: instant)
        }.sorted { $0.providerTitle < $1.providerTitle }

        let provisioned: [InventoryProvisionedRow]
        if let environmentID = query.environmentID {
            provisioned = state.provisionedResources
                .filter { $0.environmentID == environmentID }
                .sorted { $0.createdAt > $1.createdAt }
                .map { record in
                    InventoryProvisionedRow(
                        id: record.id,
                        provider: record.provider.rawValue,
                        kind: record.kind.rawValue,
                        label: state.vaultItems.first { $0.id == record.vaultItemID }?.label ?? "(removed vault item)",
                        providerResourceID: record.providerResourceID,
                        createdAt: record.createdAt,
                        status: record.revokedAt != nil ? "revoked" : (record.revocationFailedAt != nil ? "revocation_failed" : "live")
                    )
                }
        } else {
            provisioned = []
        }

        let refreshNeeded = statuses.contains(where: \.needsRefresh) || staleCount > 0
        return InventoryPage(
            rows: Array(rows),
            totalMatching: matched.count,
            staleCount: staleCount,
            refreshNeeded: refreshNeeded,
            connections: statuses,
            provisioned: provisioned,
            message: message(matched: matched.count, returned: rows.count, staleCount: staleCount, statuses: statuses, query: query)
        )
    }

    static func status(of connection: Connection, in state: VaultageMetadata, at instant: Date) -> InventoryConnectionStatus {
        let records = state.resources.filter { $0.connectionID == connection.id }
        let refresh = lastRefresh(of: connection.id, in: state)
        return InventoryConnectionStatus(
            id: connection.id,
            provider: connection.provider.rawValue,
            providerTitle: connection.provider.title,
            connectionLabel: connection.label,
            recordCount: records.count,
            staleCount: records.filter { $0.isStale(at: instant) }.count,
            lastRefreshedAt: refresh?.finishedAt ?? refresh?.startedAt,
            refreshInterrupted: refresh?.isInFlight ?? false,
            failures: refresh?.failures ?? [],
            hasNoRefreshableBinding: InventoryRefreshPlan.steps(for: connection.id, in: state).isEmpty,
            // Render's compiled inventory routes cover first pages only. This
            // fallback also labels legacy caches and retained rows after a
            // failed/interrupted retry replaces the refresh outcome.
            firstPageOnly: connection.provider == .render || refresh?.succeeded.contains { $0.firstPageOnly == true } == true ? true : nil
        )
    }

    /// The agent-facing instruction. It never tells an agent to refresh,
    /// because an agent cannot: refresh is a human action in Vaultage, and
    /// saying otherwise would send it round a loop it cannot exit.
    private static func message(matched: Int, returned: Int, staleCount: Int, statuses: [InventoryConnectionStatus], query: InventoryQuery) -> String {
        var sentences: [String] = []
        if matched == 0 {
            sentences.append("No cached resource matches \(query.description).")
        } else if returned < matched {
            sentences.append("\(returned) of \(matched) cached resources matching \(query.description).")
        } else {
            sentences.append("\(matched) cached resource\(matched == 1 ? "" : "s") matching \(query.description).")
        }
        let partial = statuses.filter { $0.firstPageOnly == true && $0.lastRefreshedAt != nil }
        if !partial.isEmpty {
            sentences.append("\(partial.map(\.providerTitle).joined(separator: ", ")) inventory covers the first page only; additional resources may exist.")
        }
        let never = statuses.filter { $0.lastRefreshedAt == nil && !$0.hasNoRefreshableBinding }
        let failed = statuses.filter { !$0.failures.isEmpty }
        let unbindable = statuses.filter(\.hasNoRefreshableBinding)
        if !never.isEmpty {
            sentences.append("\(never.map(\.providerTitle).joined(separator: ", ")) has never been refreshed, so resources there are not listed here yet.")
        }
        if staleCount > 0 {
            sentences.append("\(staleCount) row\(staleCount == 1 ? " is" : "s are") stale and may no longer match the provider.")
        }
        if !failed.isEmpty {
            sentences.append("The last refresh of \(failed.map(\.providerTitle).joined(separator: ", ")) had a failed read, so that provider's list may be incomplete.")
        }
        if !unbindable.isEmpty {
            sentences.append("\(unbindable.map(\.providerTitle).joined(separator: ", ")) has no binding that allows a resource read, so nothing can be listed for it.")
        }
        if !never.isEmpty || staleCount > 0 || !failed.isEmpty {
            sentences.append("Refreshing is a human action: ask the owner to open Services in Vaultage and refresh the provider's resources. Values are never cached and never returned here.")
        } else {
            sentences.append("Values are never cached and never returned here. Binding a resource to an environment is approved by the owner in Vaultage.")
        }
        return sentences.joined(separator: " ")
    }
}

// MARK: - What the provisioning conversation checks first

/// One cached resource that could serve a provisioning request, so the agent
/// can offer it before anyone authorizes creating a second thing.
///
/// D34's example, in the ticket's own words: "an existing Vercel project named
/// X matches; bind it?" Nothing here decides anything — the human still
/// approves, in Vaultage — and nothing here is a capability: `id` is the
/// inventory row's local id, which only `inventory.bind` accepts and only a
/// desktop approval acts on.
public struct ProvisioningInventoryMatch: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let provider: String
    public let kind: String
    public let name: String
    public let providerResourceID: String
    public let parent: String?
    public let isStale: Bool
    /// The environments it is already bound into, so an agent does not offer to
    /// bind something that is already bound where it is asking.
    public let boundEnvironmentIDs: [UUID]
    public let detail: String

    public init(id: UUID, provider: String, kind: String, name: String, providerResourceID: String, parent: String?, isStale: Bool, boundEnvironmentIDs: [UUID], detail: String) {
        self.id = id
        self.provider = provider
        self.kind = kind
        self.name = name
        self.providerResourceID = providerResourceID
        self.parent = parent
        self.isStale = isStale
        self.boundEnvironmentIDs = boundEnvironmentIDs
        self.detail = detail
    }
}

public extension ResourceInventory {
    /// Every resource kind any compiled read contributes. Derived rather than
    /// listed, so a wave-2 provider widens the MCP tool's filter by being
    /// classified rather than by being added to a list here.
    static var searchableKinds: [ResourceKind] {
        var seen: Set<ResourceKind> = []
        for operation in Operation.allCases {
            if let kind = InventoryReadProjection.kind(of: operation) { seen.insert(kind) }
        }
        return seen.sorted { $0.rawValue < $1.rawValue }
    }

    /// The cached resources a provisioning request could be satisfied by
    /// instead of creating something new.
    ///
    /// A match is a row this build could actually *bind* — `scope(for:)` returns
    /// a scope — whose scope kind is one the capability's own operations run
    /// against. That last condition is what keeps the offer honest: suggesting a
    /// Vercel project for a Cloudflare DNS capability would be noise, and
    /// suggesting something no operation can act on would be a dead end.
    ///
    /// It is written against scope kinds rather than against a capability's
    /// name, so the day `ProvisioningCapability` gains a Vercel case, D34's own
    /// example — "an existing Vercel project named X matches" — works without a
    /// change here.
    static func provisioningMatches(
        provider: Provider,
        scopeKinds: Set<ProviderResourceScopeKind>,
        projectID: UUID,
        environmentID: UUID,
        in state: VaultageMetadata,
        at instant: Date,
        limit: Int = 5
    ) -> [ProvisioningInventoryMatch] {
        guard !scopeKinds.isEmpty else { return [] }
        let reachable = connectionIDs(inProject: projectID, in: state)
        var matches: [ProvisioningInventoryMatch] = []
        for record in state.resources where record.provider == provider && reachable.contains(record.connectionID) {
            guard let scope = scope(for: record), scopeKinds.contains(scope.kind) else { continue }
            let bound = boundEnvironmentIDs(of: record, in: state)
            // Already bound here: there is nothing to offer.
            guard !bound.contains(environmentID) else { continue }
            let stale = record.isStale(at: instant)
            var detail = "An existing \(record.provider.title) \(record.kind.label.lowercased()) named \(record.name) matches. Bind it instead of creating a new one: the owner approves that in Vaultage."
            if !bound.isEmpty { detail += " It is already bound to \(bound.count) other environment(s)." }
            if stale { detail += " This row is stale; ask the owner to refresh \(record.provider.title) resources before relying on it." }
            matches.append(ProvisioningInventoryMatch(
                id: record.id,
                provider: record.provider.rawValue,
                kind: record.kind.rawValue,
                name: record.name,
                providerResourceID: record.providerResourceID,
                parent: record.parent?.display,
                isStale: stale,
                boundEnvironmentIDs: bound,
                detail: detail
            ))
            if matches.count >= limit { break }
        }
        return matches
    }
}

// MARK: - Binding a row

/// Exactly what `inventory.bind` changed, in the binding model that already
/// existed. Nothing here is new state: the change is a `resourceScope` and a
/// widened `allowedOperations` on one `Binding`, which is what BL-091 built.
public struct InventoryBindOutcome: Codable, Hashable, Sendable {
    public let resourceID: UUID
    public let bindingID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let connectionID: UUID
    public let scopeKind: String
    public let scopeLabel: String
    /// The scope this binding carried before, when it carried a different one.
    /// A re-scoped binding is a material change and the caller is told, in
    /// words, rather than having to diff it.
    public let replacedScope: String?
    public let addedOperations: [String]
    public let alreadyAllowedOperations: [String]
    public let summary: String

    public init(resourceID: UUID, bindingID: UUID, projectID: UUID, environmentID: UUID, connectionID: UUID, scopeKind: String, scopeLabel: String, replacedScope: String?, addedOperations: [String], alreadyAllowedOperations: [String], summary: String) {
        self.resourceID = resourceID
        self.bindingID = bindingID
        self.projectID = projectID
        self.environmentID = environmentID
        self.connectionID = connectionID
        self.scopeKind = scopeKind
        self.scopeLabel = scopeLabel
        self.replacedScope = replacedScope
        self.addedOperations = addedOperations
        self.alreadyAllowedOperations = alreadyAllowedOperations
        self.summary = summary
    }
}
