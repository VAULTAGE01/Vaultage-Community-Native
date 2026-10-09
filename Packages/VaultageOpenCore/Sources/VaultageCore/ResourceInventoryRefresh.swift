import Foundation

// BL-092 — how the inventory is filled, and from what.
//
// The refresh is deliberately **not** a new way to talk to a provider. It runs
// the read operations that already exist, through the path an agent's read
// already takes, and turns their already-value-free results into records. That
// is the whole design, and it is what makes three separate guarantees free
// rather than re-argued:
//
//   * **No new approval class.** A read is `bindingsAndGrants` (BL-091's
//     mapping, unchanged). A refresh is therefore N ordinary reads: silent
//     under a grant that covers them, and one sheet each otherwise. There is no
//     "refresh" approval and no policy code that is only reached by a refresh.
//   * **No second parse of provider bytes.** The inventory reads the same
//     projection the agent and the receipt see. There is no second place a
//     value could escape, so BL-088's and BL-091's byte scans cover this path
//     too.
//   * **No new egress.** Every route a refresh can reach is a route a binding
//     already allows, in the compiled tables, with no query string.
//
// The cost of that choice is stated rather than hidden: a table-driven read
// reports its members as parallel comma-joined lists, and a name that failed
// `ValueFree.displayText` is dropped from the names list without dropping its
// id. `InventoryReadProjection` therefore pairs names with ids **only when the
// two lists are the same length**, and otherwise keeps the ids with no names.
// Pairing them wrongly would put one resource's name on another resource's row,
// which is worse than a row that shows an id.

// MARK: - What a refresh would do

/// One read a refresh will run: an operation, the binding that allows it, and
/// the bound scope it runs against.
public struct InventoryRefreshStep: Sendable, Hashable {
    public let projectID: UUID
    public let environmentID: UUID
    public let bindingID: UUID
    public let operation: Operation
    /// The kind this read contributes. Held here so error isolation can be
    /// expressed as "which kinds were actually re-read".
    public let kind: ResourceKind
    /// Nil for a read that needs no bound scope.
    public let scope: ProviderResourceScope?

    public init(projectID: UUID, environmentID: UUID, bindingID: UUID, operation: Operation, kind: ResourceKind, scope: ProviderResourceScope?) {
        self.projectID = projectID
        self.environmentID = environmentID
        self.bindingID = bindingID
        self.operation = operation
        self.kind = kind
        self.scope = scope
    }

    /// Two steps that would issue the same request. A connection bound into
    /// three environments must not list the same zone three times.
    var requestIdentity: String {
        "\(operation.rawValue)|\(scope?.canonicalFields.joined(separator: "|") ?? "none")"
    }
}

public enum InventoryRefreshPlan {
    /// Every read this connection's bindings already allow that would report a
    /// resource, de-duplicated by the request it would issue.
    ///
    /// The plan can only ever *narrow*: it selects from what a binding already
    /// allows, and a read that no binding allows is simply not in it. A
    /// connection with no binding has an empty plan and refreshing it refuses,
    /// rather than reaching a provider on the strength of the connection alone.
    public static func steps(for connectionID: UUID, in state: VaultageMetadata) -> [InventoryRefreshStep] {
        guard let connection = state.connections.first(where: { $0.id == connectionID }) else { return [] }
        var seen: Set<String> = []
        var steps: [InventoryRefreshStep] = []
        // Sorted, so the plan does not depend on the order records happen to sit
        // in the metadata file.
        for binding in state.bindings.filter({ $0.connectionID == connectionID }).sorted(by: { $0.id.uuidString < $1.id.uuidString }) {
            guard let project = state.projects.first(where: { $0.id == binding.projectID }),
                  let environment = state.environments.first(where: { $0.id == binding.environmentID }),
                  environment.projectID == project.id else { continue }
            for operation in binding.allowedOperations.sorted(by: { $0.rawValue < $1.rawValue }) {
                guard operation.provider == connection.provider,
                      operation.taxonomy.kind == .read,
                      let kind = InventoryReadProjection.kind(of: operation) else { continue }
                var scope: ProviderResourceScope?
                if operation.isResourceOperation {
                    // Exactly the conditions `resourceResolution` imposes. A
                    // step the broker would refuse does not belong in a plan.
                    guard let bound = binding.resourceScope,
                          bound.isWellFormed,
                          bound.provider == operation.provider,
                          ProviderResourceScope.kinds(for: operation).contains(bound.kind) else { continue }
                    scope = bound
                }
                let step = InventoryRefreshStep(projectID: project.id, environmentID: environment.id, bindingID: binding.id, operation: operation, kind: kind, scope: scope)
                guard seen.insert(step.requestIdentity).inserted else { continue }
                steps.append(step)
            }
        }
        return steps
    }
}

// MARK: - Turning a read into records

public enum InventoryReadProjection {
    /// Compiled copy only: never display a provider-supplied cursor, URL or
    /// arbitrary pagination message in the desktop refresh status.
    public static func coverageNotice(fields: [String: String]) -> String? {
        guard fields["inventory_scope"] == "first_page" else { return nil }
        return "Inventory covers the first page only; additional resources may exist."
    }

    /// Resource kinds whose provider route **is a secret store**.
    ///
    /// The wave-2 research found that Vercel, Netlify, Supabase, Railway and
    /// Render all return secret *values* when their variable or secret store is
    /// read. A cache of those routes would be a cache of credentials, so the
    /// inventory refuses these kinds unless the read is routed through BL-091's
    /// resource path, whose adapters remove every value-bearing field inside the
    /// transport before any projection reads it and refuse the whole reply if
    /// one survived. BL-088's table-driven family has no such seam at all.
    public static let secretStoreKinds: Set<ResourceKind> = [.environmentVariable, .workerSecret]

    /// The value-returning reads whose adapter provably drops values inside the
    /// transport (BL-091 §5: `VercelMutations.stripValues` *removes* rather than
    /// blanks, and `ResourceValueFree.carriesForbiddenValue` refuses the reply
    /// if anything survived).
    ///
    /// An allowlist rather than a flag, because "this route returns values" is a
    /// fact about the provider and "this adapter strips them" is a fact about
    /// our code, and only the second one makes caching safe. A value-returning
    /// read that is not named here contributes nothing to the inventory, whatever
    /// else is true of it.
    public static let valueStrippedReads: Set<Operation> = [.vercelEnvList]

    /// Whether a read may contribute to the inventory at all, as a function of
    /// the four facts that decide it.
    ///
    /// Written over raw facts rather than over an `Operation` so the rule can be
    /// exercised against operations that do not exist yet — a Railway variable
    /// list, a Render environment-group read — which is the only way to prove a
    /// refusal for something nobody has written.
    public static func isEligible(resource: ResourceKind, returnsValues: Bool, isResourceRouted: Bool, isValueStripped: Bool) -> Bool {
        // Not resources you own: the account a verify reports, a Stripe
        // balance, and BL-074's credential-minting class.
        switch resource {
        case .account, .balance, .apiToken: return false
        default: break
        }
        // A secret store may only be read through the path that has a stripping
        // seam, and only ever for names.
        if secretStoreKinds.contains(resource), !isResourceRouted { return false }
        // And a route documented to return values may only be read through an
        // adapter that is known to drop them.
        if returnsValues, !isValueStripped { return false }
        return true
    }

    /// The resource kind an operation contributes, or nil when it reports the
    /// account behind the credential rather than a resource — or when caching it
    /// would mean caching a secret store.
    ///
    /// The kind itself is read straight off BL-091's taxonomy rather than
    /// restated: the taxonomy already names every operation's resource kind, so
    /// a wave-2 provider's list joins the inventory by being classified.
    public static func kind(of operation: Operation) -> ResourceKind? {
        let taxonomy = operation.taxonomy
        guard isEligible(
            resource: taxonomy.resource,
            returnsValues: taxonomy.providerReturnsValues,
            isResourceRouted: operation.isResourceOperation,
            isValueStripped: valueStrippedReads.contains(operation)
        ) else { return nil }
        return taxonomy.resource
    }

    /// Which result fields a table-driven read reports its members in.
    ///
    /// This is the one restatement the design needs: BL-088's projections
    /// flatten their members into `ActionResult.fields` under names each adapter
    /// chose. A `read` operation with no row here contributes no records — it
    /// does not fail, and it does not guess — so a wave-2 provider's list is
    /// inert in the inventory until somebody names its fields.
    struct TableFields: Sendable {
        let identifiers: String
        let names: String?
        /// Parallel per-member lists, mapped to the attribute key they become.
        let attributes: [String: String]
        init(identifiers: String, names: String? = nil, attributes: [String: String] = [:]) {
            self.identifiers = identifiers
            self.names = names
            self.attributes = attributes
        }
    }

    static let tableFields: [Operation: TableFields] = [
        // Wave 1 (BL-088).
        .openAIListModels: TableFields(identifiers: "models"),
        .anthropicListModels: TableFields(identifiers: "models"),
        .geminiListModels: TableFields(identifiers: "models"),
        .vercelListProjects: TableFields(identifiers: "projects", names: "names"),
        .netlifyListSites: TableFields(identifiers: "sites", names: "names"),
        .supabaseListProjects: TableFields(identifiers: "projects", names: "names", attributes: ["statuses": "status"]),
        .neonListProjects: TableFields(identifiers: "projects", names: "names"),
        .resendListDomains: TableFields(identifiers: "domains", names: "names", attributes: ["statuses": "status"]),
        .sentryListOrganizations: TableFields(identifiers: "organizations", names: "slugs"),
        // Wave 2 (BL-089). Only the columns the adapter builds **per member** —
        // `ValueFree.statusColumn` and `booleanColumn` — are mapped to
        // attributes. A scalar field such as Mistral's `fine_tuned` or a
        // pagination flag is deliberately absent: it describes the page, not a
        // row, and pairing it by index would attach it to whichever row came
        // first.
        .railwayListProjects: TableFields(identifiers: "projects", names: "names"),
        .renderListProjects: TableFields(identifiers: "projects", names: "names"),
        .renderListServices: TableFields(identifiers: "services", names: "names", attributes: ["types": "type"]),
        .digitalOceanListProjects: TableFields(identifiers: "projects", names: "names", attributes: ["environments": "environment"]),
        .clerkListDomains: TableFields(identifiers: "domains", names: "names"),
        .mailgunListDomains: TableFields(identifiers: "domains", names: "names", attributes: ["states": "state", "disabled": "disabled"]),
        .posthogListOrganizations: TableFields(identifiers: "organizations", names: "names"),
        .twilioListAccounts: TableFields(identifiers: "accounts", names: "names", attributes: ["statuses": "status"]),
        .xaiListModels: TableFields(identifiers: "models"),
        .mistralListModels: TableFields(identifiers: "models"),
        .deepSeekListModels: TableFields(identifiers: "models"),
        .cohereListModels: TableFields(identifiers: "models", attributes: ["fine_tuned": "fine_tuned", "deprecated": "deprecated"]),
        // Wave 3 (BL-111). `owners` is a per-member column — each Actor's
        // owning account — so it maps to an attribute; without the `my`
        // filter the list mixes Actors this account created with Actors it has
        // only run, and that is exactly the distinction an inventory row needs
        // to carry.
        .apifyListActors: TableFields(identifiers: "actors", names: "names", attributes: ["owners": "owner"]),
        .gitlabListGroups: TableFields(identifiers: "groups", names: "names", attributes: ["visibilities": "visibility"]),
        // BL-128. GitHub's repositories carry `full_name` (`owner/repo`) as
        // the identifier and no separate name column: the full name *is* the
        // handle a human recognises and the one every other GitHub route
        // takes, so a name column would repeat it. The two per-member columns
        // the adapter builds map to attributes.
        .githubListRepositories: TableFields(identifiers: "repositories", attributes: ["visibilities": "visibility", "archived": "archived"]),
        // Wave 4 (BL-112). `paused` is a per-member column — Make's own
        // `isPaused` on each organization — so it maps to an attribute. A
        // paused organization runs no scenario, which is exactly the kind of
        // fact an inventory row should carry into a bind sheet.
        .makeListOrganizations: TableFields(identifiers: "organizations", names: "names", attributes: ["paused": "paused"]),
        .paddleListProducts: TableFields(identifiers: "products", names: "names", attributes: ["statuses": "status"]),
        // Segment's read answers with exactly one workspace — the one the token
        // belongs to — so the inventory carries a single row. A one-row list is
        // still a list: it goes through the same row projection, so the id and
        // the name of that row cannot come apart (PW-H1).
        .segmentGetWorkspace: TableFields(identifiers: "workspaces", names: "names"),
        .workosListOrganizations: TableFields(identifiers: "organizations", names: "names"),
        // BL-112's wave-5 follow-up. Bitbucket's `/user/workspaces` rows carry
        // no name: the embedded workspace object documents `slug`, `uuid`,
        // `type` and `links` and nothing else, so the inventory carries
        // identifiers alone rather than a name column of placeholders.
        .bitbucketListWorkspaces: TableFields(identifiers: "workspaces"),
        .lemonSqueezyListStores: TableFields(identifiers: "stores", names: "names"),
        .planetScaleListOrganizations: TableFields(identifiers: "organizations", names: "names"),
        // BL-116 wave 5 (D50). Hostinger Horizons' websites carry no name —
        // the resource has a description the customer wrote and this
        // projection does not read it — so identifiers, a status column and a
        // domain column go in and no name column does. Doppler's projects
        // carry a slug beside the id, which is the handle a human recognises
        // and the one Doppler's own routes accept, so it maps to an attribute.
        .glideListTables: TableFields(identifiers: "tables", names: "names"),
        .hostingerHorizonsListWebsites: TableFields(identifiers: "websites", attributes: ["statuses": "status", "domains": "domain"]),
        .v0ListScopes: TableFields(identifiers: "scopes", names: "names"),
        .dopplerListProjects: TableFields(identifiers: "projects", names: "names", attributes: ["slugs": "slug"]),
        // BL-117's Azure slot (D51). Microsoft Graph's organization read answers
        // with exactly one organization — the tenant the token was minted for —
        // so the inventory carries a single row, the shape Segment's workspace
        // read already has. A one-row list is still a list: the id and the name
        // come out of the same reader and cannot come apart (PW-H1).
        // `verified_domains` is deliberately **not** an attribute: it is a
        // count of the whole tenant rather than a per-member column, and
        // pairing it by index would attach a tenant-wide number to a row as if
        // it described that row.
        .azureGetOrganization: TableFields(identifiers: "tenant_id", names: "display_name"),
        // BL-117's Google Cloud slot (D51, §7.3). Cloud Resource Manager's
        // project list is an ordinary many-row list: the id column is
        // `projects` and the name column is `project_names`, both produced by
        // one pass of `ValueFree.list`, so they cannot come apart (PW-H1).
        // `nextPageToken`, the project number, the lifecycle state and the
        // customer-authored labels are not projected at all and therefore have
        // no attribute here — a column the projection does not produce would be
        // an inventory row that is always empty.
        .googleCloudListProjects: TableFields(identifiers: "projects", names: "project_names")
    ]

    /// Every onboarded read that the inventory accepts but has no field row.
    ///
    /// A provider onboarded later is *classified* by the taxonomy but its
    /// members still arrive in result fields the adapter named, so it needs a
    /// row above. This is the contract the suite asserts is empty, which turns
    /// "a new provider's list is inert in the inventory" from a note into a
    /// failing test.
    public static var unmappedTableReads: [Operation] {
        Operation.allCases.filter { operation in
            !operation.isResourceOperation
                && operation.taxonomy.kind == .read
                && kind(of: operation) != nil
                && tableFields[operation] == nil
        }.sorted { $0.rawValue < $1.rawValue }
    }

    /// BL-116 wave 5. Every table-driven read whose projection builds at least
    /// one **per-row column** beside the id, derived from the same rows the
    /// inventory reads rather than from a list.
    ///
    /// `ProviderRowPairingContracts` keeps one replay probe per column-bearing
    /// read — the PW4-M3 property, stated over every provider that has a column
    /// to get wrong — and until this existed that list was hand-maintained, the
    /// same "a count is updated by the same hand" weakness PW-M2's registry fix
    /// names one level up. The suite now asserts its probes cover exactly this
    /// set, so a provider that adds a column without adding a probe fails
    /// rather than passing quietly.
    public static var columnBearingReads: [Operation] {
        tableFields
            .filter { !$0.value.attributes.isEmpty }
            .keys
            .sorted { $0.rawValue < $1.rawValue }
    }

    /// Every operation the inventory knows how to read today. The Services
    /// screen uses it to say what a refresh would actually fetch.
    public static func supportedOperations(for provider: Provider) -> [Operation] {
        Operation.allCases.filter { operation in
            operation.provider == provider
                && operation.taxonomy.kind == .read
                && kind(of: operation) != nil
                && (operation.isResourceOperation || tableFields[operation] != nil)
        }.sorted { $0.rawValue < $1.rawValue }
    }

    /// The parent a bound scope gives every row a scoped read returns.
    public static func parent(of scope: ProviderResourceScope) -> ResourceParent? {
        switch scope.kind {
        case .cloudflareZone:
            scope.zoneID.map { ResourceParent(kind: .zone, id: $0, label: scope.label) }
        case .cloudflareAccount:
            scope.accountID.map { ResourceParent(kind: .account, id: $0, label: scope.label) }
        case .cloudflareWorkerScript:
            scope.scriptName.map { ResourceParent(kind: .workerScript, id: $0, label: scope.label) }
        case .vercelProject:
            scope.projectID.map { ResourceParent(kind: .project, id: $0, label: scope.label) }
        case .vercelAccount:
            nil
        case .githubRepository:
            scope.repository.map { ResourceParent(kind: .repository, id: $0, label: scope.label) }
        }
    }

    /// The records a table-driven read contributes, and the provider's own total
    /// where the projection reported one.
    public static func records(
        fromTableRead operation: Operation,
        fields: [String: String],
        connectionID: UUID,
        at instant: Date
    ) -> (records: [ResourceRecord], reportedCount: Int?) {
        guard let kind = kind(of: operation), let spec = tableFields[operation] else { return ([], nil) }
        let identifiers = members(fields[spec.identifiers])
        let names = spec.names.map { members(fields[$0]) } ?? []
        // PW-H1. This used to pair the two columns whenever their lengths
        // matched, with a comment claiming that stopped one resource's name
        // reaching another resource's row. It did not: two shape failures in
        // *different* columns restore equality while destroying the
        // correspondence, which is what the pass reproduced end to end.
        //
        // Correspondence is now established where the columns are built — the
        // adapter's `ValueFree.list` drops a member whole when its id fails and
        // holds its place in the name column when only the name does — so equal
        // length here is a *consequence* of pairing rather than evidence of it.
        // A mismatch is therefore no longer a shortened list to pair around: it
        // is a projection that did not come from that seam, and the honest
        // answer is to contribute no rows at all rather than rows that may be
        // mislabelled.
        let pairedNames: [String]
        if names.isEmpty {
            pairedNames = []
        } else if names.count == identifiers.count {
            pairedNames = names
        } else {
            return ([], fields["count"].flatMap(Int.init))
        }
        var pairedAttributes: [String: [String]] = [:]
        for (field, attribute) in spec.attributes {
            let values = members(fields[field])
            guard values.count == identifiers.count else { continue }
            pairedAttributes[attribute] = values
        }
        let staleAfter = instant.addingTimeInterval(ResourceInventory.freshness)
        var records: [ResourceRecord] = []
        for (index, identifier) in identifiers.enumerated() {
            var attributes: [String: String] = [:]
            for (attribute, values) in pairedAttributes { attributes[attribute] = values[index] }
            guard let record = ResourceRecord.make(
                connectionID: connectionID,
                provider: operation.provider,
                kind: kind,
                name: pairedNames.isEmpty ? nil : pairedNames[index],
                providerResourceID: identifier,
                attributes: attributes,
                fetchedAt: instant,
                staleAfter: staleAfter
            ) else { continue }
            records.append(record)
        }
        return (records, fields["count"].flatMap(Int.init))
    }

    /// The records a bound resource read contributes. These arrive already
    /// structured — `ResourceOperationResult.items` is BL-091's fixed shape —
    /// so nothing is parsed out of a joined string here.
    public static func records(
        fromResourceRead operation: Operation,
        result: ResourceOperationResult,
        scope: ProviderResourceScope,
        connectionID: UUID,
        at instant: Date
    ) -> (records: [ResourceRecord], reportedCount: Int?) {
        guard let kind = kind(of: operation) else { return ([], nil) }
        let container = parent(of: scope)
        let staleAfter = instant.addingTimeInterval(ResourceInventory.freshness)
        let records = result.items.compactMap { item in
            ResourceRecord.make(
                connectionID: connectionID,
                provider: operation.provider,
                kind: kind,
                name: item.label,
                providerResourceID: item.id,
                parent: container,
                region: nil,
                attributes: item.attributes,
                fetchedAt: instant,
                staleAfter: staleAfter
            )
        }
        return (records, result.count)
    }

    /// Splits one of BL-088's joined member lists. Empty members are dropped
    /// rather than becoming a row with no identifier.
    private static func members(_ joined: String?) -> [String] {
        guard let joined, !joined.isEmpty else { return [] }
        return joined.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

// MARK: - What a refresh reports

/// The outcome of one on-demand refresh, as the desktop shows it and the
/// receipt records it.
public struct InventoryRefreshReport: Codable, Hashable, Sendable {
    public let connectionID: UUID
    public let provider: String
    public let connectionLabel: String
    public let startedAt: Date
    public let finishedAt: Date
    public let operations: [InventoryOperationOutcome]
    /// How many records the inventory holds for this connection afterwards.
    public let recordCount: Int
    public let summary: String

    public init(connectionID: UUID, provider: String, connectionLabel: String, startedAt: Date, finishedAt: Date, operations: [InventoryOperationOutcome], recordCount: Int, summary: String) {
        self.connectionID = connectionID
        self.provider = provider
        self.connectionLabel = connectionLabel
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.operations = operations
        self.recordCount = recordCount
        self.summary = summary
    }

    public var failures: [InventoryOperationOutcome] { operations.filter { $0.failure != nil } }
    /// True when every read failed. The caller has an inventory that is no worse
    /// than before — error isolation keeps the previous rows — but nothing was
    /// learned, and saying so is the honest report.
    public var isTotalFailure: Bool { !operations.isEmpty && failures.count == operations.count }
}
