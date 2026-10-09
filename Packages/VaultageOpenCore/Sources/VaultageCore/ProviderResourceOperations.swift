import Foundation

// BL-091 / owner decision D34 — the operation taxonomy.
//
// D34 makes the *provider resource* the unit of value: a builder wants to
// create a DNS record, add a domain or set an environment variable from the
// IDE they are already in. That means Vaultage stops having "one read
// operation per provider" and starts having a matrix, and a matrix needs a
// classification before it needs adapters — otherwise "is this one safe to
// auto-allow?" becomes a judgement made once per operation by whoever writes
// it.
//
// So this file is the classification, and nothing else. It contains no route,
// no URL, no body and no credential. Every operation in `Operation` carries
// exactly five facts:
//
//   * **kind** — read, create, update or delete;
//   * **resource kind** — what provider-side thing it acts on;
//   * **trust class** — ordinary, billing, production-affecting or admin,
//     the same four classes `design/provider-flow-system.md` already renders
//     as chips (`CatalogTrustClass` mirrors these raw values and a self-test
//     pins the two enums together);
//   * **idempotency** — whether repeating it is free, needs a key, or makes a
//     second object;
//   * **mints a credential** — whether running it brings a *new secret* into
//     existence, which routes it to BL-074's native-approval-only class and
//     off the agent surface entirely.
//
// `ApprovalRequirement.of(_:)` turns those five facts into one answer: which
// approval class this operation runs under. That function is the whole of the
// BL-091 approval mapping, it is pure, and `ProviderResourceOperationContracts`
// asserts it table-driven for every case of `Operation` — so an operation added
// later is classified by construction and fails the suite if its classification
// contradicts its own taxonomy.

// MARK: - The five facts

/// What an operation does to provider state.
public enum OperationKind: String, Codable, Sendable, CaseIterable {
    case read, create, update, delete
    /// BL-094 / owner decision D36. **Delivery**: a value that lives in this
    /// Mac's Keychain is written into a provider's own secret store, so the
    /// deployed environment holds its own copy and keeps running with the app
    /// quit and the laptop shut.
    ///
    /// It is its own kind rather than a create or an update because the thing
    /// that makes it dangerous is not the HTTP verb. A delivery is the only
    /// agent-reachable class whose request body contains a credential, its
    /// destination is a production runtime rather than a record, and the
    /// question the human is answering is "should this secret live there?" —
    /// not "should this object change?". Classing it separately is what lets
    /// `ApprovalRequirement.of` give the same answer for every store without
    /// each provider's adapter having to remember to say `productionAffecting`.
    ///
    /// The provider verb is still whatever the provider documents — Cloudflare
    /// PUTs a Worker secret by name, Vercel POSTs a new variable and PATCHes an
    /// existing one — so `namesExistingResource` carries that fact instead of
    /// being read off the kind.
    case deliver

    /// Reads and creates name no pre-existing object; updates and deletes do,
    /// and the approval sheet must show that object's exact id (BL-091). A
    /// delivery answers this from its own taxonomy fact, because both shapes
    /// exist on the same store.
    public var namesAnExistingResource: Bool { self == .update || self == .delete }
}

/// The provider-side thing an operation acts on. Deliberately coarse: it is
/// what the approval sheet's first line says ("DNS record", "Environment
/// variable"), and what a D19 grant is scoped to alongside the operation.
public enum ResourceKind: String, Codable, Sendable, CaseIterable {
    /// The account or principal behind the credential — what a verify or a
    /// rate-limit read reports.
    case account
    case dnsRecord = "dns_record"
    case workerScript = "worker_script"
    case workerSecret = "worker_secret"
    case deploymentProject = "deployment_project"
    /// A provider project grouping environments, distinct from a deployed
    /// service/workload. Separate inventory kinds isolate failed reads.
    case environmentProject = "environment_project"
    case environmentVariable = "environment_variable"
    case domain
    case model
    case site
    case database
    case organization
    case balance
    /// BL-112 wave 4. A billing catalogue entity — the thing an account sells,
    /// which its prices, discounts and transactions all hang off. Paddle's
    /// product list is the first read of one. No existing kind described it,
    /// and D34's copy rule leads with the resource, so calling it an account or
    /// a project would have put the wrong noun at the front of every approval
    /// sheet.
    case product
    /// BL-116 wave 5. A table of rows in a builder's own data store — Glide's
    /// Big Tables are the first read of one. `database` was the nearest
    /// existing kind and it is the wrong noun: D34's copy rule leads with the
    /// resource, so a bind sheet would have opened "A Database Invoices" for
    /// something the builder calls a table. The same reason wave 4 added
    /// `product` rather than reusing `account`.
    case table
    /// BL-128. A source-control repository — GitHub's repository list is the
    /// first read of one. `deploymentProject` was the nearest existing kind
    /// and it is the wrong noun for the same reason waves 4 and 5 added
    /// `product` and `table`: D34's copy rule leads with the resource, and a
    /// developer calls this a repository.
    case repository
    /// BL-128 slice 3b. A GitHub Actions secret — the CI credential a workflow
    /// reads. Its own noun rather than `workerSecret` or
    /// `environmentVariable`, because D34's copy rule leads the sheet with the
    /// resource and a developer calls this an Actions secret.
    case actionsSecret = "actions_secret"
    /// BL-074's class: an API token or key. Nothing with this resource kind is
    /// ever an `Operation`; it is here so the taxonomy can name the class.
    case apiToken = "api_token"

    /// The words the approval sheet leads with (D34 copy rule: resource, then
    /// action, then safety).
    public var label: String {
        switch self {
        case .account: "Account"
        case .dnsRecord: "DNS record"
        case .workerScript: "Worker script"
        case .workerSecret: "Worker secret"
        case .deploymentProject, .environmentProject: "Project"
        case .environmentVariable: "Environment variable"
        case .domain: "Domain"
        case .model: "Model"
        case .site: "Site"
        case .database: "Database"
        case .organization: "Organization"
        case .balance: "Balance"
        case .product: "Product"
        case .table: "Table"
        case .repository: "Repository"
        case .actionsSecret: "Actions secret"
        case .apiToken: "API token"
        }
    }
}

/// The four trust classes of `design/provider-flow-system.md`. The raw values
/// are byte-identical to `VaultageProviders.CatalogTrustClass`, and a self-test
/// asserts that, so the chip on the card, the row in the Operations tab and the
/// class the broker enforces cannot drift apart.
public enum OperationTrustClass: String, Codable, Sendable, CaseIterable {
    case ordinary
    case billing
    case productionAffecting = "production-affecting"
    case admin

    public var label: String {
        switch self {
        case .ordinary: "Ordinary"
        case .billing: "Billing data"
        case .productionAffecting: "Production-affecting"
        case .admin: "Admin"
        }
    }
}

/// What happens if the same request runs twice.
public enum IdempotencyClass: String, Codable, Sendable, CaseIterable {
    /// Repeating it reaches the same state: a read, a full-record overwrite, a
    /// delete of an id that is already gone.
    case idempotent
    /// Repeating it would make a second object, so it carries a key and
    /// Vaultage refuses a second dispatch under that key.
    ///
    /// For the providers in this slice the key is **Vaultage's, not the
    /// provider's**: neither Cloudflare's DNS create nor Vercel's project,
    /// env-var or domain creates document an idempotency header. The ledger in
    /// `ResourceMutationKey` is therefore local replay protection, and the
    /// disclosure says so rather than implying the provider will de-duplicate.
    /// Stripe, which does document `Idempotency-Key`, is a later wave.
    case idempotencyKey = "idempotency-key"
    /// Repeating it has a further effect that no key can undo — a send, a
    /// deploy, a new Worker version.
    case notIdempotent = "not-idempotent"
}

/// The five facts, as one value.
public struct OperationTaxonomy: Sendable, Hashable, Codable {
    public let kind: OperationKind
    public let resource: ResourceKind
    public let trust: OperationTrustClass
    public let idempotency: IdempotencyClass
    /// True when running this brings a new secret into existence. Nothing in
    /// `Operation` sets it — BL-074's `ProviderResourceOperation` is a separate
    /// enum for exactly this reason — but the taxonomy names the class so the
    /// mapping below is complete rather than silently missing a branch.
    public let mintsCredential: Bool
    /// True when the provider's own response on this route carries credential
    /// *values*, so the projection has to drop fields rather than merely bound
    /// them. Vercel's environment-variable list is the wave-1 example
    /// (`providers-wave1-2026-09-11.md` §3): `value` is present on a plain
    /// variable and `?decrypt=true` returns it for an encrypted one.
    public let providerReturnsValues: Bool
    /// Whether the provider route names a pre-existing object. Derived from the
    /// kind for everything except a `deliver`, where both shapes exist on one
    /// store: Cloudflare's Worker secret PUT is keyed by *name* and names no
    /// id, Vercel's variable PATCH names the variable's exact id.
    public let namesExistingResource: Bool

    public init(
        kind: OperationKind,
        resource: ResourceKind,
        trust: OperationTrustClass,
        idempotency: IdempotencyClass,
        mintsCredential: Bool = false,
        providerReturnsValues: Bool = false,
        namesExistingResource: Bool? = nil
    ) {
        self.kind = kind
        self.resource = resource
        self.trust = trust
        self.idempotency = idempotency
        self.mintsCredential = mintsCredential
        self.providerReturnsValues = providerReturnsValues
        self.namesExistingResource = namesExistingResource ?? kind.namesAnExistingResource
    }

    /// An update or a delete must name the exact provider id on the sheet and
    /// in the request; a create has nothing to name yet. A delivery answers
    /// from its own fact.
    public var requiresExactResourceID: Bool { namesExistingResource }

    /// Only a delete is two-step. The first call returns a preview of what
    /// would be removed; the second repeats the same id with the confirmation
    /// flag. See `ResourceDeletePreview`.
    public var isTwoStepDelete: Bool { kind == .delete }

    /// BL-094. True when this operation writes a vault value into a provider's
    /// own secret store.
    public var isDelivery: Bool { kind == .deliver }

    /// BL-095 / owner decision D38. Whether this operation's approval may be
    /// mirrored to an enrolled phone and signed there.
    ///
    /// D38 allows production-covering *grants* from the phone behind extra
    /// confirmation, and keeps "runtime injection and credential-minting
    /// operations" native-only. A delivery is runtime injection into a cloud
    /// runtime — it is the one agent-reachable class whose request body carries
    /// a credential — so it is decided on the Mac that holds custody, and
    /// nowhere else. Stated here, on the taxonomy, so the remote-approval
    /// protocol reads the answer off the operation instead of keeping a second
    /// list that could drift.
    public var isRemotelyApprovable: Bool { !mintsCredential && !isDelivery }
}

// MARK: - The approval mapping

/// Which approval class an operation runs under. This is BL-091's mapping,
/// stated once.
public enum ApprovalRequirement: String, Codable, Sendable, CaseIterable {
    /// Reads: the binding decides what is permitted and a D19 grant may cover
    /// it, exactly as every build before this ticket. Unchanged.
    case bindingsAndGrants = "bindings-and-grants"
    /// Create and update under ordinary trust: a D19 grant may cover it, but
    /// only a grant that names **this operation** — which, because an operation
    /// determines its own resource kind, is also a grant scoped to that
    /// resource kind. A grant that covers a binding's reads does not
    /// accidentally acquire its mutations; see `GrantRequest.includedMutations`.
    case grantScopedToOperation = "grant-scoped-to-operation"
    /// Delete, anything production-affecting, and any billing mutation: the
    /// native sheet every time, naming the exact resource id where one exists.
    /// No grant may ever cover it.
    case nativeSheetEveryTime = "native-sheet-every-time"
    /// Admin: the native sheet, never auto-allowed, and never default-enabled
    /// on a connect panel toggle.
    case neverAutoAllowed = "never-auto-allowed"
    /// BL-074: it mints a credential, so it is not an agent operation at all.
    /// It is absent from `vaultage_execute`, cannot be stored in a binding's
    /// allowed set, and its only entry is a desktop approval.
    case nativeApprovalOnly = "native-approval-only"

    /// The one question the broker asks: may a grant ever stand in for the
    /// sheet here?
    public var mayBeCoveredByGrant: Bool {
        self == .bindingsAndGrants || self == .grantScopedToOperation
    }

    /// Whether a grant has to *name* the operation rather than inheriting it
    /// from the binding.
    public var requiresExplicitGrantInclusion: Bool { self == .grantScopedToOperation }

    /// The mapping. Ordered so that the strictest fact wins, and written as a
    /// single chain rather than a matrix so there is exactly one answer per
    /// operation and no precedence to argue about.
    public static func of(_ taxonomy: OperationTaxonomy) -> ApprovalRequirement {
        // 1. Minting a credential outranks everything: BL-074's class is not on
        //    the agent surface at all, whatever its other facts say.
        if taxonomy.mintsCredential { return .nativeApprovalOnly }
        // 2. Admin is never auto-allowed, whatever the verb.
        if taxonomy.trust == .admin { return .neverAutoAllowed }
        // 3. BL-094 / D36. A delivery writes a credential into a provider's
        //    secret store, so it takes the native sheet every time and the
        //    sheet names the exact destination. No grant may ever cover it and
        //    it is never mirrored to a phone (`isRemotelyApprovable`).
        //
        //    This branch changes no existing answer: every delivery is also
        //    production-affecting, so rule 5 would already have returned the
        //    same class. It is here so the class is *decided by what the
        //    operation is* rather than by a trust label an adapter has to
        //    remember to set, and `deliveryClassIsOverDetermined` in the
        //    BL-094 suite asserts the two agree for every compiled delivery.
        if taxonomy.isDelivery { return .nativeSheetEveryTime }
        // 4. A delete always takes the sheet, with the exact id, every time —
        //    including an ordinary-trust delete. Deletes are the one verb where
        //    a mistake cannot be walked back by repeating the opposite verb.
        if taxonomy.kind == .delete { return .nativeSheetEveryTime }
        // 5. Production-affecting never auto-allows.
        if taxonomy.trust == .productionAffecting { return .nativeSheetEveryTime }
        // 6. Reads follow bindings and grants as today — including the billing
        //    reads BL-088 already shipped, whose behaviour this ticket does not
        //    change.
        if taxonomy.kind == .read { return .bindingsAndGrants }
        // 7. A billing *mutation* takes the sheet. None exists yet; the branch
        //    is here so that adding one cannot land in the ordinary case.
        if taxonomy.trust == .billing { return .nativeSheetEveryTime }
        // 8. What is left is an ordinary create or update: grant-coverable, but
        //    only by a grant that named it.
        return .grantScopedToOperation
    }

    public static func of(_ operation: Operation) -> ApprovalRequirement {
        of(operation.taxonomy)
    }
}

// MARK: - The table

public extension Operation {
    /// The classification for every compiled operation.
    ///
    /// A `switch` with no `default`, so adding an `Operation` case is a compile
    /// error here until it has been classified. That is the point: an
    /// unclassified operation must not be able to reach the broker and pick up
    /// whatever the fallback happened to be.
    var taxonomy: OperationTaxonomy {
        switch self {
        // MARK: reads that shipped before BL-091
        case .githubRateLimit:
            OperationTaxonomy(kind: .read, resource: .account, trust: .ordinary, idempotency: .idempotent)
        case .githubListRepositories:
            // BL-128. The repositories the token can see: full names, their
            // documented visibility and whether they are archived. Nothing is
            // created, changed or revealed.
            OperationTaxonomy(kind: .read, resource: .repository, trust: .ordinary, idempotency: .idempotent)
        case .githubActionsSecretNameList:
            // BL-128 slice 3b. Names and dates only: GitHub documents that a
            // secret's value is never returned by any read, so
            // `providerReturnsValues` stays false — the Cloudflare secret-name
            // list's shape, not Vercel's.
            OperationTaxonomy(kind: .read, resource: .actionsSecret, trust: .ordinary, idempotency: .idempotent)
        case .githubActionsSecretPut:
            // BL-128 slice 3c (D65). A delivery, in the class BL-094 names:
            // a vault value written into a provider's secret store. GitHub's
            // route is one PUT that creates or replaces by name, so it names
            // no provider id — Cloudflare's Worker secret shape, not Vercel's
            // two routes. Production-affecting for Vercel's reason: the
            // workflows that read it deploy things, and replacing it changes
            // what the next run deploys with. Idempotent: repeating the PUT
            // leaves the same value under the same name.
            OperationTaxonomy(kind: .deliver, resource: .actionsSecret, trust: .productionAffecting, idempotency: .idempotent, namesExistingResource: false)
        case .openAIListModels:
            OperationTaxonomy(kind: .read, resource: .model, trust: .ordinary, idempotency: .idempotent)
        case .cloudflareVerifyToken:
            OperationTaxonomy(kind: .read, resource: .account, trust: .ordinary, idempotency: .idempotent)
        case .anthropicListModels, .geminiListModels:
            OperationTaxonomy(kind: .read, resource: .model, trust: .ordinary, idempotency: .idempotent)
        case .vercelListProjects:
            OperationTaxonomy(kind: .read, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotent)
        case .netlifyListSites:
            OperationTaxonomy(kind: .read, resource: .site, trust: .ordinary, idempotency: .idempotent)
        case .supabaseListProjects, .neonListProjects:
            OperationTaxonomy(kind: .read, resource: .database, trust: .ordinary, idempotency: .idempotent)
        case .resendListDomains:
            OperationTaxonomy(kind: .read, resource: .domain, trust: .ordinary, idempotency: .idempotent)
        case .stripeRetrieveBalance:
            // BL-088 classified this Billing, and that is preserved exactly: a
            // billing *read* still follows bindings and grants, so no behaviour
            // changes for the operation that shipped.
            OperationTaxonomy(kind: .read, resource: .balance, trust: .billing, idempotency: .idempotent)
        case .sentryListOrganizations:
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)

        // MARK: BL-089 wave 2 — reads only, exactly as wave 1
        //
        // Every one of these is a `GET` (Railway's two are a compiled
        // read-only GraphQL `query`), every one is idempotent, and every one
        // is ordinary: none reads a balance, a message, an event or a secret.
        // Where a provider's own resource has no closer kind, the read is
        // classified by what the reply actually describes rather than by the
        // provider's marketing noun.
        case .railwayListProjects, .renderListServices, .digitalOceanListProjects:
            OperationTaxonomy(kind: .read, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotent)
        case .renderListProjects:
            OperationTaxonomy(kind: .read, resource: .environmentProject, trust: .ordinary, idempotency: .idempotent)
        case .clerkListDomains, .mailgunListDomains:
            OperationTaxonomy(kind: .read, resource: .domain, trust: .ordinary, idempotency: .idempotent)
        case .posthogListOrganizations, .twilioListAccounts:
            // Twilio's reply is a list of accounts and subaccounts, which is
            // an organization boundary in everything but the provider's name
            // for it.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .slackTeamInfo, .discordListGuilds, .postmarkGetServer, .sendGridListScopes:
            // The workspace, the servers the bot is in, the Postmark server
            // and the scopes a SendGrid key carries are all facts about the
            // account behind the credential, not about a resource it holds.
            OperationTaxonomy(kind: .read, resource: .account, trust: .ordinary, idempotency: .idempotent)
        case .xaiListModels, .mistralListModels, .deepSeekListModels, .cohereListModels:
            OperationTaxonomy(kind: .read, resource: .model, trust: .ordinary, idempotency: .idempotent)

        // MARK: BL-111 wave 3 — reads only, exactly as waves 1 and 2
        case .apifyListActors:
            // An Apify Actor is a deployable program with its own versions,
            // builds, runs and environment variables — `deploymentProject` is
            // what the reply actually describes, in the same way Railway's and
            // Render's are, and there is no closer kind. Ordinary: the list
            // reports ids, names and owners and touches nothing.
            OperationTaxonomy(kind: .read, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotent)
        // MARK: BL-112's wave-5 follow-up — reads only, exactly as waves 1 to 4
        case .bitbucketListWorkspaces:
            // A Bitbucket workspace is "where you create repositories,
            // collaborate on your code, and organize different streams of
            // work" — the boundary every repository, project and pipeline
            // hangs off, and an organization in everything but the provider's
            // word for it. The same reading wave 3 gave GitLab's groups and
            // wave 4 gave Segment's workspace. Ordinary: the list reports
            // workspace slugs and touches nothing.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .lemonSqueezyListStores:
            // "Everything in Lemon Squeezy belongs to a store. Each store is
            // billed separately." A boundary that owns the products, orders,
            // subscriptions and licence keys *and* is the unit of billing is an
            // organization, not a product and not an account. Ordinary rather
            // than billing: this reads ids and names, and no order, customer,
            // subscription, licence key, revenue figure or sales count — which
            // the store object carries and this projection never touches.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .planetScaleListOrganizations:
            // A PlanetScale organization owns the databases, branches, teams
            // and billing a builder binds a project to. `organization` is the
            // provider's own word. Ordinary: the list reports ids and names and
            // touches no database, branch, backup, password or invoice.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        // MARK: BL-116 wave 5 (D50) — reads only, exactly as waves 1 to 5
        case .glideListTables:
            // A Glide Big Table is a table, and no existing kind said so:
            // `database` is a category above it and `deploymentProject` is a
            // different thing entirely. `table` is the wave-5 addition, made
            // for the reason wave 4 added `product` — D34's copy rule leads
            // with the resource, and the wrong noun would open every bind
            // sheet. Ordinary: the list reports table ids and names and reads
            // no row, no column and no cell.
            OperationTaxonomy(kind: .read, resource: .table, trust: .ordinary, idempotency: .idempotent)
        case .hostingerHorizonsListWebsites:
            // A Horizons website is a published site with a domain, which is
            // exactly what `site` names for Netlify. Ordinary: the list reports
            // ids, statuses and domains and touches no content.
            OperationTaxonomy(kind: .read, resource: .site, trust: .ordinary, idempotency: .idempotent)
        case .v0ListScopes:
            // v0's word for "a personal workspace or a shared team" is scope,
            // and that is an organization boundary in everything but the
            // provider's name for it — the same reading wave 3 gave GitLab's
            // groups and wave 4 gave Segment's workspace. Ordinary: the list
            // reports ids and names and creates nothing.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .dopplerListProjects:
            // A Doppler project owns the configs and, beneath them, the
            // secrets. `organization` is wrong — a Doppler *workplace* is the
            // organization and a project sits inside it — and `table` is
            // wrong. `deploymentProject` is the kind whose label is the
            // provider's own word, "Project", which is what the bind sheet
            // shows and what a Doppler user calls this; the case name is a
            // legacy of the Vercel and Railway reads it was written for, and
            // nothing here deploys. Ordinary, and value-free by construction:
            // the list reports project ids, names and slugs, and the route
            // that returns a secret value has no compiled representation in
            // this family at all (D50's exception to D32).
            OperationTaxonomy(kind: .read, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotent)
        case .awsGetCallerIdentity:
            // BL-117 (D51). STS `GetCallerIdentity` returns the account id, the
            // ARN and the user id of the identity the signature was computed
            // with — the account behind the credential, which is what
            // `.account` names and what `githubRateLimit` and
            // `cloudflareVerifyToken` already use. Ordinary and idempotent: AWS
            // documents it as requiring no permission at all — "No permissions
            // are required to perform this operation" — and it creates,
            // changes and reveals nothing. It is **not** in BL-074's creation
            // class: nothing is minted, and §2.2a's test is whether a new
            // secret comes into existence that can be used elsewhere.
            OperationTaxonomy(kind: .read, resource: .account, trust: .ordinary, idempotency: .idempotent)
        case .azureGetOrganization:
            // BL-117's Azure slot (D51). Microsoft Graph's `/organization`
            // returns the one organization object of the tenant the token was
            // minted for — its id, its display name and its verified domains.
            // `organization` is the provider's own word and the one wave 3 gave
            // GitLab's groups and wave 4 gave Segment's workspace. Ordinary and
            // idempotent: the read creates, changes and reveals nothing.
            //
            // **The exchange inside it is not a creation.** §2.2a's test is
            // whether a new secret comes into existence that *can be used
            // elsewhere*, and a token Rule C's cache will only ever hand back to
            // the action whose id keys it cannot be. Putting it in BL-074's
            // class would raise a native-only sheet in front of every ordinary
            // Azure read, which is a sheet an owner cannot act on and would
            // learn to click through.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .googleCloudListProjects:
            // BL-117's Google Cloud slot (D51). Cloud Resource Manager's
            // `projects.list` returns the ids and display names of the projects
            // one service account can see.
            //
            // `deploymentProject` for the reason Doppler's read gives one case
            // above: its **label** is the provider's own word, "Project", which
            // is what the bind sheet shows and what a Google Cloud user calls
            // this; the case name is a legacy of the Vercel and Railway reads it
            // was written for, and nothing here deploys. `organization` is wrong
            // — a Google Cloud *organization* is the node above a project — and
            // `account` is wrong, because the service account is the principal
            // rather than the resource. Ordinary and idempotent: the read
            // creates, changes and reveals nothing.
            //
            // **The exchange inside it is not a creation**, on §2.2a's own test
            // and for the reason the Azure read states: a token Rule C's cache
            // will only ever hand back to the action whose id keys it cannot be
            // used elsewhere. The RS256 **assertion** is not one either — it is
            // derived rather than minted, it authenticates one exchange, and it
            // never leaves the broker except as the body of that one request.
            OperationTaxonomy(kind: .read, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotent)
        case .workosListOrganizations:
            // A WorkOS organization is a tenant of the account behind the key —
            // the customer's own customers — and it is the scope every WorkOS
            // connection, directory and SSO record hangs off. `organization` is
            // the provider's own word and the right one. Ordinary: the list
            // reports ids and names and touches nothing.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .segmentGetWorkspace:
            // A Segment workspace owns the sources, destinations, functions and
            // people a builder binds a project to — an organization boundary
            // the provider happens to call a workspace, the same reading wave 2
            // gave Twilio's account list and wave 3 gave GitLab's groups.
            // Ordinary: it reports one id, one name and one slug.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .paddleListProducts:
            // The catalogue an account sells, read as ids, names and the
            // documented status. Ordinary rather than billing: this reads no
            // price, no transaction, no customer and no balance — Paddle keeps
            // those behind their own `.read` permissions, and this connection
            // asks for none of them.
            OperationTaxonomy(kind: .read, resource: .product, trust: .ordinary, idempotency: .idempotent)
        case .makeListOrganizations:
            // BL-112 wave 4. A Make organization owns the teams, the scenarios
            // and the connections a builder binds a project to — an
            // organization boundary the provider calls by its own name, so
            // there is nothing to reinterpret. Ordinary: the list reports ids,
            // names and the paused flag and touches nothing.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)
        case .gitlabListGroups:
            // A GitLab group is a namespace that owns projects, members and
            // CI/CD variables — an organization boundary in everything but
            // GitLab's name for it, the same reading wave 2 gave Twilio's
            // account list. Ordinary: the list reports paths, names and
            // visibility and touches nothing.
            OperationTaxonomy(kind: .read, resource: .organization, trust: .ordinary, idempotency: .idempotent)

        // MARK: BL-051's Worker secret write, now inside the taxonomy
        case .cloudflareWorkerSecretPut:
            // BL-094 moved this from `update` to `deliver`: it was always the
            // shape the delivery class is named after — a vault value written
            // into a provider's secret store — and BL-051 hand-wrote the rules
            // the class now derives. Its approval class is unchanged.
            //
            // Production-affecting because Cloudflare's ordinary secret update
            // creates a Worker version and deploys it immediately (BL-051,
            // engineering contracts §4). Not idempotent for the same reason: a
            // second identical PUT is a second deployed version. It names no
            // provider id: the route is keyed by the Worker script and the
            // secret's name.
            OperationTaxonomy(kind: .deliver, resource: .workerSecret, trust: .productionAffecting, idempotency: .notIdempotent, namesExistingResource: false)

        // MARK: BL-091 slice 1 — Cloudflare
        case .cloudflareDNSRecordList:
            OperationTaxonomy(kind: .read, resource: .dnsRecord, trust: .ordinary, idempotency: .idempotent)
        case .cloudflareDNSRecordCreate:
            // Production-affecting (audit H-10). DNS allows several A, AAAA or
            // CNAME-class records at one name, so a "new" record at a name that
            // already resolves changes or load-balances live traffic; a
            // uniqueness preflight would be racy and would not make it safe.
            // Classified by effect, not by the verb. Keyed, because a repeated
            // POST makes a second record at the same name.
            OperationTaxonomy(kind: .create, resource: .dnsRecord, trust: .productionAffecting, idempotency: .idempotencyKey)
        case .cloudflareDNSRecordUpdate:
            // Production-affecting: changing an existing record repoints live
            // traffic. Idempotent because the route is a full-record PUT.
            OperationTaxonomy(kind: .update, resource: .dnsRecord, trust: .productionAffecting, idempotency: .idempotent)
        case .cloudflareDNSRecordDelete:
            OperationTaxonomy(kind: .delete, resource: .dnsRecord, trust: .productionAffecting, idempotency: .idempotent)
        case .cloudflareWorkerScriptList:
            OperationTaxonomy(kind: .read, resource: .workerScript, trust: .ordinary, idempotency: .idempotent)
        case .cloudflareWorkerSecretNameList:
            // Names only. Cloudflare's secret list is genuinely a metadata
            // route — it returns `name` and `type` and no value — which is why
            // `providerReturnsValues` is false here and true for Vercel.
            OperationTaxonomy(kind: .read, resource: .workerSecret, trust: .ordinary, idempotency: .idempotent)

        // MARK: BL-091 slice 1 — Vercel
        case .vercelProjectCreate:
            // Ordinary: an empty project serves nothing until something is
            // deployed to it. The recorded matrix classes the whole Projects
            // row production-affecting because *delete* takes the deployments
            // with it; this slice implements create only, and says so.
            OperationTaxonomy(kind: .create, resource: .deploymentProject, trust: .ordinary, idempotency: .idempotencyKey)
        case .vercelEnvList:
            // Production-affecting is not the right class for a read, but the
            // value flag is the load-bearing fact: Vercel returns `value` on a
            // plain variable and documents a route that decrypts one. The
            // projection drops every value-bearing field inside the transport
            // seam; see `VercelMutations`.
            OperationTaxonomy(kind: .read, resource: .environmentVariable, trust: .ordinary, idempotency: .idempotent, providerReturnsValues: true)
        case .vercelEnvCreate:
            // BL-094: `deliver`, not `create`. The POST route makes a new
            // variable and the PATCH route replaces an existing one, but both
            // put a vault value into Vercel's store, which is the fact that
            // decides the approval class. `namesExistingResource` keeps the
            // provider-shaped half of the distinction: POST names no id, PATCH
            // names the variable's exact id.
            //
            // One target per approved call, deliberately. Vercel's `target` is
            // an array, so production + preview + development is three
            // approvals — see `DeliveryDestination.oneTargetPerApproval`.
            OperationTaxonomy(kind: .deliver, resource: .environmentVariable, trust: .productionAffecting, idempotency: .idempotencyKey, providerReturnsValues: true, namesExistingResource: false)
        case .vercelEnvUpdate:
            OperationTaxonomy(kind: .deliver, resource: .environmentVariable, trust: .productionAffecting, idempotency: .idempotent, providerReturnsValues: true, namesExistingResource: true)
        case .vercelEnvDelete:
            OperationTaxonomy(kind: .delete, resource: .environmentVariable, trust: .productionAffecting, idempotency: .idempotent, providerReturnsValues: true)
        case .vercelDomainList:
            OperationTaxonomy(kind: .read, resource: .domain, trust: .ordinary, idempotency: .idempotent)
        case .vercelDomainAdd:
            // Production-affecting (audit H-10): a domain attached to a project
            // routes its current production deployment once verified, so the
            // attachment is the traffic change, whatever its DNS says today.
            OperationTaxonomy(kind: .create, resource: .domain, trust: .productionAffecting, idempotency: .idempotencyKey)
        case .vercelDomainRemove:
            // Removing a project domain takes live traffic with it.
            OperationTaxonomy(kind: .delete, resource: .domain, trust: .productionAffecting, idempotency: .idempotent)
        }
    }

    /// Which approval class this operation runs under.
    var approvalRequirement: ApprovalRequirement { ApprovalRequirement.of(taxonomy) }

    /// True for everything BL-091 routes through the resource path: the
    /// mutations, and the two kinds of read that need a bound resource
    /// identifier in the URL and therefore cannot live in `ProviderRouteTable`.
    var isResourceOperation: Bool {
        switch self {
        case .cloudflareDNSRecordList, .cloudflareDNSRecordCreate, .cloudflareDNSRecordUpdate,
             .cloudflareDNSRecordDelete, .cloudflareWorkerScriptList, .cloudflareWorkerSecretNameList,
             .vercelProjectCreate, .vercelEnvList, .vercelEnvCreate, .vercelEnvUpdate,
             .vercelEnvDelete, .vercelDomainList, .vercelDomainAdd, .vercelDomainRemove,
             .githubActionsSecretNameList, .githubActionsSecretPut:
            true
        default:
            false
        }
    }

    /// A short verb for the sheet's second line and for the receipt.
    var verbLabel: String {
        switch taxonomy.kind {
        case .read: "List"
        case .create: "Create"
        case .update: "Update"
        case .delete: "Delete"
        case .deliver: "Deliver"
        }
    }

    /// BL-094. True when this operation writes a vault value into a provider's
    /// own secret store, so the deployed environment keeps its own copy (D36).
    var isDelivery: Bool { taxonomy.isDelivery }

    /// BL-095 / D38. Whether this operation's approval may be signed on an
    /// enrolled phone rather than on this Mac.
    var isRemotelyApprovable: Bool { taxonomy.isRemotelyApprovable }

    /// D71. Whether an agent may request this operation as an *action*
    /// (`vaultage_execute`).
    ///
    /// False for every delivery. The action path runs BL-091's resource
    /// operation with no check before the write, none after it, and no
    /// ledger row; a delivery is asked for with `vaultage_deliver` instead,
    /// which runs `deliverCredential` — the same checked, recorded path the
    /// owner's app uses. So the execute schema does not offer a delivery, the
    /// MCP parser refuses one, and the broker refuses one before anything is
    /// read. (BL-128 slice 3c first did this for GitHub's write alone, under
    /// D65; D71 made it the rule for the class.)
    var isAgentReachable: Bool { !isDelivery }
}

// MARK: - The bound resource scope

/// Which provider-side container a binding is scoped to.
///
/// This is the BL-091 generalisation of `CloudflareWorkerDestination`: an
/// immutable, non-secret identifier the human chose when they made the binding,
/// which the agent can never supply and never change. Without it a DNS
/// operation would take a zone id from the request, and "create a DNS record"
/// would mean "create a DNS record in any zone this token can reach".
public enum ProviderResourceScopeKind: String, Codable, Sendable, CaseIterable {
    /// One Cloudflare zone. `zoneID` is required.
    case cloudflareZone = "cloudflare.zone"
    /// One Cloudflare account, for the Worker script list. `accountID` required.
    case cloudflareAccount = "cloudflare.account"
    /// One Cloudflare account plus one Worker script, for the secret-name list.
    case cloudflareWorkerScript = "cloudflare.worker_script"
    /// One Vercel project. `projectID` is required.
    case vercelProject = "vercel.project"
    /// The Vercel account itself, for project creation. No identifier.
    case vercelAccount = "vercel.account"
    /// BL-128 slice 3b. One GitHub repository, as its `owner/repo` full name.
    /// `repository` is required.
    case githubRepository = "github.repository"
}

public struct ProviderResourceScope: Codable, Hashable, Sendable {
    public let kind: ProviderResourceScopeKind
    public let accountID: String?
    public let zoneID: String?
    public let scriptName: String?
    public let projectID: String?
    /// BL-128 slice 3b. A GitHub repository's `owner/repo` full name. Absent
    /// from every scope written before it existed, which decodes as nil.
    public let repository: String?
    /// What the sheet calls it — a human label, never identity.
    public let label: String

    public init(
        kind: ProviderResourceScopeKind,
        accountID: String? = nil,
        zoneID: String? = nil,
        scriptName: String? = nil,
        projectID: String? = nil,
        repository: String? = nil,
        label: String
    ) {
        self.kind = kind
        self.accountID = accountID
        self.zoneID = zoneID
        self.scriptName = scriptName
        self.projectID = projectID
        self.repository = repository
        self.label = label
    }

    public var provider: Provider {
        switch kind {
        case .cloudflareZone, .cloudflareAccount, .cloudflareWorkerScript: .cloudflare
        case .vercelProject, .vercelAccount: .vercel
        case .githubRepository: .github
        }
    }

    /// BL-128 slice 3b. A GitHub `owner/repo` full name, as a path segment
    /// pair. The owner is up to 39 alphanumerics and single hyphens, neither
    /// leading nor trailing; the repository is up to 100 of `A-Za-z0-9._-`
    /// and is never `.` or `..`. Exactly one slash separates them, so the pair
    /// can never add a third path segment, a query or a traversal.
    public static func isCanonicalGitHubRepository(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard value.utf8.count <= 140, parts.count == 2 else { return false }
        let owner = String(parts[0]), repo = String(parts[1])
        guard owner.utf8.count <= 39,
              owner.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*$", options: .regularExpression) != nil
        else { return false }
        guard repo.utf8.count <= 100, repo != ".", repo != "..",
              repo.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil
        else { return false }
        return true
    }

    /// Cloudflare account and zone ids are 32 lowercase hexadecimal characters.
    public static func isCanonicalCloudflareID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil
    }

    /// A Vercel project id is `prj_` followed by an opaque token; an id or name
    /// may also be used on the same routes, so the shape is bounded rather than
    /// pinned to one prefix. No slash, no dot-dot, no percent: it becomes a
    /// path segment.
    public static func isCanonicalVercelProjectID(_ value: String) -> Bool {
        value.utf8.count <= 128
            && value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
    }

    public static func isCanonicalScriptName(_ value: String) -> Bool {
        value.utf8.count <= 128
            && value.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil
            && !value.contains("..")
    }

    /// Every identifier this kind requires is present and canonical, and every
    /// identifier it does not use is absent. A record that carries a field its
    /// kind denies is refused rather than having the extra field ignored, so a
    /// hand-edited binding cannot smuggle a second target past the digest.
    public var isWellFormed: Bool {
        guard !label.isEmpty, label.utf8.count <= 96,
              label.range(of: "^[A-Za-z0-9 ._:/@()'-]+$", options: .regularExpression) != nil else { return false }
        switch kind {
        case .cloudflareZone:
            return zoneID.map(Self.isCanonicalCloudflareID) == true
                && accountID == nil && scriptName == nil && projectID == nil && repository == nil
        case .cloudflareAccount:
            return accountID.map(Self.isCanonicalCloudflareID) == true
                && zoneID == nil && scriptName == nil && projectID == nil && repository == nil
        case .cloudflareWorkerScript:
            return accountID.map(Self.isCanonicalCloudflareID) == true
                && scriptName.map(Self.isCanonicalScriptName) == true
                && zoneID == nil && projectID == nil && repository == nil
        case .vercelProject:
            return projectID.map(Self.isCanonicalVercelProjectID) == true
                && accountID == nil && zoneID == nil && scriptName == nil && repository == nil
        case .vercelAccount:
            return accountID == nil && zoneID == nil && scriptName == nil && projectID == nil && repository == nil
        case .githubRepository:
            return repository.map(Self.isCanonicalGitHubRepository) == true
                && accountID == nil && zoneID == nil && scriptName == nil && projectID == nil
        }
    }

    /// The scope kinds an operation may run against. An operation whose binding
    /// carries a scope of another kind is refused before anything is resolved.
    public static func kinds(for operation: Operation) -> Set<ProviderResourceScopeKind> {
        switch operation {
        case .cloudflareDNSRecordList, .cloudflareDNSRecordCreate,
             .cloudflareDNSRecordUpdate, .cloudflareDNSRecordDelete:
            [.cloudflareZone]
        case .cloudflareWorkerScriptList:
            [.cloudflareAccount]
        case .cloudflareWorkerSecretNameList:
            [.cloudflareWorkerScript]
        case .githubActionsSecretNameList, .githubActionsSecretPut:
            [.githubRepository]
        case .vercelProjectCreate:
            [.vercelAccount]
        case .vercelEnvList, .vercelEnvCreate, .vercelEnvUpdate, .vercelEnvDelete,
             .vercelDomainList, .vercelDomainAdd, .vercelDomainRemove:
            [.vercelProject]
        default:
            []
        }
    }

    /// Canonical, injective fields for a request digest (RP-07).
    ///
    /// BL-128 slice 3c, from the independent security pass: the repository
    /// is what a GitHub scope routes to, so it is a term of every digest the
    /// scope is part of — the approval digest, the delivery digest, the
    /// verify digest and the inventory refresh key. Before this, a same-user
    /// process could change a binding's repository while its sheet was open,
    /// keep the label, and the re-read digest still matched. Appended only
    /// when present, so no other scope's digest moves; still injective,
    /// because the kind decides whether a repository may be present at all
    /// (`isWellFormed`) and every field is length-prefixed.
    public var canonicalFields: [String] {
        var fields = ["scope", kind.rawValue, accountID ?? "none", zoneID ?? "none", scriptName ?? "none", projectID ?? "none", label]
        if let repository { fields += ["repository", repository] }
        return fields
    }

    /// What the sheet's first line names, after the resource kind.
    public var sheetTarget: String {
        switch kind {
        case .cloudflareZone: "zone \(label)"
        case .cloudflareAccount: "Cloudflare account \(label)"
        case .cloudflareWorkerScript: "Worker \(scriptName ?? label)"
        case .vercelProject: "Vercel project \(label)"
        case .vercelAccount: "Vercel account \(label)"
        case .githubRepository: "GitHub repository \(repository ?? label)"
        }
    }
}

// MARK: - Typed request fields

/// The closed set of field names a resource operation accepts.
///
/// A closed enum rather than a free dictionary, for the same reason
/// `ProviderRoute` is a closed enum: the agent picks *which* reviewed field it
/// is setting, and cannot invent one. Anything not named here is refused by the
/// MCP parser before it reaches the broker.
///
/// There is deliberately **no `value` key**. An environment variable's value
/// never travels through MCP: `vercel.env.create` and `.update` take a
/// `sourceVaultItemID` that must already be authorized for the binding, exactly
/// as `cloudflare.worker.secret.put` does, and the broker reads the value from
/// the Keychain locally.
public enum ResourceFieldKey: String, Codable, Sendable, CaseIterable, Comparable {
    case recordType = "record_type"
    case name
    case content
    case ttl
    case proxied
    case priority
    case comment
    case target
    case gitBranch = "git_branch"
    case variableType = "variable_type"
    case framework
    case domain
    case redirect

    public static func < (lhs: ResourceFieldKey, rhs: ResourceFieldKey) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// Everything a resource operation carries beyond the binding: the exact id it
/// names, the typed fields it sets, the delete confirmation, the idempotency
/// key and — for the two operations that write a credential into a provider's
/// secret store — the local vault item the value comes from.
public struct ResourceMutationArguments: Codable, Hashable, Sendable {
    /// The exact provider-side id, required for an update or a delete.
    public let resourceID: String?
    /// Typed fields only. Values are bounded ASCII; see `validated(for:)`.
    public let fields: [ResourceFieldKey: String]
    /// Two-step delete: absent or false returns a preview, true performs it.
    public let confirmDelete: Bool
    /// Local replay protection for an `idempotencyKey`-class create.
    public let idempotencyKey: String?
    /// The vault item whose value is written into the provider's secret store,
    /// set by `VaultageBroker.deliver` when a delivery writes through the
    /// resource route (Vercel's create and update, GitHub's put). D71: no
    /// action an agent may perform names one — `vaultage_execute` carries no
    /// delivery — and `ResourceFieldRules.validate` refuses one on any other
    /// operation. Which field of a composite is delivered is the delivery
    /// request's own (`CredentialDeliveryRequest.sourceField`), resolved
    /// before the value reaches these arguments.
    public let sourceVaultItemID: UUID?

    public init(
        resourceID: String? = nil,
        fields: [ResourceFieldKey: String] = [:],
        confirmDelete: Bool = false,
        idempotencyKey: String? = nil,
        sourceVaultItemID: UUID? = nil
    ) {
        self.resourceID = resourceID
        self.fields = fields
        self.confirmDelete = confirmDelete
        self.idempotencyKey = idempotencyKey
        self.sourceVaultItemID = sourceVaultItemID
    }

    public static let maximumFieldBytes = 512
    public static let maximumResourceIDBytes = 128

    /// Canonical, injective fields for the request digest (RP-07). Field keys
    /// are sorted and the list states its own length, so no field value can
    /// impersonate another field by containing a separator.
    public var canonicalFields: [String] {
        let sorted = fields.keys.sorted()
        var out: [String] = ["arguments", resourceID ?? "none", "\(confirmDelete)", idempotencyKey ?? "none", sourceVaultItemID?.uuidString ?? "none", "\(sorted.count)"]
        for key in sorted {
            out.append(key.rawValue)
            out.append(fields[key] ?? "")
        }
        return out
    }
}

// MARK: - Field validation

/// The per-operation field rules. Pure, so the same rules run in the MCP
/// parser's negative tests and in the broker.
public enum ResourceFieldRules {
    /// DNS record types this slice accepts. Deliberately short and reviewed:
    /// `NS` is excluded because delegating a zone is an admin-class act, and
    /// `SRV`/`CAA` are excluded because their content is structured rather than
    /// a single string and would need their own typed fields.
    public static let dnsRecordTypes: Set<String> = ["A", "AAAA", "CNAME", "TXT", "MX"]
    /// Vercel deploy targets.
    public static let vercelTargets: Set<String> = ["production", "preview", "development"]
    /// Vercel environment-variable types Vaultage will create. `plain` is
    /// excluded: Vaultage only ever writes a value it took from the vault, and
    /// writing it in the clear where the dashboard shows it back would
    /// contradict the custody promise.
    public static let vercelVariableTypes: Set<String> = ["encrypted", "sensitive"]

    /// Which fields an operation requires, and which it merely allows.
    public static func required(for operation: Operation) -> Set<ResourceFieldKey> {
        switch operation {
        case .cloudflareDNSRecordCreate, .cloudflareDNSRecordUpdate: [.recordType, .name, .content]
        case .vercelProjectCreate: [.name]
        case .vercelEnvCreate: [.name, .target, .variableType]
        case .vercelEnvUpdate: [.target]
        case .vercelDomainAdd: [.domain]
        case .githubActionsSecretPut: [.name]
        default: []
        }
    }

    public static func allowed(for operation: Operation) -> Set<ResourceFieldKey> {
        switch operation {
        case .cloudflareDNSRecordCreate, .cloudflareDNSRecordUpdate:
            [.recordType, .name, .content, .ttl, .proxied, .priority, .comment]
        case .vercelProjectCreate: [.name, .framework]
        case .vercelEnvCreate: [.name, .target, .variableType, .gitBranch, .comment]
        case .vercelEnvUpdate: [.target, .gitBranch, .comment]
        case .vercelDomainAdd: [.domain, .redirect]
        case .githubActionsSecretPut: [.name]
        default: []
        }
    }

    /// Whether this operation takes its value from a local vault item.
    public static func requiresSourceVaultItem(_ operation: Operation) -> Bool {
        operation == .vercelEnvCreate || operation == .vercelEnvUpdate || operation == .githubActionsSecretPut
    }

    /// One limit for a GitHub Actions secret name, shared by the write, the
    /// name list and the direct read, so a name the write accepts is always one
    /// the reads can report (the independent pass found 101–128 accepted by
    /// the write and dropped by the list). GitHub documents no maximum.
    public static let maximumGitHubSecretNameBytes = 128

    /// BL-128 slice 3c. A GitHub Actions secret name **as GitHub stores it**:
    /// upper-case letters, digits and underscores, not starting with a digit
    /// and not starting with `GITHUB_`. GitHub documents that it stores every
    /// name in upper case "regardless of how they are entered", so a
    /// lower-case name is refused here rather than silently upper-cased:
    /// the sheet names exactly what GitHub will store, and the name list
    /// that verifies the delivery reports exactly that spelling.
    public static func isCanonicalGitHubSecretName(_ value: String) -> Bool {
        value.utf8.count <= maximumGitHubSecretNameBytes
            && value.range(of: "^[A-Z_][A-Z0-9_]*$", options: .regularExpression) != nil
            && !value.hasPrefix("GITHUB_")
    }

    /// The shape of a provider-side id for this operation's resource kind.
    public static func isCanonicalResourceID(_ value: String, for operation: Operation) -> Bool {
        guard value.utf8.count <= ResourceMutationArguments.maximumResourceIDBytes, !value.isEmpty else { return false }
        switch operation {
        case .cloudflareDNSRecordUpdate, .cloudflareDNSRecordDelete:
            return ProviderResourceScope.isCanonicalCloudflareID(value)
        case .vercelEnvUpdate, .vercelEnvDelete:
            return value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
        case .vercelDomainRemove:
            // A hostname. No scheme, no path, no port, no userinfo.
            return value.range(of: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", options: .regularExpression) != nil
                && !value.contains("..")
        default:
            return false
        }
    }

    /// Validates one typed field's value for one operation. Every rule is
    /// fail-closed and every accepted value is a bounded, closed-charset ASCII
    /// string, so nothing here can carry a control character, a newline or a
    /// path separator into a URL, a JSON body or an approval sheet.
    public static func validate(_ key: ResourceFieldKey, _ value: String, for operation: Operation) throws {
        guard value.utf8.count <= ResourceMutationArguments.maximumFieldBytes, !value.isEmpty else {
            throw VaultageError.invalidInput("\(key.rawValue) is empty or longer than \(ResourceMutationArguments.maximumFieldBytes) bytes.")
        }
        guard !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("\(key.rawValue) cannot contain control characters.")
        }
        switch key {
        case .recordType:
            guard dnsRecordTypes.contains(value) else {
                throw VaultageError.invalidInput("record_type must be one of \(dnsRecordTypes.sorted().joined(separator: ", ")).")
            }
        case .name:
            switch operation {
            case .githubActionsSecretPut:
                guard isCanonicalGitHubSecretName(value) else {
                    throw VaultageError.invalidInput("A GitHub Actions secret name is upper-case letters, digits and underscores, and does not start with a digit or GITHUB_. GitHub stores names in upper case, so write it the way it will be stored.")
                }
            case .vercelEnvCreate:
                // An environment variable key. Conservative POSIX shape, so it
                // can never become a shell surprise wherever it is later read.
                guard value.utf8.count <= 128, value.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil else {
                    throw VaultageError.invalidInput("An environment variable name must be a conservative ASCII identifier.")
                }
            case .vercelProjectCreate:
                guard value.utf8.count <= 100, value.range(of: "^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$", options: .regularExpression) != nil else {
                    throw VaultageError.invalidInput("A Vercel project name is lowercase letters, digits, and . _ -")
                }
            default:
                // A DNS record name. A hostname or `@`; never a URL.
                guard value == "@" || (value.utf8.count <= 255
                        && value.range(of: "^(\\*\\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", options: .regularExpression) != nil
                        && !value.contains("..")) else {
                    throw VaultageError.invalidInput("A DNS record name must be a hostname, a wildcard hostname, or @.")
                }
            }
        case .content:
            // Deliberately permissive in charset (a TXT record is arbitrary
            // text) but closed against anything that could reshape a sheet or a
            // URL: printable ASCII only, no quote, no backslash, no angle
            // bracket. A TXT value that needs those is refused rather than
            // escaped, because this slice does not need it.
            guard value.range(of: "^[A-Za-z0-9 ._:/@=+,;!?()\\[\\]{}~^%*#$&|-]+$", options: .regularExpression) != nil else {
                throw VaultageError.invalidInput("content may not contain quotes, backslashes or angle brackets.")
            }
        case .ttl:
            guard let ttl = Int(value), ttl == 1 || (60 ... 86400).contains(ttl) else {
                throw VaultageError.invalidInput("ttl must be 1 (automatic) or between 60 and 86400 seconds.")
            }
        case .proxied, .redirect:
            guard value == "true" || value == "false" else {
                throw VaultageError.invalidInput("\(key.rawValue) must be true or false.")
            }
        case .priority:
            guard let priority = Int(value), (0 ... 65535).contains(priority) else {
                throw VaultageError.invalidInput("priority must be between 0 and 65535.")
            }
        case .comment:
            guard value.utf8.count <= 100, value.range(of: "^[A-Za-z0-9 ._:/@()'-]+$", options: .regularExpression) != nil else {
                throw VaultageError.invalidInput("comment must be short plain text.")
            }
        case .target:
            guard vercelTargets.contains(value) else {
                throw VaultageError.invalidInput("target must be one of \(vercelTargets.sorted().joined(separator: ", ")).")
            }
        case .gitBranch:
            guard value.utf8.count <= 128, value.range(of: "^[A-Za-z0-9._/-]+$", options: .regularExpression) != nil, !value.contains("..") else {
                throw VaultageError.invalidInput("git_branch must be a conservative branch name.")
            }
        case .variableType:
            guard vercelVariableTypes.contains(value) else {
                throw VaultageError.invalidInput("variable_type must be one of \(vercelVariableTypes.sorted().joined(separator: ", ")).")
            }
        case .framework:
            guard value.utf8.count <= 40, value.range(of: "^[a-z0-9-]+$", options: .regularExpression) != nil else {
                throw VaultageError.invalidInput("framework must be a Vercel framework slug.")
            }
        case .domain:
            guard value.utf8.count <= 253,
                  value.range(of: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", options: .regularExpression) != nil,
                  !value.contains("..") else {
                throw VaultageError.invalidInput("domain must be a hostname.")
            }
        }
    }

    public static let idempotencyKeyPattern = "^[A-Za-z0-9_-]{8,64}$"

    /// The whole argument check for one operation, in one place. Called by the
    /// MCP parser and again by the broker, because a request that crossed a
    /// process boundary is re-validated on arrival.
    public static func validate(_ arguments: ResourceMutationArguments, for operation: Operation) throws {
        let taxonomy = operation.taxonomy
        guard operation.isResourceOperation else {
            throw VaultageError.invalidInput("\(operation.rawValue) is not a provider resource operation.")
        }
        if taxonomy.requiresExactResourceID {
            guard let id = arguments.resourceID, isCanonicalResourceID(id, for: operation) else {
                throw VaultageError.invalidInput("\(operation.rawValue) requires the exact resource id.")
            }
        } else {
            guard arguments.resourceID == nil else {
                throw VaultageError.invalidInput("\(operation.rawValue) does not take a resource id.")
            }
        }
        guard taxonomy.isTwoStepDelete || !arguments.confirmDelete else {
            throw VaultageError.invalidInput("Only a delete takes a confirmation flag.")
        }
        let allowed = allowed(for: operation)
        for (key, value) in arguments.fields {
            guard allowed.contains(key) else {
                throw VaultageError.invalidInput("\(operation.rawValue) does not take \(key.rawValue).")
            }
            try validate(key, value, for: operation)
        }
        for key in required(for: operation) where arguments.fields[key] == nil {
            throw VaultageError.invalidInput("\(operation.rawValue) requires \(key.rawValue).")
        }
        // MX carries a priority; nothing else may.
        if arguments.fields[.recordType] != "MX", arguments.fields[.priority] != nil {
            throw VaultageError.invalidInput("priority applies only to an MX record.")
        }
        if arguments.fields[.recordType] == "MX", arguments.fields[.priority] == nil {
            throw VaultageError.invalidInput("An MX record requires priority.")
        }
        // A preview-scoped Vercel variable is the only one that may name a
        // branch; naming one for production would silently be ignored.
        if arguments.fields[.gitBranch] != nil, arguments.fields[.target] != "preview" {
            throw VaultageError.invalidInput("git_branch applies only to a preview-target variable.")
        }
        if requiresSourceVaultItem(operation) {
            guard arguments.sourceVaultItemID != nil else {
                throw VaultageError.invalidInput("\(operation.rawValue) requires source_secret_id: the value is read from the vault, never sent through MCP.")
            }
        } else {
            guard arguments.sourceVaultItemID == nil else {
                throw VaultageError.invalidInput("\(operation.rawValue) does not take source_secret_id.")
            }
        }
        if let key = arguments.idempotencyKey {
            guard taxonomy.idempotency == .idempotencyKey else {
                throw VaultageError.invalidInput("\(operation.rawValue) does not take an idempotency key.")
            }
            guard key.range(of: idempotencyKeyPattern, options: .regularExpression) != nil else {
                throw VaultageError.invalidInput("idempotency_key must be 8 to 64 characters of A-Z a-z 0-9 _ -")
            }
        }
    }
}

// MARK: - Results

/// The value-free projection a resource operation returns.
///
/// It is a fixed shape rather than `ActionResult`'s open dictionary so that the
/// two things BL-091 must guarantee — the resource id is reported, and no value
/// is — are properties of the type rather than of each adapter's care.
public struct ResourceOperationResult: Codable, Hashable, Sendable {
    public let operation: String
    public let kind: OperationKind
    public let resourceKind: ResourceKind
    /// The provider-side id this call acted on or created. Nil for a list.
    public let resourceID: String?
    /// One sentence naming the effect, for the receipt and for the agent.
    public let effect: String
    /// The provider's own count for a list, so a bounded projection never
    /// reads as "the account has nothing".
    public let count: Int?
    /// Up to 25 projected members, identifiers and labels only.
    public let items: [ResourceOperationItem]
    /// Set when a delete was called without confirmation.
    public let preview: ResourceDeletePreview?

    public init(
        operation: String,
        kind: OperationKind,
        resourceKind: ResourceKind,
        resourceID: String? = nil,
        effect: String,
        count: Int? = nil,
        items: [ResourceOperationItem] = [],
        preview: ResourceDeletePreview? = nil
    ) {
        self.operation = operation
        self.kind = kind
        self.resourceKind = resourceKind
        self.resourceID = resourceID
        self.effect = effect
        self.count = count
        self.items = items
        self.preview = preview
    }

    /// The `ActionResult` the existing MCP and receipt paths already carry, so
    /// a resource operation needs no second result shape on the seam.
    public var actionResult: ActionResult {
        var fields: [String: String] = ["kind": kind.rawValue, "resource": resourceKind.rawValue, "effect": effect]
        if let resourceID { fields["resource_id"] = resourceID }
        if let count { fields["count"] = "\(count)" }
        if !items.isEmpty {
            fields["ids"] = items.map(\.id).joined(separator: ", ")
            let labels = items.compactMap(\.label)
            if !labels.isEmpty { fields["labels"] = labels.joined(separator: ", ") }
        }
        if let preview { fields["preview"] = preview.summary; fields["confirmation_required"] = "true" }
        return ActionResult(summary: effect, fields: fields)
    }
}

/// One projected member of a list. An id, an optional label, and at most two
/// bounded documented attributes — never a value.
public struct ResourceOperationItem: Codable, Hashable, Sendable {
    public let id: String
    public let label: String?
    public let attributes: [String: String]

    public init(id: String, label: String? = nil, attributes: [String: String] = [:]) {
        self.id = id
        self.label = label
        self.attributes = attributes
    }
}

/// What the first half of a two-step delete returns.
///
/// It is not a promise that the delete will succeed; it is a statement of the
/// exact record the confirmed call would remove, read back from the provider
/// immediately before, so the agent and the human are looking at the same
/// object. Repeating the call with `confirm: true` and the same id performs it.
public struct ResourceDeletePreview: Codable, Hashable, Sendable {
    public let resourceID: String
    public let resourceKind: ResourceKind
    /// The bounded description the sheet and the agent both show.
    public let summary: String
    /// The exact literal the confirming call must repeat.
    public let confirmationToken: String

    public init(resourceID: String, resourceKind: ResourceKind, summary: String, confirmationToken: String) {
        self.resourceID = resourceID
        self.resourceKind = resourceKind
        self.summary = summary
        self.confirmationToken = confirmationToken
    }
}

// MARK: - The approval disclosure

/// Exactly what the resource approval sheet states, as data.
///
/// D34's copy rule, as a type: **resource, then action, then safety.** The UI
/// lane renders these three lines in this order and adds nothing of its own;
/// `resourceLine` is what the human is acting on, `actionLine` is what will
/// happen to it, and `safetyLine` is the custody sentence.
public struct ResourceOperationDisclosure: Codable, Hashable, Sendable {
    /// "DNS record on zone flyingnimbus.io"
    public let resourceLine: String
    /// "Update the existing record 3f1c… (A → 203.0.113.9)"
    public let actionLine: String
    /// "Approved on this Mac and receipted. The Vaultage token stays in the
    /// Keychain and is never returned."
    public let safetyLine: String
    public let trustClass: OperationTrustClass
    public let kind: OperationKind
    public let resourceKind: ResourceKind
    /// The exact provider-side id, for an update or a delete. The sheet shows
    /// it verbatim; BL-091 requires it.
    public let resourceID: String?
    public let scopeLabel: String
    /// Set when the environment is production.
    public let productionWarning: String?
    /// Set for an operation whose provider returns values on the same route.
    public let valueDisclosure: String?
    /// Set for a create whose repeat would make a second object.
    public let idempotencyNote: String?
    public let requestDigest: String

    public init(
        resourceLine: String,
        actionLine: String,
        safetyLine: String,
        trustClass: OperationTrustClass,
        kind: OperationKind,
        resourceKind: ResourceKind,
        resourceID: String?,
        scopeLabel: String,
        productionWarning: String? = nil,
        valueDisclosure: String? = nil,
        idempotencyNote: String? = nil,
        requestDigest: String
    ) {
        self.resourceLine = resourceLine
        self.actionLine = actionLine
        self.safetyLine = safetyLine
        self.trustClass = trustClass
        self.kind = kind
        self.resourceKind = resourceKind
        self.resourceID = resourceID
        self.scopeLabel = scopeLabel
        self.productionWarning = productionWarning
        self.valueDisclosure = valueDisclosure
        self.idempotencyNote = idempotencyNote
        self.requestDigest = requestDigest
    }

    public static let safetySentence = "Approved on this Mac and receipted. The provider credential stays in the Keychain and is never returned to the agent."
    public static let deleteSafetySentence = "Approved on this Mac and receipted. Deleting is not reversible from Vaultage; the exact resource id above is what will be removed."
    public static let productionSentence = "WARNING: this environment is production. This change takes effect on live traffic."
    public static let vercelValueSentence = "Vercel returns environment-variable values on this route. Vaultage drops every value-bearing field inside the transport, so no value reaches this sheet, the result, the receipt or the agent."
    public static let localIdempotencySentence = "Repeating this would create a second object. Vaultage refuses a second dispatch under the same idempotency key; the provider does not de-duplicate on this route."
}

// MARK: - The local idempotency ledger

/// One recorded dispatch under an idempotency key.
///
/// Durable metadata, value-free, and bounded. It exists because none of the
/// create routes in this slice document a provider-side idempotency key: the
/// only thing that can stop a retried agent from making a second DNS record is
/// Vaultage refusing to dispatch twice.
public struct ResourceMutationKey: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let key: String
    public let bindingID: UUID
    public let operation: String
    /// The request digest the key was first used with. A key reused for a
    /// *different* request is refused rather than replayed, so a key cannot be
    /// used to smuggle a second, different mutation past the sheet.
    public let requestDigest: String
    public let at: Date
    /// The provider id the first dispatch produced, when it produced one.
    public let resourceID: String?
    public let effect: String

    public init(id: UUID = UUID(), key: String, bindingID: UUID, operation: String, requestDigest: String, at: Date = .now, resourceID: String?, effect: String) {
        self.id = id
        self.key = key
        self.bindingID = bindingID
        self.operation = operation
        self.requestDigest = requestDigest
        self.at = at
        self.resourceID = resourceID
        self.effect = effect
    }

    /// How long a key is remembered. Long enough to cover any plausible agent
    /// retry, short enough that the ledger stays small.
    /// Audit H-11: at least as long as the longest grant (seven days) plus a
    /// day, so a key cannot be reused while the grant that covered its first
    /// dispatch is still live.
    public static let lifetime: TimeInterval = 8 * 24 * 60 * 60
    public static let maximumRecords = 2_000
    /// The effect a claim carries between dispatch and its report. A replay
    /// that finds it is answered as unknown, never as done.
    public static let unresolvedEffect = "A dispatch under this key was started and has not reported a result."

    public func isLive(at instant: Date) -> Bool {
        instant >= at && instant.timeIntervalSince(at) <= Self.lifetime
    }
}
