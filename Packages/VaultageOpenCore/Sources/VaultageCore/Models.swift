import Foundation

public enum Provider: String, Codable, CaseIterable, Sendable, Identifiable {
    case github, openAI = "openai", cloudflare
    /// BL-088 wave 1 (D32). Every raw value is the catalog id of the same
    /// provider, which is what makes `ServiceCatalog` availability derivable
    /// from the compiled adapter set rather than authored by hand.
    case anthropic
    case googleGemini = "google-gemini"
    case vercel
    case netlify
    case supabase
    case neon
    case resend
    case stripe
    case sentry
    /// BL-089 wave 2 (D32). Same rule: the raw value is the catalog id.
    case railway
    case render
    case clerk
    case posthog
    case slack
    case discord
    case sendGrid = "sendgrid"
    case twilio
    case mailgun
    case postmark
    case xai
    case mistral
    case deepSeek = "deepseek"
    case cohere
    case digitalOcean = "digitalocean"
    /// BL-111 wave 3 (D32's pipeline, scoped by the catalog's own Coming soon
    /// bucket). Same rule again: the raw value is the catalog id.
    case apify
    case gitlab
    /// BL-112 wave 4 (D32's pipeline, scoped by the catalog's own **requested**
    /// bucket, in catalog order). Same rule again: the raw value is the catalog
    /// id.
    case make
    case paddle
    case segment
    case workos
    /// BL-112's wave-5 follow-up (D32's pipeline). The three wave 4 deferred
    /// only because their documentation could not be fetched; all three were
    /// read first-hand on 2026-09-12 by a different method, and all three fit
    /// the transport unchanged. Same rule again: the raw value is the catalog
    /// id.
    case bitbucket
    case lemonSqueezy = "lemon-squeezy"
    case planetScale = "planetscale"
    /// BL-116 wave 5 (D50, the category floor). Three app builders that now
    /// document a public API on a fixed host, and Doppler as the value-free
    /// read-only connection D50 makes an exception of. Same rule again: the raw
    /// value is the catalog id.
    case glide
    case hostingerHorizons = "hostinger-horizons"
    case v0
    case doppler
    /// BL-117 (D51). The first `signedRequest` provider: the stored access key
    /// pair signs each request and is never sent. Same rule again: the raw
    /// value is the catalog id.
    case aws
    /// BL-117's second slot (D51, spec §7.2). The first `tokenExchange`
    /// provider: the stored client secret is exchanged at Microsoft's token
    /// endpoint for a short-lived access token, and only that token reaches
    /// Microsoft Graph. Same rule again: the raw value is the catalog id.
    case azure
    /// BL-117's third slot (D51, spec §7.3). The first
    /// `tokenExchange(.serviceAccountJWT)` provider: the stored service-account
    /// key signs a one-hour RS256 assertion, the assertion is exchanged at
    /// Google's token endpoint for a short-lived access token, and only that
    /// token reaches Cloud Resource Manager. The private key itself is never
    /// sent anywhere, in any form. Same rule again: the raw value is the
    /// catalog id.
    case googleCloud = "google-cloud"
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .github: "GitHub"
        case .openAI: "OpenAI"
        case .cloudflare: "Cloudflare"
        case .anthropic: "Anthropic"
        case .googleGemini: "Google Gemini"
        case .vercel: "Vercel"
        case .netlify: "Netlify"
        case .supabase: "Supabase"
        case .neon: "Neon"
        case .resend: "Resend"
        case .stripe: "Stripe"
        case .sentry: "Sentry"
        case .railway: "Railway"
        case .render: "Render"
        case .clerk: "Clerk"
        case .posthog: "PostHog"
        case .slack: "Slack"
        case .discord: "Discord"
        case .sendGrid: "SendGrid"
        case .twilio: "Twilio"
        case .mailgun: "Mailgun"
        case .postmark: "Postmark"
        case .xai: "xAI"
        case .mistral: "Mistral AI"
        case .deepSeek: "DeepSeek"
        case .cohere: "Cohere"
        case .digitalOcean: "DigitalOcean"
        case .apify: "Apify"
        case .gitlab: "GitLab"
        case .make: "Make"
        case .paddle: "Paddle"
        case .segment: "Segment"
        case .workos: "WorkOS"
        case .bitbucket: "Bitbucket"
        case .lemonSqueezy: "Lemon Squeezy"
        case .planetScale: "PlanetScale"
        case .glide: "Glide"
        case .hostingerHorizons: "Hostinger Horizons"
        case .v0: "v0"
        case .doppler: "Doppler"
        case .aws: "Amazon Web Services"
        case .azure: "Microsoft Azure"
        case .googleCloud: "Google Cloud"
        }
    }
}

public enum Operation: String, Codable, CaseIterable, Sendable {
    case githubRateLimit = "github.rate_limit"
    // BL-128. GitHub moves into the table family: the rate-limit read keeps
    // its raw value (grants and receipts name it), and the repository list is
    // the second read. Both are reads, exactly as every wave before.
    case githubListRepositories = "github.list_repositories"
    // BL-128 slice 3b (D65). The names of one repository's Actions secrets.
    // A resource-scoped read in BL-091's family: it takes a bound
    // `owner/repo` scope and GitHub never returns a value on this route.
    case githubActionsSecretNameList = "github.actions.secret.list"
    // BL-128 slice 3c (D65). Writes one vault value into one repository's
    // Actions secrets, sealed on this Mac to the repository's own public key.
    // A delivery (BL-094): a native sheet every time, never grantable.
    case githubActionsSecretPut = "github.actions.secret.put"
    case openAIListModels = "openai.list_models"
    case cloudflareVerifyToken = "cloudflare.verify_token"
    case cloudflareWorkerSecretPut = "cloudflare.worker.secret.put"
    // BL-088 wave 1. Every one of these is a read of provider metadata; none
    // creates, sends, rotates, deletes or reveals anything. The onboarding
    // rule is that a wave adds no mutation route (BL-088, runbook §4).
    case anthropicListModels = "anthropic.list_models"
    case geminiListModels = "google-gemini.list_models"
    case vercelListProjects = "vercel.list_projects"
    case netlifyListSites = "netlify.list_sites"
    case supabaseListProjects = "supabase.list_projects"
    case neonListProjects = "neon.list_projects"
    case resendListDomains = "resend.list_domains"
    case stripeRetrieveBalance = "stripe.retrieve_balance"
    case sentryListOrganizations = "sentry.list_organizations"
    // BL-089 wave 2. Reads, exactly as wave 1: no operation here creates,
    // sends, rotates, deletes or reveals anything.
    case railwayListProjects = "railway.list_projects"
    case renderListServices = "render.list_services"
    case renderListProjects = "render.list_projects"
    case clerkListDomains = "clerk.list_domains"
    case posthogListOrganizations = "posthog.list_organizations"
    case slackTeamInfo = "slack.team_info"
    case discordListGuilds = "discord.list_guilds"
    case sendGridListScopes = "sendgrid.list_scopes"
    case twilioListAccounts = "twilio.list_accounts"
    case mailgunListDomains = "mailgun.list_domains"
    case postmarkGetServer = "postmark.get_server"
    case xaiListModels = "xai.list_models"
    case mistralListModels = "mistral.list_models"
    case deepSeekListModels = "deepseek.list_models"
    case cohereListModels = "cohere.list_models"
    case digitalOceanListProjects = "digitalocean.list_projects"
    // BL-111 wave 3. Reads, exactly as waves 1 and 2.
    case apifyListActors = "apify.list_actors"
    case gitlabListGroups = "gitlab.list_groups"
    // BL-112 wave 4. Reads, exactly as waves 1 to 3.
    case makeListOrganizations = "make.list_organizations"
    case paddleListProducts = "paddle.list_products"
    case segmentGetWorkspace = "segment.get_workspace"
    case workosListOrganizations = "workos.list_organizations"
    // BL-112's wave-5 follow-up. Reads, exactly as waves 1 to 4. Each of the
    // three is its provider's *only* compiled operation and is also its verify
    // route, so the capability set a verified connection records is exactly the
    // read that verify ran.
    case bitbucketListWorkspaces = "bitbucket.list_workspaces"
    case lemonSqueezyListStores = "lemon-squeezy.list_stores"
    case planetScaleListOrganizations = "planetscale.list_organizations"
    // BL-116 wave 5 (D50). Reads, exactly as waves 1 to 5. Three of the four
    // are their provider's only compiled operation and also its verify route;
    // Doppler is the exception on purpose — its verify route is the narrower
    // `/v3/me`, so a verified Doppler connection attests nothing and says so.
    case glideListTables = "glide.list_tables"
    case hostingerHorizonsListWebsites = "hostinger-horizons.list_websites"
    case v0ListScopes = "v0.list_scopes"
    case dopplerListProjects = "doppler.list_projects"
    // BL-117 (D51). AWS's one compiled operation, which is also its verify
    // route, so a verified AWS connection attests exactly the read verify ran —
    // the shape wave 5 shipped three times (Bitbucket, Lemon Squeezy,
    // PlanetScale). §7.1 declines to name a second AWS read as a fact because
    // none was read for the spec, and the ticket's "three available
    // backend-cloud providers" does not need one.
    case awsGetCallerIdentity = "aws.get_caller_identity"
    // BL-117's Azure slot (D51, §7.2). Azure's one compiled operation, which is
    // also its verify route — the wave-5 shape again. Verify under
    // `tokenExchange` sends **two** requests, the exchange and the resource
    // read, and it is the resource one PW4-M2 compares: a verified Azure
    // connection attests exactly `azure.get_organization` and nothing else.
    case azureGetOrganization = "azure.get_organization"
    // BL-117's Google Cloud slot (D51, §7.3). Google's one compiled operation,
    // which is also its verify route — the wave-5 shape a third time. A verify
    // under `serviceAccountJWT` sends **two** requests, the assertion exchange
    // and the projects read, and it is the resource one PW4-M2 compares: a
    // verified Google Cloud connection attests exactly
    // `google-cloud.list_projects` and nothing else.
    case googleCloudListProjects = "google-cloud.list_projects"
    // BL-091 slice 1 (D34). The first provider resource CRUD matrix: Cloudflare
    // DNS records on a bound zone, the two Worker reads, and Vercel projects,
    // environment variables and project domains. Each one's kind, resource,
    // trust class, idempotency and approval class live in
    // `ProviderResourceOperations.swift`; nothing about them is decided here.
    case cloudflareDNSRecordList = "cloudflare.dns_record.list"
    case cloudflareDNSRecordCreate = "cloudflare.dns_record.create"
    case cloudflareDNSRecordUpdate = "cloudflare.dns_record.update"
    case cloudflareDNSRecordDelete = "cloudflare.dns_record.delete"
    case cloudflareWorkerScriptList = "cloudflare.worker.script.list"
    case cloudflareWorkerSecretNameList = "cloudflare.worker.secret.list"
    case vercelProjectCreate = "vercel.project.create"
    case vercelEnvList = "vercel.env.list"
    case vercelEnvCreate = "vercel.env.create"
    case vercelEnvUpdate = "vercel.env.update"
    case vercelEnvDelete = "vercel.env.delete"
    case vercelDomainList = "vercel.domain.list"
    case vercelDomainAdd = "vercel.domain.add"
    case vercelDomainRemove = "vercel.domain.remove"
    public var isSensitive: Bool { true }
    /// BL-060, re-derived by BL-091. Whether an auto-allow grant may ever cover
    /// this operation.
    ///
    /// This used to be a hand-maintained exception list with one entry. It is
    /// now derived from the operation's own taxonomy through
    /// `ApprovalRequirement`, so the answer for an operation added later is a
    /// consequence of how it was classified rather than of whether somebody
    /// remembered to add it here.
    ///
    /// The one pre-existing exception is preserved exactly, and for the same
    /// reason it was written down: `cloudflare.worker.secret.put` is an update
    /// to a production-affecting resource, so it maps to
    /// `.nativeSheetEveryTime` and stays outside every grant.
    public var isAutoAllowable: Bool { approvalRequirement.mayBeCoveredByGrant }
    public var provider: Provider {
        switch self {
        case .githubRateLimit, .githubListRepositories, .githubActionsSecretNameList, .githubActionsSecretPut: .github
        case .openAIListModels: .openAI
        case .cloudflareVerifyToken, .cloudflareWorkerSecretPut,
             .cloudflareDNSRecordList, .cloudflareDNSRecordCreate, .cloudflareDNSRecordUpdate,
             .cloudflareDNSRecordDelete, .cloudflareWorkerScriptList, .cloudflareWorkerSecretNameList: .cloudflare
        case .anthropicListModels: .anthropic
        case .geminiListModels: .googleGemini
        case .vercelListProjects, .vercelProjectCreate, .vercelEnvList, .vercelEnvCreate,
             .vercelEnvUpdate, .vercelEnvDelete, .vercelDomainList, .vercelDomainAdd,
             .vercelDomainRemove: .vercel
        case .netlifyListSites: .netlify
        case .supabaseListProjects: .supabase
        case .neonListProjects: .neon
        case .resendListDomains: .resend
        case .stripeRetrieveBalance: .stripe
        case .sentryListOrganizations: .sentry
        case .railwayListProjects: .railway
        case .renderListServices, .renderListProjects: .render
        case .clerkListDomains: .clerk
        case .posthogListOrganizations: .posthog
        case .slackTeamInfo: .slack
        case .discordListGuilds: .discord
        case .sendGridListScopes: .sendGrid
        case .twilioListAccounts: .twilio
        case .mailgunListDomains: .mailgun
        case .postmarkGetServer: .postmark
        case .xaiListModels: .xai
        case .mistralListModels: .mistral
        case .deepSeekListModels: .deepSeek
        case .cohereListModels: .cohere
        case .digitalOceanListProjects: .digitalOcean
        case .apifyListActors: .apify
        case .gitlabListGroups: .gitlab
        case .makeListOrganizations: .make
        case .paddleListProducts: .paddle
        case .segmentGetWorkspace: .segment
        case .workosListOrganizations: .workos
        case .bitbucketListWorkspaces: .bitbucket
        case .lemonSqueezyListStores: .lemonSqueezy
        case .planetScaleListOrganizations: .planetScale
        case .glideListTables: .glide
        case .hostingerHorizonsListWebsites: .hostingerHorizons
        case .v0ListScopes: .v0
        case .dopplerListProjects: .doppler
        case .awsGetCallerIdentity: .aws
        case .azureGetOrganization: .azure
        case .googleCloudListProjects: .googleCloud
        }
    }
}

public struct Project: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public var name: String
    public var folder: String?
    public var createdAt: Date
    public init(id: UUID = UUID(), name: String, folder: String? = nil, createdAt: Date = .now) { self.id = id; self.name = name; self.folder = folder; self.createdAt = createdAt }
}

/// How much a mistake in this environment costs. `production` adds a separate
/// warning line to the runtime-delivery approval sheet; an environment literally
/// named "production" is treated as production whatever the stored value says,
/// so an older record cannot quietly lose the warning.
///
/// Schema 8 replaces the two-level `standard`/`production` scale with three
/// levels. `development` and `staging` are both non-production and behave
/// identically everywhere a production check is made; the distinction is
/// descriptive, so that an environment can say it is staging without claiming
/// the production warning.
public enum EnvironmentSensitivity: String, Codable, Sendable, CaseIterable {
    case development, staging, production

    /// Schema 7 and earlier wrote `standard`. Source that still says
    /// `.standard` keeps compiling and keeps meaning "not production"; it is an
    /// alias for `development`, not a fourth level, so `allCases` stays three.
    public static let standard = EnvironmentSensitivity.development

    /// Decoding never throws and never invents a *lower* sensitivity.
    ///
    /// - `standard` (schema 7 and earlier) becomes `development`, which is the
    ///   same "not production" meaning it always had.
    /// - `production` is preserved exactly.
    /// - An unrecognized value — a corrupt record, a hand edit, or a record
    ///   written by a newer build that added a level above production — decodes
    ///   to `production`. The failure mode of guessing low is a silently
    ///   dropped production warning on a runtime delivery, so the unknown case
    ///   fails closed upward rather than defaulting to `development`.
    public init(from decoder: Decoder) throws {
        switch try decoder.singleValueContainer().decode(String.self) {
        case Self.development.rawValue, "standard": self = .development
        case Self.staging.rawValue: self = .staging
        default: self = .production
        }
    }
}

/// BL-072 / D17. What an environment *is*, in the owner's definition: either a
/// local project root — a folder on this Mac — or a cloud mapping of a provider
/// connection and the resources bound to it.
///
/// This is descriptive, not an authorization input. Bindings, runtime-source
/// authorizations, runtime delivery, grants and every approval behave exactly
/// as before in both kinds; nothing is stored for a cloud environment that was
/// not already stored, and the only thing a local environment adds is a path
/// string held as metadata.
public enum EnvironmentKind: String, Codable, Sendable, CaseIterable {
    case local, cloud

    /// Schema 8 and earlier have no `kind`, and BL-072 says those environments
    /// become `cloud` — which is also the value that claims the least: a cloud
    /// environment stores no folder and asserts nothing about this Mac's disk.
    /// An unrecognized value (a corrupt record, a hand edit, or a record from a
    /// newer build with a third kind) decodes the same way for the same reason.
    public init(from decoder: Decoder) throws {
        switch try decoder.singleValueContainer().decode(String.self) {
        case Self.local.rawValue: self = .local
        default: self = .cloud
        }
    }
}

/// Validation for a local environment's root folder.
///
/// The path is **metadata and nothing else**. Vaultage never executes it, never
/// passes it to a shell, never interpolates it into a command, and never reads
/// a file inside it; the one filesystem call made here is the existence and
/// directory check at creation time, on a path the human picked themselves.
public enum EnvironmentRoot {
    public static let maximumLength = 1024

    /// Accepts what a folder picker produces and refuses everything else.
    ///
    /// Refusals are all fail-closed: a path that is empty, relative, oversized,
    /// carries a control character or a newline, does not exist, or is a file
    /// rather than a directory never becomes an environment. The returned value
    /// is standardized (`.` and `..` resolved, tilde expanded), so the stored
    /// record is the same folder written one way.
    public static func validated(_ raw: String, fileManager: FileManager = .default) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultageError.invalidInput("A local environment needs a folder.") }
        guard trimmed.utf8.count <= maximumLength else { throw VaultageError.invalidInput("That folder path is too long.") }
        guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
            throw VaultageError.invalidInput("A folder path cannot contain control characters.")
        }
        let expanded = (trimmed as NSString).expandingTildeInPath
        guard expanded.hasPrefix("/") else { throw VaultageError.invalidInput("Choose a folder by its full path.") }
        let standardized = URL(fileURLWithPath: expanded).standardizedFileURL.path
        guard standardized.hasPrefix("/"), standardized.utf8.count <= maximumLength else {
            throw VaultageError.invalidInput("That folder path could not be resolved.")
        }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: standardized, isDirectory: &isDirectory) else {
            throw VaultageError.invalidInput("That folder does not exist on this Mac.")
        }
        guard isDirectory.boolValue else { throw VaultageError.invalidInput("That path is a file. Choose a folder.") }
        return standardized
    }
}

public struct Environment: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public var projectID: UUID
    public var name: String
    /// BL-072. `local` or `cloud`; see `EnvironmentKind`.
    public var kind: EnvironmentKind
    /// The local project root, for a `local` environment only. Metadata, never
    /// shell input — see `EnvironmentRoot`. Always nil for a `cloud`
    /// environment, including one that was hand-edited to carry a path.
    public var rootPath: String?
    public var sensitivity: EnvironmentSensitivity
    public var createdAt: Date

    /// A root is kept only for a local environment; passing one for a cloud
    /// environment drops it rather than storing something the kind denies.
    public init(id: UUID = UUID(), projectID: UUID, name: String, kind: EnvironmentKind = .cloud, rootPath: String? = nil, sensitivity: EnvironmentSensitivity = .development, createdAt: Date = .now) {
        self.id = id
        self.projectID = projectID
        self.name = name
        self.kind = kind
        self.rootPath = kind == .local ? rootPath : nil
        self.sensitivity = sensitivity
        self.createdAt = createdAt
    }

    /// The only way to make a local environment from a human's folder choice:
    /// the path is validated as an existing directory first, so a local
    /// environment never records a folder that is not there.
    public static func local(id: UUID = UUID(), projectID: UUID, name: String, root: String, sensitivity: EnvironmentSensitivity = .development, createdAt: Date = .now, fileManager: FileManager = .default) throws -> Environment {
        Environment(id: id, projectID: projectID, name: name, kind: .local, rootPath: try EnvironmentRoot.validated(root, fileManager: fileManager), sensitivity: sensitivity, createdAt: createdAt)
    }

    /// The root to show, which exists only for a coherent local record.
    public var localRoot: String? { kind == .local ? rootPath : nil }

    /// True when the stored sensitivity says production or the name is
    /// "production" in any casing or surrounding whitespace.
    public var isProduction: Bool {
        sensitivity == .production
            || name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "production"
    }

    private enum CodingKeys: String, CodingKey { case id, projectID, name, kind, rootPath, sensitivity, createdAt }

    /// Schema 4 records have no `sensitivity`. They migrate to `development`,
    /// the least sensitive level, because an absent field is the day-one
    /// default rather than a corrupted one; a record named "production" still
    /// reports `isProduction`. A *present* but unrecognized value is handled by
    /// `EnvironmentSensitivity.init(from:)` and fails closed to `production`.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        projectID = try c.decode(UUID.self, forKey: .projectID)
        name = try c.decode(String.self, forKey: .name)
        sensitivity = try c.decodeIfPresent(EnvironmentSensitivity.self, forKey: .sensitivity) ?? .development
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        // Schema 9 addition. An absent `kind` is schema 8 or earlier and
        // becomes `cloud` (BL-072); so does an unrecognized value.
        let decodedKind = try c.decodeIfPresent(EnvironmentKind.self, forKey: .kind) ?? .cloud
        let decodedRoot = try c.decodeIfPresent(String.self, forKey: .rootPath)?.trimmingCharacters(in: .whitespacesAndNewlines)
        // A record that says `local` but carries no root is not a shape this
        // product can create. It decodes to `cloud` rather than to a card that
        // claims a local folder it does not have, and a `cloud` record that
        // carries a root drops it rather than keeping a field its kind denies.
        if decodedKind == .local, let decodedRoot, !decodedRoot.isEmpty {
            kind = .local
            rootPath = decodedRoot
        } else {
            kind = .cloud
            rootPath = nil
        }
    }
}

public struct VaultItem: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public var label: String
    public var provider: Provider?
    public var keychainAccount: String
    /// Opaque local revision; never a secret hash. Evidence for an older
    /// Keychain record cannot authorize a replacement credential.
    public var credentialVersion: UUID?
    /// BL-078. Which vault this item is filed in. Filing is metadata: it never
    /// widens or narrows what may be done with the value, and the broker
    /// resolves an item by id without reading this field.
    public var vaultID: UUID
    /// The folder inside that vault, or nil for the vault root.
    public var folderID: UUID?
    /// BL-079 / D24. What kind of item this is. Stored as its raw name so a
    /// build that does not understand a type re-encodes the record it read
    /// instead of flattening it; see `VaultItemType`.
    private var storedType: String
    /// BL-079. Every field of the item, in display order, including the primary
    /// one. A secret field carries its own opaque Keychain account; a
    /// non-secret field carries text and is ordinary metadata. The invariant
    /// the decoder and `VaultItemTypes.normalize` keep is that **at most one
    /// field's account is `keychainAccount`** — the primary, and the only one
    /// a connection, a binding, a grant or a runtime delivery ever reads.
    public var fields: [VaultItemField]
    /// BL-079. Sealed files belonging to this item: screenshots, certificates,
    /// key files. Each record here is metadata; the bytes live in the
    /// attachment store under `id`, sealed with the vault's content key.
    public var attachments: [VaultItemAttachment]
    public var createdAt: Date

    public var type: VaultItemType {
        get { VaultItemType(rawName: storedType) }
        set { storedType = newValue.rawName }
    }

    /// The field whose Keychain account is this item's account: the value the
    /// broker, the connections and the runtime path have always resolved.
    public var primaryField: VaultItemField? {
        fields.first { $0.isSecret && $0.keychainAccount == keychainAccount }
    }

    /// Whether a Keychain record exists under `keychainAccount` at all.
    ///
    /// False for a certificate item, whose payload is a sealed file and whose
    /// parsed subject, issuer and expiry are metadata. Such an item still owns
    /// an opaque `keychainAccount` so deletion reservations, request digests
    /// and reference counting keep their existing shape — but every disclosure
    /// path checks this first and refuses **before** prompting, rather than
    /// raising an OS prompt for a record that was never written.
    public var hasProtectedValue: Bool { primaryField != nil }

    /// Every secret field, in display order. Each is its own user-presence
    /// record under its own account.
    public var secretFields: [VaultItemField] { fields.filter { $0.isSecret && $0.keychainAccount != nil } }

    public init(
        id: UUID = UUID(),
        label: String,
        provider: Provider?,
        keychainAccount: String,
        credentialVersion: UUID? = UUID(),
        vaultID: UUID = Vault.defaultID,
        folderID: UUID? = nil,
        type: VaultItemType = .apiKey,
        fields: [VaultItemField]? = nil,
        attachments: [VaultItemAttachment] = [],
        createdAt: Date = .now
    ) {
        self.id = id; self.label = label; self.provider = provider; self.keychainAccount = keychainAccount; self.credentialVersion = credentialVersion; self.vaultID = vaultID; self.folderID = folderID; self.createdAt = createdAt
        self.storedType = type.rawName
        self.attachments = attachments
        // A caller that names no fields gets the one-field shape schema 12 had:
        // the primary, pointing at this item's account. Passing `[]` explicitly
        // is a different statement — an item with no scalar value at all — and
        // is honoured.
        self.fields = fields ?? [VaultItemField(id: id, key: type.migratedPrimaryKey, isSecret: true, keychainAccount: keychainAccount, credentialVersion: credentialVersion)]
    }

    private enum CodingKeys: String, CodingKey {
        case id, label, provider, keychainAccount, credentialVersion, vaultID, folderID, createdAt
        case storedType = "type"
        case fields, attachments
    }

    /// Schema 11 and earlier have no `vaultID`. Those items decode into the
    /// fixed default vault id, which `VaultOrganization.normalize` then makes
    /// real as the "Personal" vault — the BL-078 migration, expressed as a
    /// decoding default so it cannot be half applied. A `folderID` that names
    /// nothing, or a folder in another vault, is cleared by the same pass; an
    /// item is never dropped, because its Keychain record is real whatever the
    /// tree above it says.
    ///
    /// Schema 12 and earlier have no `type` and no `fields`: every item was one
    /// provider token under one account. Such a record decodes to an `apiKey`
    /// whose **single field is that same account** — the BL-079 migration,
    /// expressed the same way, as a decoding default. Nothing is moved, no
    /// account changes, and no Keychain record is touched: the old shape is
    /// simply written down as a one-element list.
    ///
    /// The distinction between an *absent* `fields` key and an explicitly empty
    /// one is load-bearing. Absent means "a record from before fields existed",
    /// and the primary is synthesized. Empty means "a schema-13 item that
    /// genuinely has no scalar value" — a certificate — and is left empty, so
    /// the migration cannot invent a primary field for a record that never had
    /// a Keychain value behind it.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        label = try c.decode(String.self, forKey: .label)
        provider = try c.decodeIfPresent(Provider.self, forKey: .provider)
        keychainAccount = try c.decode(String.self, forKey: .keychainAccount)
        credentialVersion = try c.decodeIfPresent(UUID.self, forKey: .credentialVersion)
        vaultID = try c.decodeIfPresent(UUID.self, forKey: .vaultID) ?? Vault.defaultID
        folderID = try c.decodeIfPresent(UUID.self, forKey: .folderID)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        storedType = try c.decodeIfPresent(String.self, forKey: .storedType) ?? VaultItemType.apiKey.rawName
        attachments = try c.decodeIfPresent([VaultItemAttachment].self, forKey: .attachments) ?? []
        if let decodedFields = try c.decodeIfPresent([VaultItemField].self, forKey: .fields) {
            fields = decodedFields
        } else {
            let migratedType = VaultItemType(rawName: storedType)
            fields = [VaultItemField(id: id, key: migratedType.migratedPrimaryKey, isSecret: true, keychainAccount: keychainAccount, credentialVersion: credentialVersion)]
        }
    }
}

/// A short-lived local deletion lease. It is persisted before an OS-controlled
/// Keychain deletion prompt, so another process cannot attach a connection or
/// runtime source authorization to a value that is being removed.
public struct VaultItemDeletionReservation: Codable, Hashable, Sendable {
    public let id: UUID
    public let vaultItemID: UUID
    public let keychainAccount: String
    public let credentialVersion: UUID?
    public let reservedAt: Date
    public init(id: UUID = UUID(), vaultItemID: UUID, keychainAccount: String, credentialVersion: UUID?, reservedAt: Date = .now) {
        self.id = id; self.vaultItemID = vaultItemID; self.keychainAccount = keychainAccount; self.credentialVersion = credentialVersion; self.reservedAt = reservedAt
    }
}

/// D44a (`blueprint/10-OWNER-DECISIONS.md` D44) — the documented region ids a
/// connection may name, per provider.
///
/// **Why this list is compiled here and not read from the catalog.**
/// `VaultageProviders` depends on `VaultageCore`, never the other way round, so
/// nothing in this module can see `CatalogProvider.regions`. It could not be an
/// injected dependency either: the repair below runs inside
/// `VaultageMetadata`'s decoder, which is handed a `metadata.json` and nothing
/// else. So the ids are compiled here, and
/// `ServiceCatalogContracts.regionDirectoryMatchesTheManifests` asserts — in
/// both directions, provider by provider and id by id — that this table is
/// byte-identical to `CatalogProvider.regions`' ids *and* to each adapter
/// manifest's `regionRoutes` keys. That is the same "mirror plus a self-test"
/// shape `OperationTrustClass` already uses against `CatalogTrustClass`, and it
/// is what stops the three from drifting apart.
///
/// Empty for every provider with one documented host, which is what
/// single-region honestly is. A connection whose provider is absent here can
/// only ever carry `nil`.
public enum ProviderRegionDirectory {
    /// Provider -> its documented region ids, **primary first**. The primary is
    /// the region the adapter was onboarded against and the one `nil` means;
    /// `ProviderRegionRouting.route(for:region:)` resolves `nil` to the
    /// manifest's `verifyRoute`, which is that same primary.
    public static let regionIDs: [Provider: [String]] = [
        .posthog: ["us", "eu"],
        .mailgun: ["us", "eu"],
        // SendGrid calls its default region "global", not "US"; the id follows
        // the provider's own word rather than a tidier one.
        .sendGrid: ["global", "eu"],
        // BL-112 wave 4. Make publishes six zone base URLs and no
        // zone-neutral one, and warns "Make sure to use the correct base URL
        // when running API calls otherwise your API requests will fail." The
        // ids are the zone subdomains Make itself prints, in the order its own
        // list prints them, so the primary is `eu1` — the zone whose URL Make
        // uses in the example on that page.
        .make: ["eu1", "eu2", "us1", "us2", "eu1-celonis", "us1-celonis"],
        // BL-112 wave 4. Segment documents one host per data residency region
        // and names them "US-based Workspaces" and "EU-based Workspaces"; the
        // US host is the one its own examples use, so it is the primary.
        .segment: ["us", "eu"]
    ]

    /// The documented ids for a provider, primary first. Empty means
    /// single-region.
    public static func documentedIDs(for provider: Provider) -> [String] { regionIDs[provider] ?? [] }

    /// The id of the provider's primary region, or `nil` for a single-region
    /// provider. `Connection.region == nil` always means this region.
    public static func primaryID(for provider: Provider) -> String? { documentedIDs(for: provider).first }

    /// Whether `region` is one of the provider's documented ids. `nil` is
    /// always acceptable and is *not* passed here.
    public static func isDocumented(_ region: String, for provider: Provider) -> Bool {
        documentedIDs(for: provider).contains(region)
    }

    /// The create-time check. `nil` passes; anything else must be a documented
    /// id for that provider.
    ///
    /// - Throws: `VaultageError.invalidInput` — a region outside the manifest is
    ///   refused, never silently defaulted to another host. It is the same
    ///   error `ProviderRegionRouting.route(for:region:)` throws for the same
    ///   reason, so the two halves of D44a refuse identically.
    @discardableResult
    public static func validated(_ region: String?, for provider: Provider) throws -> String? {
        guard let region else { return nil }
        guard isDocumented(region, for: provider) else {
            throw VaultageError.invalidInput("That region is not documented for this provider.")
        }
        return region
    }

    /// The decode-time repair. An undocumented id becomes `nil` — the primary
    /// region — rather than failing the load or reaching the route table.
    ///
    /// Repairing to `nil` is the safe direction and the only one available: the
    /// alternative, keeping the unknown id, hands `ProviderRegionRouting` a
    /// value it will refuse on every request, which turns one bad byte in
    /// `metadata.json` into a connection that can never be used again. `nil` is
    /// where the connection was before D44a shipped, and re-selecting a region
    /// is the connect panel's reconnect step.
    public static func repaired(_ region: String?, for provider: Provider) -> String? {
        guard let region, isDocumented(region, for: provider) else { return nil }
        return region
    }
}

/// BL-117 (D51) §7.2. Which providers carry a **tenant**, and what a tenant may
/// look like.
///
/// D44a's `region` is the precedent and the semantics are copied exactly: a
/// compiled directory in `VaultageCore` (which cannot import
/// `VaultageProviders`), a create-time check that refuses rather than silently
/// defaulting, and a decode-time repair that only ever narrows. What differs is
/// what the value *is*: a region selects between documented hosts, and a tenant
/// fills one constrained segment of a compiled **path**.
///
/// **The pattern is positional, and version 1's was not.** Version 1 proposed
/// `/^[0-9a-fA-F-]{36}$/`, which accepts thirty-six hyphens. That could not
/// introduce a `/`, a `?`, a `#`, a userinfo or a second host, so the security
/// property held — but a suite asserting "every GUID substitution produces the
/// expected host and path" would have passed while non-GUIDs also passed, which
/// is a test that cannot fail. The pattern below is the five positional groups
/// Microsoft's own GUID format has.
///
/// Microsoft also documents a **domain-name** tenant form — *"in GUID or
/// domain-name format"* (read 2026-09-13). It is not supported, and the connect
/// panel says GUID only: a domain name is a customer-controlled string in a URL
/// path, which is the shape R7 and the fifteen customer-host providers are
/// blocked on.
public enum ProviderTenantDirectory {

    /// The providers whose compiled routes carry a tenant variable. A closed
    /// set with one member, for the same reason `ProviderURLVariable` is a
    /// closed enum with one case: a second entry is a deliberate edit that
    /// lands under runbook §10 item 2 and gets its own pass.
    public static let tenantedProviders: Set<Provider> = [.azure]

    /// The positional GUID pattern, compiled once. `8-4-4-4-12` hexadecimal.
    public static let guidPattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

    /// Whether a provider takes a tenant at all.
    public static func isTenanted(_ provider: Provider) -> Bool { tenantedProviders.contains(provider) }

    /// Whether `tenant` is a well-formed GUID. Length is checked before the
    /// expression so a pathological input cannot reach the matcher.
    public static func isDocumented(_ tenant: String) -> Bool {
        tenant.utf8.count == 36 && tenant.range(of: guidPattern, options: .regularExpression) != nil
    }

    /// The create-time check. `nil` passes — a connection can exist before its
    /// tenant is chosen, exactly as one can exist before it is verified — and
    /// anything else must be a GUID on a provider that takes one.
    ///
    /// - Throws: `VaultageError.invalidInput` — a malformed tenant is refused,
    ///   never silently dropped, and a tenant on a provider that has none is
    ///   refused too, because it would be a value nothing reads.
    @discardableResult
    public static func validated(_ tenant: String?, for provider: Provider) throws -> String? {
        guard let tenant else { return nil }
        guard isTenanted(provider) else {
            throw VaultageError.invalidInput("That provider does not take a tenant.")
        }
        guard isDocumented(tenant) else {
            throw VaultageError.invalidInput("A tenant ID must be a GUID, in the 8-4-4-4-12 form Microsoft documents.")
        }
        return tenant
    }

    /// The decode-time repair, in the safe direction and the only one
    /// available. A malformed tenant becomes `nil`, which is where every
    /// connection written before this schema already is; keeping it would hand
    /// the route resolver a value it refuses on every request, turning one bad
    /// byte in `metadata.json` into a connection that can never be used again.
    /// Re-entering the tenant is the connect panel's reconnect step.
    public static func repaired(_ tenant: String?, for provider: Provider) -> String? {
        guard let tenant, isTenanted(provider), isDocumented(tenant) else { return nil }
        return tenant
    }
}

public struct Connection: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public var provider: Provider
    public var label: String
    public var vaultItemID: UUID
    public var state: ConnectionState
    public var lastVerifiedAt: Date?
    public var verification: ConnectionVerification?
    /// A plan pause preserves the connection and every binding, while ensuring
    /// no credential for that connection can be read by the broker.
    public var pauseReason: ConnectionPauseReason?
    /// D44a / owner decision D44. Which of the provider's documented regions
    /// this connection reaches, or `nil` for the provider's primary region.
    /// `nil` is what every connection written before schema 18 decodes to, and
    /// a `nil` connection behaves byte-for-byte as it did before this field
    /// existed: `ProviderRegionRouting.route(for:region: nil)` is the
    /// manifest's `verifyRoute`, which is the primary region's route.
    ///
    /// **`fileprivate(set)` on purpose.** A region change re-points every route
    /// for this connection at a different host, and the capability evidence the
    /// human saw was obtained against the *old* host — it attests nothing at the
    /// new one. So the setter is unreachable outside this file, and the only way
    /// a region reaches an existing connection is `reconnect(to:vaultItemID:)`
    /// below, which is the connect panel's reconnect path and which clears that
    /// evidence as it goes. An ordinary edit — renaming a connection, pausing
    /// it, re-verifying it — cannot change the region, because it has no way to
    /// write the field at all.
    public fileprivate(set) var region: String?
    /// BL-117 (D51) §7.2. Which **tenant** this connection operates against, or
    /// `nil` for a provider that takes none — which is what every connection
    /// written before schema 24 decodes to, and what every non-Azure connection
    /// is.
    ///
    /// It is a **connection** field and not a credential field, and that
    /// distinction is the whole reason it exists. §1.3 asked for three values
    /// against `.clientIDAndSecret` custody, whose fields are `identifier` and
    /// `secret` — so the pairing contract could not check the third and
    /// `ProviderCredentialKind.kind(ofMode:)` would still render a two-field
    /// panel. The tenant id is also not secret: it is in the issuer of every
    /// token Microsoft mints and it is what the connect panel must be able to
    /// show.
    ///
    /// **`fileprivate(set)` for exactly D44a's reason**, one level sharper. A
    /// tenant change re-points the token route at a different directory, and
    /// the capability evidence the human saw was obtained against the *old*
    /// one — it attests nothing in the new tenant, where the application
    /// registration may not even exist. So the setter is unreachable outside
    /// this file and the only way a tenant reaches an existing connection is
    /// `reconnect(to:tenant:vaultItemID:)` below, which clears that evidence as
    /// it goes.
    public fileprivate(set) var tenant: String?
    public init(id: UUID = UUID(), provider: Provider, label: String, vaultItemID: UUID, state: ConnectionState = .unverified, lastVerifiedAt: Date? = nil, verification: ConnectionVerification? = nil, pauseReason: ConnectionPauseReason? = nil, region: String? = nil, tenant: String? = nil) { self.id = id; self.provider = provider; self.label = label; self.vaultItemID = vaultItemID; self.state = state; self.lastVerifiedAt = lastVerifiedAt; self.verification = verification; self.pauseReason = pauseReason; self.region = region; self.tenant = tenant }

    /// D44a. **The connect panel's reconnect path, and the only way a region
    /// changes on an existing connection.**
    ///
    /// The human re-opens the connect panel for a connection that already
    /// exists, picks a region from `CatalogProvider.regions`, and supplies the
    /// credential for that region — which is a *different* credential: a
    /// PostHog Cloud EU personal API key is not a Cloud US one, and neither
    /// account can see the other. So this takes the vault item that credential
    /// was stored as, and resets the connection to unverified with no evidence:
    ///
    /// - `state` becomes `.unverified`, `lastVerifiedAt` and `verification`
    ///   become `nil`. Evidence obtained against the old host cannot attest the
    ///   new one, and `ConnectionVerification.permits` would otherwise keep
    ///   authorizing operations for up to fifteen minutes against a host the
    ///   credential was never checked at.
    /// - The caller then runs the ordinary verify, which now resolves through
    ///   `ProviderRegionRouting.route(for:region:)` and reaches the new host.
    ///
    /// `pauseReason` is deliberately untouched: a Free-plan pause is a plan
    /// fact about the connection, not about which host it talks to.
    ///
    /// - Throws: `VaultageError.invalidInput` when `region` is not one of the
    ///   provider's documented ids.
    ///
    /// BL-117 §7.2 adds `tenant` on the same path and with the same rule. It is
    /// defaulted to `nil` so every existing caller compiles unchanged **and
    /// clears the tenant**, which is the correct direction: a reconnect that
    /// does not name a tenant is a reconnect to no tenant, and an Azure
    /// connection that lost its tenant refuses its routes rather than reaching
    /// the wrong directory.
    public mutating func reconnect(to region: String?, tenant: String? = nil, vaultItemID: UUID) throws {
        self.region = try ProviderRegionDirectory.validated(region, for: provider)
        self.tenant = try ProviderTenantDirectory.validated(tenant, for: provider)
        self.vaultItemID = vaultItemID
        self.state = .unverified
        self.lastVerifiedAt = nil
        self.verification = nil
    }
}

/// D44a's idempotent repair pass, in the same place and for the same reason as
/// BL-078's, BL-092's, BL-094's and BL-099's: it runs on every decode and on
/// every hand-built `VaultageMetadata`, it only ever narrows, and it can be run
/// twice with the same result.
///
/// A connection whose stored region is not one of its provider's documented ids
/// — a hand-edited file, a file written by a build that knew a region this one
/// does not, or a provider that has since dropped a region — is repaired to
/// `nil`, the primary region, and the repair is noted once per process on
/// stderr. It is never a load failure: the region decides which documented host
/// a read is sent to, not whether anything is authorized, so an unreadable
/// `metadata.json` would be a far worse answer than a connection that fell back
/// to the host it used before D44a.
/// BL-117 (D51) §7.2's repair pass, in the same place and for the same reasons
/// as D44a's above: it runs on every decode and on every hand-built
/// `VaultageMetadata`, it only ever narrows, and it can be run twice with the
/// same result.
///
/// A connection whose stored tenant is not a well-formed GUID — or which
/// carries one at all on a provider that takes none — is repaired to `nil`. It
/// is never a load failure: the tenant decides which directory one compiled
/// path reaches, not whether anything is authorized, and an unreadable
/// `metadata.json` would be a far worse answer than an Azure connection that
/// has to have its tenant re-entered on the connect panel.
public enum ConnectionTenants {
    public static func normalize(_ state: inout VaultageMetadata) {
        for index in state.connections.indices {
            let stored = state.connections[index].tenant
            let repaired = ProviderTenantDirectory.repaired(stored, for: state.connections[index].provider)
            guard repaired != stored else { continue }
            state.connections[index].tenant = repaired
        }
    }
}

public enum ConnectionRegions {
    public static func normalize(_ state: inout VaultageMetadata) {
        for index in state.connections.indices {
            let stored = state.connections[index].region
            let repaired = ProviderRegionDirectory.repaired(stored, for: state.connections[index].provider)
            guard repaired != stored else { continue }
            state.connections[index].region = repaired
            diagnostics.note(provider: state.connections[index].provider, refused: stored)
        }
    }

    /// What the repair pass has had to fix in this process. Value-free: a
    /// provider slug from a closed enum, and a **sanitized** rendering of the
    /// refused id. Exposed so a self-test can assert the repair was noticed
    /// rather than silently performed.
    public static let diagnostics = RegionRepairDiagnostics()

    public final class RegionRepairDiagnostics: @unchecked Sendable {
        private let lock = NSLock()
        private var repairs: [String] = []
        private var emitted = false

        fileprivate init() {}

        /// The bound exists because `metadata.json` is a local file a human can
        /// edit: a file naming ten thousand bad regions must not become ten
        /// thousand retained strings.
        public static let maximumRetained = 16

        /// The notes this process has recorded, oldest first, bounded.
        public var recorded: [String] {
            lock.lock(); defer { lock.unlock() }
            return repairs
        }

        public var count: Int {
            lock.lock(); defer { lock.unlock() }
            return repairs.count
        }

        /// Self-tests only: the pass is idempotent, so clearing what it noticed
        /// changes nothing about the data.
        public func reset() {
            lock.lock(); defer { lock.unlock() }
            repairs.removeAll()
            emitted = false
        }

        fileprivate func note(provider: Provider, refused: String?) {
            let note = "Vaultage repaired a connection's region to the provider's primary region: \(provider.rawValue) does not document \(Self.sanitized(refused))."
            lock.lock()
            if repairs.count < Self.maximumRetained { repairs.append(note) }
            let first = !emitted
            emitted = true
            lock.unlock()
            // One line, once, exactly as `KeychainAccessGroup`'s fallback note:
            // a repair is worth saying, and a corrupted file full of them is not
            // worth a thousand lines of stderr.
            guard first else { return }
            FileHandle.standardError.write(Data("\(note)\n".utf8))
        }

        /// The refused id came out of a local file and is therefore
        /// attacker-influenced text. It is never written to stderr as-is:
        /// anything outside the shape a region id can have becomes a fixed
        /// word, so a region field cannot inject a newline, a terminal escape
        /// or a thousand characters into a diagnostic.
        static func sanitized(_ value: String?) -> String {
            guard let value else { return "an absent region" }
            guard value.utf8.count <= 32,
                  value.range(of: "^[a-z0-9-]+$", options: .regularExpression) != nil else {
                return "that region id"
            }
            return "\"\(value)\""
        }
    }
}

public enum ConnectionState: String, Codable, Sendable { case unverified, verified, failed }
public enum ConnectionPauseReason: String, Codable, Sendable { case freePlanLimit }

/// Bounded, value-free server evidence. `scopeStatus` deliberately retains an
/// unknown state: a capability probe must never be presented as full provider
/// scope introspection.
public struct ConnectionVerification: Codable, Hashable, Sendable {
    public static let maxAge: TimeInterval = 15 * 60
    public let credentialVersion: UUID
    public let keychainAccount: String
    public let providerContractRevision: String
    public let verifiedAt: Date
    public let providerExpiresAt: Date?
    public let principalID: String?
    public let principalLabel: String?
    public let scopeStatus: ScopeStatus
    public let capabilities: Set<Operation>
    public init(credentialVersion: UUID, keychainAccount: String, providerContractRevision: String, verifiedAt: Date = .now, providerExpiresAt: Date? = nil, principalID: String? = nil, principalLabel: String? = nil, scopeStatus: ScopeStatus = .unknown, capabilities: Set<Operation>) { self.credentialVersion = credentialVersion; self.keychainAccount = keychainAccount; self.providerContractRevision = providerContractRevision; self.verifiedAt = verifiedAt; self.providerExpiresAt = providerExpiresAt; self.principalID = principalID; self.principalLabel = principalLabel; self.scopeStatus = scopeStatus; self.capabilities = capabilities }
    /// - Parameter freshUntil: D19. The instant this evidence stops counting as
    ///   current, when something other than the default 15-minute rule decides
    ///   it. Today the only such thing is an active auto-allow grant that covers
    ///   the action: while the human's grant runs, the verification they had
    ///   when they approved it stays current for the grant's remaining
    ///   duration. A ceiling can only ever *extend* the default — it is combined
    ///   with `verifiedAt + maxAge` by taking the later of the two — so no
    ///   caller can use this parameter to shorten the base rule or to revive
    ///   evidence the other checks below already refuse.
    public func permits(_ operation: Operation, item: VaultItem, provider: Provider, at now: Date, freshUntil: Date? = nil) -> Bool {
        // A mutation is attested by the provider's own read probe, never by a
        // separate write probe: engineering contracts §7 is explicit that "list
        // success does not prove Write permission — the provider enforces Write
        // on the actual PUT", and Vaultage will not perform a speculative write
        // to find out. So a connection verified for a provider's read carries
        // the *capability* evidence for that provider's mutations, and the
        // provider's own 403 is what refuses one the token may not do.
        //
        // BL-091 generalises the single hand-written `cloudflareWorkerSecretPut`
        // exception this line used to carry; that exact case still passes,
        // because `cloudflare.verify_token` is a read of the same provider.
        // Nothing else about the evidence check moves: the binding still has to
        // allow the operation, the approval class is still decided by
        // `ApprovalRequirement`, and every other condition below is unchanged.
        // The pass-through covers every *resource* operation: the mutations,
        // and the two kinds of read whose URL carries a bound identifier and
        // which therefore are not part of the verify probe's own route table.
        // A read that has its own compiled verify route is still attested
        // directly, and nothing widens what a binding allows.
        //
        // PW4-M2, from the independent pass over wave 4. `capabilities` is now
        // **evidence** rather than the whole gate: it carries the operations
        // the verify request actually exercised, which for a provider whose
        // verify route is not one of its operations' routes is none of them.
        // So the pass-through above is stated once, for every operation of the
        // provider this evidence was taken for, anchored on the evidence being
        // a genuine current verification of *this* provider under the compiled
        // contract revision — evidence naming another provider's capability
        // still carries nothing, and every other condition below is unchanged.
        // Recording all thirty compiled operations to make this line pass was
        // the untruth the pass found; widening it here loses no check, because
        // the set it read was `Set(manifest.operations.keys)` — the same set
        // this clause now names — for every provider in the table family.
        let needsResourceEvidence = operation.taxonomy.kind != .read || operation.isResourceOperation
        let carriedByThisProvidersVerification = operation.provider == provider
            && providerContractRevision == Self.contractRevision(for: provider)
        let capabilityAttested = capabilities.contains(operation)
            || carriedByThisProvidersVerification
            || (needsResourceEvidence
                && operation.provider == provider
                && capabilities.contains { $0.provider == provider && $0.taxonomy.kind == .read })
        let defaultStaleAt = verifiedAt.addingTimeInterval(Self.maxAge)
        let staleAt = freshUntil.map { $0.timeIntervalSince1970.isFinite ? max(defaultStaleAt, $0) : defaultStaleAt } ?? defaultStaleAt
        guard now.timeIntervalSince1970.isFinite, verifiedAt.timeIntervalSince1970.isFinite,
              now >= verifiedAt,
              item.provider == provider, let version = item.credentialVersion,
              credentialVersion == version, keychainAccount == item.keychainAccount,
              staleAt >= now,
              providerExpiresAt.map({ $0.timeIntervalSince1970.isFinite && $0 > now }) ?? true,
              capabilityAttested else { return false }
        return true
    }
    public static func contractRevision(for provider: Provider) -> String {
        switch provider {
        // BL-128. Re-scoped: the table adapter verifies against `GET /user`
        // and compiles the rate-limit and repository reads, so evidence written
        // by the hand-written v1 contract cannot authorize the new read.
        case .github: "github.user-rate-limit-repos.v2"
        case .openAI: "openai.models.v1"
        case .cloudflare: "cloudflare.token-verify.v1"
        // BL-088 wave 1. The revision names the exact routes the adapter
        // verified against, so evidence written by an older contract cannot
        // authorize an operation a newer one re-scoped.
        case .anthropic: "anthropic.models.v1"
        case .googleGemini: "google-gemini.models.v1"
        case .vercel: "vercel.user-projects.v1"
        case .netlify: "netlify.user-sites.v1"
        case .supabase: "supabase.organizations-projects.v1"
        case .neon: "neon.user-projects.v1"
        case .resend: "resend.domains.v1"
        case .stripe: "stripe.balance.v1"
        case .sentry: "sentry.organizations.v1"
        // BL-089 wave 2.
        case .railway: "railway.me-projects.v1"
        case .render: "render.owners-services-projects.v2"
        case .clerk: "clerk.instance-domains.v1"
        case .posthog: "posthog.organizations.v1"
        case .slack: "slack.team-info.v1"
        case .discord: "discord.user-guilds.v1"
        case .sendGrid: "sendgrid.scopes.v1"
        case .twilio: "twilio.accounts.v1"
        case .mailgun: "mailgun.domains.v1"
        case .postmark: "postmark.server.v1"
        case .xai: "xai.api-key-models.v1"
        case .mistral: "mistral.models.v1"
        case .deepSeek: "deepseek.models.v1"
        case .cohere: "cohere.models.v1"
        case .digitalOcean: "digitalocean.account-projects.v1"
        // BL-111 wave 3.
        case .apify: "apify.user-actors.v1"
        case .gitlab: "gitlab.user-groups.v1"
        // BL-112 wave 4.
        case .make: "make.organizations.v1"
        case .paddle: "paddle.event-types-products.v1"
        case .segment: "segment.workspace.v1"
        case .workos: "workos.organizations.v1"
        // BL-112's wave-5 follow-up. One route each, and the revision names it.
        case .bitbucket: "bitbucket.workspaces.v1"
        case .lemonSqueezy: "lemon-squeezy.stores.v1"
        case .planetScale: "planetscale.organizations.v1"
        // BL-116 wave 5. One route each, and the revision names it; Doppler's
        // names both, because its verify route is not its operation's.
        case .glide: "glide.tables.v2"
        case .hostingerHorizons: "hostinger-horizons.websites.v1"
        case .v0: "v0.user-scopes.v1"
        case .doppler: "doppler.me-projects.v3"
        // The routes this contract covers: STS `GetCallerIdentity` at the
        // documented API version, signed with SigV4. A later slot that adds a
        // second AWS read or moves the signing scheme moves this string, so
        // older evidence cannot authorize a re-scoped operation.
        case .aws: "aws.sts-get-caller-identity.2011-06-15"
        // The routes this contract covers are **two**: the client-credentials
        // token exchange on `login.microsoftonline.com` and the Graph v1.0
        // organization read. The revision names the Graph version because that
        // is the one whose reply shape a projection depends on; the token
        // endpoint's own version (`oauth2/v2.0`) is in the route.
        case .azure: "azure.graph-organization.v1.0"
        // Two routes again: the service-account JWT exchange at
        // `oauth2.googleapis.com` and Cloud Resource Manager's **v1** project
        // list. The revision names v1 because that is the reply shape the
        // projection depends on — Google documents a v3 `projects:search` whose
        // envelope and field names differ (`displayName` rather than `name`),
        // and moving to it is a re-scoped operation that must move this string.
        case .googleCloud: "google-cloud.cloudresourcemanager-projects.v1"
        }
    }
}
public enum ScopeStatus: String, Codable, Sendable { case unknown, capabilityOnly, known }

public struct Binding: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public var projectID: UUID
    public var environmentID: UUID
    public var connectionID: UUID
    public var allowedOperations: Set<Operation>
    /// Immutable, non-secret deployment destination. Nil keeps older/read-only
    /// bindings compatible with the schema.
    public var cloudflareWorkerDestination: CloudflareWorkerDestination?
    /// BL-091. The immutable, non-secret provider container this binding is
    /// scoped to — a Cloudflare zone, a Cloudflare account and Worker script, a
    /// Vercel project. The human chooses it when they make the binding; an
    /// agent can never supply one and never change one, which is what makes
    /// "create a DNS record" mean "in this zone" rather than "in any zone this
    /// token can reach". Nil for every read-only binding that existed before
    /// this ticket, and a resource operation whose binding has no scope — or a
    /// scope of the wrong kind — is refused.
    public var resourceScope: ProviderResourceScope?
    public init(id: UUID = UUID(), projectID: UUID, environmentID: UUID, connectionID: UUID, allowedOperations: Set<Operation>, cloudflareWorkerDestination: CloudflareWorkerDestination? = nil, resourceScope: ProviderResourceScope? = nil) { self.id = id; self.projectID = projectID; self.environmentID = environmentID; self.connectionID = connectionID; self.allowedOperations = allowedOperations; self.cloudflareWorkerDestination = cloudflareWorkerDestination; self.resourceScope = resourceScope }
}

public enum CloudflareDeploymentMode: String, Codable, Sendable { case immediateScriptUpdate }
public enum CloudflareDestinationClass: String, Codable, CaseIterable, Sendable { case development, staging, production, unknown }
public struct CloudflareWorkerDestination: Codable, Hashable, Sendable {
    public let accountID: String
    public let scriptName: String
    public let deploymentMode: CloudflareDeploymentMode
    public let destinationClass: CloudflareDestinationClass
    public init(accountID: String, scriptName: String, deploymentMode: CloudflareDeploymentMode = .immediateScriptUpdate, destinationClass: CloudflareDestinationClass) { self.accountID = accountID; self.scriptName = scriptName; self.deploymentMode = deploymentMode; self.destinationClass = destinationClass }
}

/// An explicit local permission for one vault source item to feed one exact
/// runtime binding. It contains no credential material.
public struct RuntimeSourceAuthorization: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public let sourceVaultItemID: UUID
    public let bindingID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public init(id: UUID = UUID(), sourceVaultItemID: UUID, bindingID: UUID, projectID: UUID, environmentID: UUID) { self.id = id; self.sourceVaultItemID = sourceVaultItemID; self.bindingID = bindingID; self.projectID = projectID; self.environmentID = environmentID }
}

/// An explicit local permission for one vault item to be delivered into a child
/// process, under one exact variable name, for one exact project and
/// environment. It contains no credential material.
///
/// This is deliberately not `RuntimeSourceAuthorization`: that record authorizes
/// a source for a provider *binding*, and local runtime delivery has no provider
/// connection. Binding the variable name here is what stops an approved
/// production database password from arriving as `OPENAI_API_KEY`.
public struct RuntimeInjectionAuthorization: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public let vaultItemID: UUID
    public let projectID: UUID
    public let environmentID: UUID
    public let variableName: String
    public let createdAt: Date

    public init(id: UUID = UUID(), vaultItemID: UUID, projectID: UUID, environmentID: UUID, variableName: String, createdAt: Date = .now) {
        self.id = id
        self.vaultItemID = vaultItemID
        self.projectID = projectID
        self.environmentID = environmentID
        self.variableName = variableName
        self.createdAt = createdAt
    }
}

public enum AuditDecision: String, Codable, Sendable {
    case pending, approved, denied, blocked, executed, failed, resultUnknown
    /// Local runtime delivery is a separate, higher-exposure approval class, so
    /// it has its own terminal decisions and is never reported as `executed`.
    case runtimeDelivered, runtimeDenied
    /// BL-062. Human-only disclosure is a third approval class: no agent, no
    /// binding and no provider is involved, and the destination is a human's
    /// screen or clipboard. It therefore has its own terminal decisions, and is
    /// never reported as `executed` or as a runtime delivery.
    case humanRevealed, humanCopied, humanDenied

    /// A terminal decision closes one invocation. The durable receipt log writes
    /// at most one of these per correlation ID, so an invocation can never carry
    /// two contradicting outcomes.
    public var isTerminal: Bool {
        switch self {
        case .pending, .approved: false
        case .denied, .blocked, .executed, .failed, .resultUnknown, .runtimeDelivered, .runtimeDenied, .humanRevealed, .humanCopied, .humanDenied: true
        }
    }
}
public struct AuditEvent: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    public let at: Date
    public let projectID: UUID?
    public let environmentID: UUID?
    public let connectionID: UUID?
    public let operation: String
    public let decision: AuditDecision
    public let result: String
    /// BL-099 §4.6. The phone that decided, when it was not this Mac. Optional
    /// so every event written before this ticket decodes unchanged, and an
    /// identifier plus the **local pin's** name rather than the roster's.
    public let decidingDeviceID: String?
    public let decidingDeviceName: String?
    public init(id: UUID = UUID(), at: Date = .now, projectID: UUID? = nil, environmentID: UUID? = nil, connectionID: UUID? = nil, operation: String, decision: AuditDecision, result: String, decidingDeviceID: String? = nil, decidingDeviceName: String? = nil) { self.id = id; self.at = at; self.projectID = projectID; self.environmentID = environmentID; self.connectionID = connectionID; self.operation = operation; self.decision = decision; self.result = result; self.decidingDeviceID = decidingDeviceID; self.decidingDeviceName = decidingDeviceName }
}

public struct VaultageMetadata: Codable, Sendable {
    /// Schema 22 (BL-099 §3.7, DB-H7 item 3) adds `remoteMirroringSetting`: the
    /// owner's "Approve on my phone" switch and the one-screen consent that has
    /// to precede it, moved out of this Mac's `UserDefaults` — where the
    /// UI-lane evidence recorded it living, with the screen saying so —
    /// because a copy the broker does not read is a copy that can disagree
    /// with the one that matters (`blueprint/evidence/ui-lane-remote-approval-views-2026-09-13.md`
    /// §3).
    ///
    /// **Why 22 and not 20.** `blueprint/SCHEMA-LEDGER.md` (BL-097 ninth pass,
    /// DB9-M2) already reserves 20 for BL-099's own pairing-pins/DSRL work and
    /// 21 for BL-100 slice A, both still **pending** — neither has landed a
    /// build that enforces either number. The ledger's own invariant is that a
    /// new claim must collide with **no pending claim**, so this field's bump
    /// takes the next number the ledger names as free: **22**. The ledger's own
    /// text anticipates landing ahead of a lower pending claim by name ("a lane
    /// that has claimed 22 does not fail the build for everyone until 22
    /// ships").
    ///
    /// It moves for the same DB-H36 reason 17 through 19 did: `MetadataStore`
    /// has no migration ladder, so a schema-19 build that accepted this file
    /// would decode it with a synthesized decoder that silently discards
    /// `remoteMirroringSetting` and writes it back — an owner who turned the
    /// switch on would find it silently off again with no acknowledgement
    /// screen ever shown a second time, or worse, a build that initialized the
    /// field to a **default of "Always"** rather than "not yet consented" would
    /// start mirroring requests nobody agreed to publish. At 22 a 19 build
    /// refuses the file with "Unsupported local metadata version" instead,
    /// which is what `metadataAtSchema22IsRefusedByASchema19Build` asserts —
    /// **19, not 21**: nothing ever shipped a build with `supportedSchemaVersion`
    /// fixed at 20 or 21, both remaining pending reservations with no
    /// independent data shape, so the true immediately-preceding **landed**
    /// state is 19. The number is recorded in `blueprint/SCHEMA-LEDGER.md`,
    /// which is the file the custody plan names as authoritative (§9.3).
    ///
    /// Every earlier file migrates by decoding default: an absent
    /// `remoteMirroringSetting` is `RemoteMirroringSetting()`, whose `consent`
    /// is `nil` and whose `effectivePosition` is therefore `.off` regardless of
    /// `chosenPosition` — the fail-closed state in which nothing is ever
    /// published. **There is no repair pass**, unlike D44a's region or
    /// BL-099's own pins: those reason about a stored value against something
    /// external (a provider's documented regions, a signature); this field's
    /// only unsafe state is "present but not consented", and the type itself
    /// makes that state unreachable — `effectivePosition` and
    /// `needsConsentScreen` both gate on `consent` before they look at
    /// `chosenPosition`. A hand-edited file that sets `chosenPosition` to
    /// `"always"` with no `consent` object still mirrors nothing.
    ///
    /// Living here rather than in `UserDefaults` also settles the two
    /// persistence questions D38 and the custody plan ask of every record:
    /// this field now shares `metadata.json`'s reset boundary, so it survives
    /// a reinstall of the app (the file lives under Application Support, which
    /// a reinstalled bundle does not touch) but not a reset of the metadata
    /// store (deleting `metadata.json` deletes the acknowledgement along with
    /// everything else it decodes default from) — `UserDefaults`, keyed by
    /// bundle identifier, answered both questions differently and answered
    /// them alone.
    ///
    /// Schema 19 (D44c, owner decision D44) adds `valueSweptAt` to
    /// `ProvisionedResource`: when the protected Keychain value behind a
    /// revoked provisioned token was deleted.
    ///
    /// It moves for the same DB-H36 reason 18 did, and the loss it prevents is
    /// specific. A schema-18 build that accepted this file would discard
    /// `valueSweptAt` on write-back, which flips a swept record into the
    /// *"revoked, but the local value could not be deleted"* state — the one
    /// state that tells the owner there is still something on this Mac to clean
    /// up. That is a false alarm rather than a false all-clear, which is the
    /// safer direction of the two, but it is still the product lying about
    /// custody, and BL-074's whole discipline is that it does not.
    ///
    /// Every earlier file migrates by decoding default to `nil`, which is the
    /// truthful state for a record written by a build that never swept
    /// anything: the value it created is still there. The field is only ever
    /// written by `revokeProviderResource`, after the provider confirms and
    /// after the Keychain delete returns, and no repair pass invents one — a
    /// stamp that claimed a deletion nobody performed would be exactly the
    /// false success state the ticket forbids.
    ///
    /// Schema 18 (D44a, owner decision D44) adds `region` to `Connection`.
    ///
    /// **The number had to move, for exactly the reason §12 item 9 / DB-H36
    /// gives.** `MetadataStore` has no migration ladder; the number's only
    /// consumer is `guard value.schemaVersion <= VaultageMetadata.schemaVersion`.
    /// Until it moves, a schema-17 build **accepts** a file written by this one,
    /// decodes it with a synthesized decoder that silently discards unknown
    /// keys, and writes it back — dropping the region from every connection that
    /// has one. That is not a cosmetic loss: a PostHog Cloud EU connection
    /// silently becomes a Cloud US connection, whose next verify reaches a host
    /// the owner never chose and whose credential that host has never seen. At
    /// 18 a 17 build refuses the file with "Unsupported local metadata version"
    /// instead.
    ///
    /// Every earlier file migrates by decoding default: `region` absent is
    /// `nil`, which is the provider's primary region — exactly where every
    /// connection was before this ticket, and what
    /// `aConnectionWithoutARegionIsUnchanged` asserts byte-for-byte.
    /// `ConnectionRegions.normalize` is the idempotent repair pass, run on every
    /// decode and on every hand-built value, and it only ever narrows: an id
    /// this build does not document becomes `nil` plus one diagnostic line.
    ///
    /// Schema 17 (BL-099 / BL-095, §2.4 and §2.6) adds the remote-approval
    /// device records: `devicePairings` — the pin written by the mutual pairing
    /// ceremony, which is where §4.6's `coveringDigest` device section reads the
    /// pinned thumbprint and `pinGeneration` from, and why the pins live here
    /// rather than in a side store (Q17 item 2) — plus `deviceRevocations`, the
    /// verified device-signed revocation list, the two **never-cleared** sets
    /// `everRevokedDeviceIDs` and `everRevokedKeyThumbprints`, and
    /// `revocationSerialWatermarks`, and §4.4's durable
    /// `remoteDecisionReplays`.
    ///
    /// **The number had to move, and 16 would have been a no-op** (§12 item 9,
    /// DB-H36). `MetadataStore` has no migration ladder; the number's only
    /// consumer is `guard value.schemaVersion <= VaultageMetadata.schemaVersion`
    /// (`MetadataStore.swift:105`). Until it moves, an older build **accepts**
    /// the new file, decodes it with a synthesized decoder that silently
    /// discards unknown keys, and writes it back — deleting every pin record and
    /// every device stamp. At 17 a 16 build refuses it with "Unsupported local
    /// metadata version", which is what
    /// `metadataAtSchema17IsRefusedByASchema16Build` asserts. Schema 16 was
    /// BL-094's own bump (`05df972`), so gating on 16 would have been a test
    /// asserting a constant equal to itself.
    ///
    /// Every earlier file migrates by decoding default: no pins, no revocations,
    /// two empty sets and no watermarks — the fail-closed state, in which no
    /// device is paired, so nothing can be decided remotely at all.
    ///
    /// Schema 16 (BL-094 / D36) adds `deployedCredentials`, the
    /// deployed-credential ledger, and `rotations`, the overlap-rotation state
    /// machine's persisted records. Every earlier file migrates by decoding
    /// default to an empty ledger and no rotations, which is the truthful
    /// state: a build that could not deliver a credential into a provider's
    /// secret store never delivered one. Both are repaired on every decode by
    /// `DeployedCredentialLedger.normalize` and `CredentialRotationStore`, and
    /// both only ever narrow. Neither authorizes anything: a delivery, a
    /// verification and a rotation each re-resolve the binding, the bound
    /// scope and the source authorization from scratch.
    ///
    /// Schema 15 (BL-092) adds `resources`, the cross-provider inventory, and
    /// `inventoryRefreshes`, its on-demand refresh ledger. Every earlier record
    /// migrates by decoding default to an empty inventory, which is the
    /// truthful state: a build that could not cache a resource never cached
    /// one. Both are caches — `ResourceInventory.normalize` repairs them on
    /// every decode and only ever removes — so neither can make the metadata
    /// file unreadable and neither can widen what anything is allowed to do.
    ///
    /// Schema 14 (BL-091) adds `resourceMutationKeys`, the local idempotency
    /// ledger, and `resourceScope` inside a `Binding`. Every earlier record
    /// migrates by decoding default: an absent ledger is an empty one, and an
    /// absent scope is a binding that cannot run a resource operation at all.
    ///
    /// Schema 13 (BL-079) adds `type`, `fields` and `attachments` to a vault
    /// item. Every earlier record migrates by decoding default: see
    /// `VaultItem.init(from:)`.
    ///
    /// Schema 23 (**BL-100 slice A**, `13-MULTI-DEVICE-CUSTODY.md` §9.3) adds
    /// `minimumAppBuild` — the marker written when this Mac takes custody of a
    /// sealed store, and the second of §9.3's two downgrade guards. The schema
    /// guard covers `metadata.json`; the marker covers the **sealed store**, and
    /// is checked immediately after the metadata file opens. **A build that
    /// passes one and fails the other must not half-open**: it refuses the whole
    /// store with one message naming which check failed.
    ///
    /// The number is **read from `blueprint/SCHEMA-LEDGER.md` at the moment this
    /// work lands** rather than carried in prose: versions 2 through 8 of the
    /// custody plan each wrote a literal and each was overtaken, and D44a took
    /// 18 and D44c took 19 inside a day. 20 and 21 are **void** — a pending
    /// claim below the shipped constant can never be spent, because
    /// `MetadataStore`'s guard makes a new shape at a passed number unreachable.
    ///
    /// The same number versions `DurableReceipt`'s **record-shaped variant**
    /// (vault id, `wireID`, revision, no label), which slice A owes §7.1's
    /// discard receipt and which is absent from every receipt written before it.
    ///
    /// **24 is BL-117's Azure slot**, claimed and spent in the same pass: it
    /// carries `Connection.tenant` (§7.2), the one constrained connection field
    /// the client-credentials grant needs, which is absent from every
    /// connection written before it in the pattern `Connection.region` already
    /// follows. The ledger was re-read at the moment it landed and 24 was the
    /// next free number above the constant. Its refusal test is named from
    /// **23**, the immediately preceding landed state:
    /// `ConnectionTenantContracts.metadataAtSchema24IsRefusedByASchema23Build`.
    ///
    /// **26 is BL-128 slice 3c** (D65), read off the ledger at the moment it
    /// landed — 25 was BL-110's pending claim, which this voids and which moves
    /// to 27. It carries `SecretStore.githubActionsSecret` in deployed-
    /// credential rows and rotation steps, and `Operation.githubActionsSecretPut`
    /// in bindings. Both independent passes over the slice found why a number is
    /// owed: ledger rows and rotations decode one at a time and an undecodable
    /// one is dropped, and a row outlives its binding, so a schema-24 build
    /// opening a file whose GitHub binding had been removed would lose the
    /// record that a secret is still at GitHub and save the file without it.
    /// Its refusal test is named from **24**, the preceding landed state:
    /// `GitHubActionsDeliveryContracts.metadataAtSchema26IsRefusedByASchema24Build`.
    ///
    /// **28 is D71's review pass** (agent deliveries), read off the ledger at
    /// the moment it landed — 27 was BL-110's pending claim, which this voids
    /// and which moves to 30, behind BL-136 step 1's 29. It carries two
    /// things. `RuntimeSourceAuthorization` is now written by one thing only,
    /// the owner's "sources an agent may deliver" control, and means only
    /// that; every record an older build wrote — the binding builder's, the
    /// provisioning conversation's — meant something else and is dropped on
    /// the way up, so an upgrade opens no agent door the owner did not open.
    /// And a `DeployedCredential` row says which door wrote it and which
    /// enrolled client asked, which an older build would re-save without. Its
    /// refusal test is named from **26**, the preceding landed state:
    /// `AgentDeliveryContracts.metadataAtSchema28IsRefusedByASchema26Build`.
    ///
    /// **30 is the audit's rollback anchor (H-08)**, taken the same day 29
    /// landed. It carries `revocationGeneration`, the count of revocations the
    /// broker has written, which the broker anchors in the broker-only
    /// Keychain group: a `metadata.json` restored from before a revocation is
    /// below the anchor and authorizes nothing. An older build would re-save
    /// the file at 0 — and this build would then, correctly, refuse every
    /// grant in it forever — so the shape takes a number and the older build
    /// refuses the file whole instead. Its refusal test is named from **29**:
    /// `GrantContracts.metadataAtSchema30IsRefusedByASchema29Build`.
    ///
    /// **29 is BL-136 step 1** (D70 amendment 2), claimed on the ledger the
    /// same day 28 landed and taken when it did. It carries `Grant.mac`: the
    /// HMAC under a key only this Mac's signed Vaultage binaries hold, stamped
    /// at commit and at arming, without which a grant authorizes nothing. An
    /// older build would re-save grants without it — a safe direction, since
    /// the newer build then refuses them — but a shape an older build silently
    /// drops takes a number, as `Connection.region` and `Connection.tenant`
    /// did. Its refusal test is named from **28**, the preceding landed state:
    /// `GrantContracts.metadataAtSchema29IsRefusedByASchema28Build`.
    public static let schemaVersion = 30
    public var schemaVersion: Int
    /// §9.3's second guard: the lowest app build that can open the sealed store
    /// this Mac holds. `nil` on every file written before schema 23 and on every
    /// install that has not taken custody of a sealed store.
    public var minimumAppBuild: Int?
    public var projects: [Project]
    public var environments: [Environment]
    /// BL-078 / D24. The vaults in the rail. Never empty after decoding: a
    /// file that names none gets the default "Personal" vault.
    public var vaults: [Vault]
    /// The folders inside those vaults. A folder holds nothing of its own; it
    /// is a name, a parent and an order.
    public var folders: [Folder]
    /// The one vault the rail highlights and a new item is filed into. Always
    /// an existing, unarchived vault after decoding.
    public var activeVaultID: UUID
    public var vaultItems: [VaultItem]
    public var connections: [Connection]
    public var bindings: [Binding]
    public var runtimeSourceAuthorizations: [RuntimeSourceAuthorization]
    public var runtimeInjectionAuthorizations: [RuntimeInjectionAuthorization]
    /// BL-069 enrolled MCP clients. Hash-only: no record here carries a
    /// credential, and nothing here authorizes anything.
    public var enrolledClients: [EnrolledClient]
    /// BL-060 auto-allow grants. Durable metadata only: the secret cache that
    /// makes a grant window useful lives in broker process memory and is never
    /// written here, so a restart leaves the grant armed but unprimed.
    public var grants: [Grant]
    /// Durable only while a protected Keychain deletion is pending. A retained
    /// reservation is a safe, retryable tombstone after a crash or a final
    /// metadata-write failure; it prevents new references to the item.
    public var vaultItemDeletionReservations: [VaultItemDeletionReservation]
    /// The three connections explicitly kept active when the effective plan is
    /// Free. Empty means policy must choose its deterministic default.
    public var freeActiveConnectionIDs: Set<UUID>
    /// BL-074. Value-free records of provider resources Vaultage created, each
    /// linking a created vault item to the connection that created it and to
    /// the project environment it was created for. Nothing here is a credential
    /// and nothing here authorizes anything; it is what makes an honest
    /// `cloudflare.token.revoke` possible later.
    public var provisionedResources: [ProvisionedResource]
    /// BL-073. Provisioning conversations waiting on a human step, with an
    /// expiry. Nothing here authorizes anything: it is a note that a human was
    /// asked something plus their answer, and the broker re-resolves and
    /// re-checks every record before acting on it.
    public var pendingProvisionings: [PendingProvisioning]
    /// BL-091. The local idempotency ledger: one record per dispatched
    /// `idempotencyKey`-class create. Value-free, bounded and expiring; see
    /// `ResourceMutationKey`. Nothing here authorizes anything — it can only
    /// ever *refuse* a second dispatch.
    public var resourceMutationKeys: [ResourceMutationKey]
    /// BL-092 / D34. The cross-provider Resources inventory: value-free records
    /// of what each connected provider says already exists, cached on demand.
    /// Nothing here is a credential, nothing here is a capability, and nothing
    /// here is consulted by a policy decision — a row is a thing the human can
    /// find and then bind, and binding is its own approved step.
    public var resources: [ResourceRecord]
    /// BL-092. One record per connection: when its inventory was last refreshed,
    /// which reads ran, and which failed. It is also the rate-limit claim that
    /// keeps an on-demand refresh from becoming a poll.
    public var inventoryRefreshes: [InventoryRefreshRecord]
    /// BL-094 / D36. The deployed-credential ledger: for every environment,
    /// which credential is deployed to which provider secret store, when it was
    /// delivered and last verified, and its expiry where the provider states
    /// one. Value-free — the fingerprint is a digest of the source item's
    /// *identity*, never of its value — and advisory: a row is a record of
    /// something Vaultage did, not a permission to do it again.
    public var deployedCredentials: [DeployedCredential]
    /// BL-094 / D36. Rotations with overlap, persisted so a partly delivered
    /// rotation is visible and resumable. The one invariant the machine
    /// enforces is that the old credential is never revoked before every
    /// destination has been delivered *and* verified.
    public var rotations: [CredentialRotation]
    /// BL-099 / §2.4. One record per paired phone: five public keys, their RFC
    /// 7638 thumbprints, and the `pinGeneration` that ends an overwritten pin's
    /// grants for good. **The pin is the authority**: every key this protocol
    /// uses is resolved from here, never from the roster, and §4.3 step 2 — the
    /// only check that survives a compromised control plane — reads this and
    /// needs no network.
    public var devicePairings: [DevicePairingRecord]
    /// BL-099 / §2.6. Verified device-signed revocations. **Append-only and
    /// never removed by any network input**: a compromised relay can delay a
    /// revocation, it can never reverse one. The owner at the Mac can clear one
    /// behind Touch ID, which sets `clearedAt` and nothing else.
    public var deviceRevocations: [DeviceRevocationRecord]
    /// BL-099 / §2.6 rule 5. **Never cleared.** §2.4 rule 6 consults these two
    /// sets rather than the live DSRL, which the clearance empties — otherwise
    /// the social-engineering script rule 6 exists to stop ("re-pair your phone,
    /// something broke") simply gains one step.
    public var everRevokedDeviceIDs: Set<String>
    /// The thumbprint half, and the one that matters (DB-M32, DB-L31): a
    /// `deviceId` is a fresh UUID per enrolment, so a phone that re-enrolled
    /// while keeping its Secure Enclave keys would otherwise pair again under a
    /// new id **to the exact key that was revoked**. All five of a revoked
    /// device's pinned thumbprints are recorded, `sig` included.
    public var everRevokedKeyThumbprints: Set<String>
    /// Highest revocation serial ever seen per **revoking** device (§2.6 rule
    /// 3). A clearance never resets it, or a captured older statement replays.
    public var revocationSerialWatermarks: [String: Int]
    /// BL-099 / §4.4. The durable `RemoteDecisionReplayCache`: capacity 512,
    /// pruned at 24 hours, **checked and inserted atomically before any
    /// effect**, surviving restart. It is one of the two independent single-use
    /// records a captured decision signature has to get past — the other is the
    /// Worker's `UNIQUE(pending_id)` — which is why §4.4 could lengthen the
    /// signature's validity from 120 seconds to the pending's own remaining life
    /// without lengthening what a captured one buys.
    public var remoteDecisionReplays: [RemoteDecisionReplayEntry]
    /// Schema 22 / BL-099 §3.7. The owner's "Approve on my phone" switch and
    /// the consent that must precede it. **Never defaults to a position that
    /// mirrors**: a value absent from an older file, or a value nobody has
    /// ever set, decodes to `RemoteMirroringSetting()`, whose `consent` is
    /// `nil` and whose `effectivePosition` is therefore `.off` no matter what
    /// `chosenPosition` says. See the schema-20 note above for why this lives
    /// here rather than in `UserDefaults`.
    public var remoteMirroringSetting: RemoteMirroringSetting
    /// Audit H-08 (schema 30). Counts every revocation the broker writes — a
    /// grant revoked, a device's kill switch, a device unpaired. The broker
    /// keeps the highest value it has written in the broker-only Keychain
    /// group; a file whose count is lower than that anchor has been rolled
    /// back to before a revocation, and no grant in it authorizes anything
    /// and no remote decision is applied until it is current again.
    public var revocationGeneration: Int
    public var audit: [AuditEvent]
    public init(schemaVersion: Int = VaultageMetadata.schemaVersion, minimumAppBuild: Int? = nil, projects: [Project] = [], environments: [Environment] = [], vaults: [Vault] = [], folders: [Folder] = [], activeVaultID: UUID = Vault.defaultID, vaultItems: [VaultItem] = [], connections: [Connection] = [], bindings: [Binding] = [], runtimeSourceAuthorizations: [RuntimeSourceAuthorization] = [], runtimeInjectionAuthorizations: [RuntimeInjectionAuthorization] = [], enrolledClients: [EnrolledClient] = [], grants: [Grant] = [], vaultItemDeletionReservations: [VaultItemDeletionReservation] = [], freeActiveConnectionIDs: Set<UUID> = [], provisionedResources: [ProvisionedResource] = [], pendingProvisionings: [PendingProvisioning] = [], resourceMutationKeys: [ResourceMutationKey] = [], resources: [ResourceRecord] = [], inventoryRefreshes: [InventoryRefreshRecord] = [], deployedCredentials: [DeployedCredential] = [], rotations: [CredentialRotation] = [], devicePairings: [DevicePairingRecord] = [], deviceRevocations: [DeviceRevocationRecord] = [], everRevokedDeviceIDs: Set<String> = [], everRevokedKeyThumbprints: Set<String> = [], revocationSerialWatermarks: [String: Int] = [:], remoteDecisionReplays: [RemoteDecisionReplayEntry] = [], remoteMirroringSetting: RemoteMirroringSetting = RemoteMirroringSetting(), revocationGeneration: Int = 0, audit: [AuditEvent] = []) { self.schemaVersion = schemaVersion; self.revocationGeneration = revocationGeneration; self.minimumAppBuild = minimumAppBuild; self.projects = projects; self.environments = environments; self.vaults = vaults; self.folders = folders; self.activeVaultID = activeVaultID; self.vaultItems = vaultItems; self.connections = connections; self.bindings = bindings; self.runtimeSourceAuthorizations = runtimeSourceAuthorizations; self.runtimeInjectionAuthorizations = runtimeInjectionAuthorizations; self.enrolledClients = enrolledClients; self.grants = grants; self.vaultItemDeletionReservations = vaultItemDeletionReservations; self.freeActiveConnectionIDs = freeActiveConnectionIDs; self.provisionedResources = provisionedResources; self.pendingProvisionings = pendingProvisionings; self.resourceMutationKeys = resourceMutationKeys; self.resources = resources; self.inventoryRefreshes = inventoryRefreshes; self.deployedCredentials = deployedCredentials; self.rotations = rotations; self.devicePairings = devicePairings; self.deviceRevocations = deviceRevocations; self.everRevokedDeviceIDs = everRevokedDeviceIDs; self.everRevokedKeyThumbprints = everRevokedKeyThumbprints; self.revocationSerialWatermarks = revocationSerialWatermarks; self.remoteDecisionReplays = remoteDecisionReplays; self.remoteMirroringSetting = remoteMirroringSetting; self.audit = audit; VaultOrganization.normalize(&self); ConnectionRegions.normalize(&self); ConnectionTenants.normalize(&self); ResourceInventory.normalize(&self); DeployedCredentialLedger.normalize(&self); CredentialRotationStore.normalize(&self) }

    private enum CodingKeys: String, CodingKey { case schemaVersion, minimumAppBuild, projects, environments, vaults, folders, activeVaultID, vaultItems, connections, bindings, runtimeSourceAuthorizations, runtimeInjectionAuthorizations, enrolledClients, grants, vaultItemDeletionReservations, freeActiveConnectionIDs, provisionedResources, pendingProvisionings, resourceMutationKeys, resources, inventoryRefreshes, deployedCredentials, rotations, devicePairings, deviceRevocations, everRevokedDeviceIDs, everRevokedKeyThumbprints, revocationSerialWatermarks, remoteDecisionReplays, remoteMirroringSetting, revocationGeneration, audit }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let decodedSchemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        schemaVersion = decodedSchemaVersion
        minimumAppBuild = try c.decodeIfPresent(Int.self, forKey: .minimumAppBuild)
        projects = try c.decodeIfPresent([Project].self, forKey: .projects) ?? []
        environments = try c.decodeIfPresent([Environment].self, forKey: .environments) ?? []
        // Schema 12 addition (BL-078). A file written by an earlier schema has
        // no vault and no folder: every item decodes into the fixed default
        // vault id, and `VaultOrganization.normalize` below creates the
        // "Personal" vault those items point at. That is the whole migration,
        // and it runs on every decode, so it is also the repair pass for a
        // hand-edited or partially written tree.
        vaults = try c.decodeIfPresent([Vault].self, forKey: .vaults) ?? []
        folders = try c.decodeIfPresent([Folder].self, forKey: .folders) ?? []
        activeVaultID = try c.decodeIfPresent(UUID.self, forKey: .activeVaultID) ?? Vault.defaultID
        vaultItems = try c.decodeIfPresent([VaultItem].self, forKey: .vaultItems) ?? []
        connections = try c.decodeIfPresent([Connection].self, forKey: .connections) ?? []
        bindings = try c.decodeIfPresent([Binding].self, forKey: .bindings) ?? []
        // Schema 28 (D71). A `RuntimeSourceAuthorization` is now exactly what
        // the agent's delivery door checks — a source the owner allowed for a
        // binding in the app's own control — and nothing else writes one. Every
        // record before 28 was written by something else (the binding builder
        // for BL-051's Worker path, the provisioning conversation), none of it
        // the owner saying "an agent may deliver this", so none of it comes
        // up: the owner allows again, in the control that says what it means.
        // The fail-closed direction, as schemas 5, 6 and 7 took it.
        runtimeSourceAuthorizations = decodedSchemaVersion >= 28
            ? try c.decodeIfPresent([RuntimeSourceAuthorization].self, forKey: .runtimeSourceAuthorizations) ?? []
            : []
        // Schema 5 addition; schema 4 records migrate to no runtime injections.
        runtimeInjectionAuthorizations = try c.decodeIfPresent([RuntimeInjectionAuthorization].self, forKey: .runtimeInjectionAuthorizations) ?? []
        // Schema 6 addition; every earlier record migrates to no enrolled
        // client, which is the fail-closed state: unenrolled, per-action
        // approval only.
        enrolledClients = try c.decodeIfPresent([EnrolledClient].self, forKey: .enrolledClients) ?? []
        // Schema 7 addition; every earlier record migrates to no grants, which
        // is the fail-closed state: per-action approval for everything.
        //
        // Schema 8 changes no key here: it widens `EnvironmentSensitivity` from
        // two levels to three, and the stored `standard` of schema 7 and
        // earlier decodes to `development` inside `Environment`.
        //
        // Schema 9 (BL-072) changes no key here either: it adds `kind` and
        // `rootPath` inside `Environment`, and every environment written by an
        // earlier schema decodes as `cloud` with no root.
        grants = try c.decodeIfPresent([Grant].self, forKey: .grants) ?? []
        vaultItemDeletionReservations = try c.decodeIfPresent([VaultItemDeletionReservation].self, forKey: .vaultItemDeletionReservations) ?? []
        freeActiveConnectionIDs = try c.decodeIfPresent(Set<UUID>.self, forKey: .freeActiveConnectionIDs) ?? []
        // Schema 10 addition (BL-074); every earlier record migrates to no
        // provisioned resources, which is the truthful state: a build that
        // could not create one never did.
        provisionedResources = try c.decodeIfPresent([ProvisionedResource].self, forKey: .provisionedResources) ?? []
        // Schema 11 addition (BL-073). Every earlier record migrates to no
        // pending conversations, which is the fail-closed state: no human step
        // is treated as already answered.
        pendingProvisionings = try c.decodeIfPresent([PendingProvisioning].self, forKey: .pendingProvisionings) ?? []
        // Schema 14 addition (BL-091). Every earlier record migrates to an
        // empty ledger, which is the truthful state: a build that could not
        // dispatch a keyed create never dispatched one. An empty ledger never
        // *permits* a dispatch — it only fails to refuse one — so migrating to
        // empty cannot replay a mutation that already happened.
        resourceMutationKeys = try c.decodeIfPresent([ResourceMutationKey].self, forKey: .resourceMutationKeys) ?? []
        // Schema 15 addition (BL-092). Both decode leniently, element by
        // element, and a whole array that cannot be read at all becomes an empty
        // one: the inventory is a *cache*, so every decoding failure must
        // degrade to "not cached" rather than making `metadata.json` — which
        // also holds the projects, connections and bindings — unreadable. A row
        // this build cannot understand is a row it does not have.
        resources = ((try? c.decodeIfPresent([DecodedResourceRecord].self, forKey: .resources)) ?? [])?.compactMap(\.record) ?? []
        inventoryRefreshes = ((try? c.decodeIfPresent([DecodedInventoryRefresh].self, forKey: .inventoryRefreshes)) ?? [])?.compactMap(\.record) ?? []
        // Schema 16 addition (BL-094). Both decode leniently, element by
        // element, for the same reason BL-092's arrays do: a ledger row this
        // build cannot read must not make `metadata.json` — which also holds
        // the projects, connections and bindings — unreadable. But the two
        // arrays are *not* caches, and the difference is deliberate: an
        // inventory row can always be re-fetched, while a delivery cannot be
        // un-done by forgetting it, so `DeployedCredentialLedger.normalize`
        // keeps far more than `ResourceInventory.normalize` does — including a
        // row whose source vault item has since been deleted, because the value
        // is still at the provider.
        deployedCredentials = ((try? c.decodeIfPresent([DecodedDeployedCredential].self, forKey: .deployedCredentials)) ?? [])?.compactMap(\.value) ?? []
        rotations = ((try? c.decodeIfPresent([DecodedCredentialRotation].self, forKey: .rotations)) ?? [])?.compactMap(\.value) ?? []
        // Schema 17 additions (BL-099). Pins and revocations decode **strictly**,
        // unlike BL-092's and BL-094's lenient arrays: those are caches and
        // ledgers, where a row this build cannot read must not make
        // `metadata.json` unreadable. These are authorization records. A pin this
        // build cannot decode must not silently become "no pin" — that is a
        // device quietly losing its authority — and a revocation it cannot decode
        // must not silently become "not revoked", which is the one direction
        // §2.6 rule 2 forbids. A record that fails to decode fails the load, and
        // `MetadataStore` surfaces it.
        devicePairings = try c.decodeIfPresent([DevicePairingRecord].self, forKey: .devicePairings) ?? []
        deviceRevocations = try c.decodeIfPresent([DeviceRevocationRecord].self, forKey: .deviceRevocations) ?? []
        everRevokedDeviceIDs = try c.decodeIfPresent(Set<String>.self, forKey: .everRevokedDeviceIDs) ?? []
        everRevokedKeyThumbprints = try c.decodeIfPresent(Set<String>.self, forKey: .everRevokedKeyThumbprints) ?? []
        revocationSerialWatermarks = try c.decodeIfPresent([String: Int].self, forKey: .revocationSerialWatermarks) ?? [:]
        remoteDecisionReplays = try c.decodeIfPresent([RemoteDecisionReplayEntry].self, forKey: .remoteDecisionReplays) ?? []
        // Schema 22 addition (BL-099 §3.7). Every earlier record migrates to
        // `RemoteMirroringSetting()` — no consent, no position that matters —
        // which is the fail-closed state a clean install is already in. This
        // decodes leniently, unlike the pins and revocations above: a
        // malformed switch is a UI preference, not an authorization record,
        // and a file this build cannot parse must not become unreadable over
        // one screen's remembered position. A decode failure here still can
        // never *widen* access, because the type's own gate — `consent` must
        // be present and current before `effectivePosition` reads
        // `chosenPosition` at all — makes "on by default" unreachable
        // regardless of what failed to parse.
        remoteMirroringSetting = (try? c.decode(RemoteMirroringSetting.self, forKey: .remoteMirroringSetting)) ?? RemoteMirroringSetting()
        // Schema 30 (audit H-08): a file from before the count is at 0, which
        // is below any anchor a revocation has raised — fail closed, as a
        // rollback is.
        revocationGeneration = try c.decodeIfPresent(Int.self, forKey: .revocationGeneration) ?? 0
        audit = try c.decodeIfPresent([AuditEvent].self, forKey: .audit) ?? []
        // Applied after every array is in hand, because it reasons about the
        // relationships between them. It never removes an item.
        VaultOrganization.normalize(&self)
        // D44a's repair pass. Same place, same reasons: it reasons about a
        // connection against its own provider's documented regions, it is
        // idempotent, and it only ever narrows — an id this build does not
        // document becomes `nil`, the primary region, and is noted once.
        ConnectionRegions.normalize(&self)
        // BL-117 §7.2's repair pass, for the same reasons and in the same
        // place: it reasons about a connection against its own provider, it is
        // idempotent, and it only ever narrows.
        ConnectionTenants.normalize(&self)
        // BL-092's repair pass, for the same reason and in the same place: it
        // reasons about records against the connections above, it is
        // idempotent, and it only ever removes.
        ResourceInventory.normalize(&self)
        // BL-094's two repair passes, in dependency order: the ledger first,
        // because a rotation step points at a ledger row and a rotation whose
        // rows are gone has nothing left to resume.
        DeployedCredentialLedger.normalize(&self)
        CredentialRotationStore.normalize(&self)
        // BL-099's repair pass. It only ever *adds* to the never-cleared sets and
        // only ever *raises* a watermark, which is the only direction §2.6 rules
        // 2 and 3 permit: a hand-edited file that removed an id from
        // `everRevokedDeviceIDs` while leaving its revocation in place gets the
        // id back, and a file whose watermark sits below a recorded serial gets
        // the watermark raised.
        RemoteDeviceRecords.normalize(&self)
    }

    /// The vaults the rail shows, ordered as the rail shows them: the active
    /// vault first, then unarchived vaults by name, then archived ones.
    public var orderedVaults: [Vault] {
        vaults.sorted { left, right in
            if (left.id == activeVaultID) != (right.id == activeVaultID) { return left.id == activeVaultID }
            if left.isArchived != right.isArchived { return !left.isArchived }
            let order = left.name.localizedCaseInsensitiveCompare(right.name)
            if order != .orderedSame { return order == .orderedAscending }
            return left.id.uuidString < right.id.uuidString
        }
    }

    public var activeVault: Vault? { vaults.first { $0.id == activeVaultID } }
}

public struct ActionRequest: Codable, Hashable, Sendable {
    public let projectID: UUID
    public let environmentID: UUID
    public let bindingID: UUID
    public let operation: Operation
    /// BL-091. Set for a provider resource operation and nothing else. D71: an
    /// action carries no delivery of any kind — BL-051's Worker secret write
    /// and the Vercel and GitHub writes run `VaultageBroker.deliver`, from the
    /// owner's door or the agent's, and never through here.
    public let resourceMutation: ResourceMutationArguments?
    public init(projectID: UUID, environmentID: UUID, bindingID: UUID, operation: Operation, resourceMutation: ResourceMutationArguments? = nil) { self.projectID = projectID; self.environmentID = environmentID; self.bindingID = bindingID; self.operation = operation; self.resourceMutation = resourceMutation }
}

public struct ProviderReceipt: Codable, Hashable, Sendable {
    public let provider: String
    public let accountID: String
    public let scriptName: String
    public let variableName: String
    public let bindingType: String
    public let status: String
    public let valueVerified: Bool
    public init(provider: String, accountID: String, scriptName: String, variableName: String, bindingType: String, status: String, valueVerified: Bool) { self.provider = provider; self.accountID = accountID; self.scriptName = scriptName; self.variableName = variableName; self.bindingType = bindingType; self.status = status; self.valueVerified = valueVerified }
}

public struct ActionResult: Codable, Hashable, Sendable {
    public let summary: String
    public let fields: [String: String]
    public init(summary: String, fields: [String: String] = [:]) { self.summary = summary; self.fields = fields }
}

public enum VaultageError: LocalizedError, Equatable, Sendable {
    case invalidInput(String), policyDenied(String), approvalDenied, unsupported(String), transport(String), storage(String), authenticationFailed, permissionMissing, destinationNotFound, rateLimited, upstreamUnavailable, providerResultInvalid, resultUnknown
    /// PW5-H1, from the independent pass over provider wave 5. **Vaultage
    /// refused this credential because it is the wrong *kind*, not because the
    /// provider refused it.**
    ///
    /// It is its own case rather than an `invalidInput` string because the
    /// refusal has to be identifiable by a machine as well as readable by a
    /// human: `code` is a compiled, stable name — `doppler.credential_kind` —
    /// that a contract suite, a receipt and a live-certification transcript can
    /// all assert on, while `message` is the sentence the connect panel shows.
    /// The pass's finding was precisely that a wrong-kind credential produced
    /// *no* distinguishable signal anywhere, so an anonymous refusal would have
    /// fixed only half of it.
    ///
    /// It carries no credential bytes and must never be constructed with any:
    /// the message names the token *kind*, never the value or a fragment of it.
    case credentialKindRefused(code: String, message: String)
    public var errorDescription: String? {
        switch self { case .invalidInput(let s), .policyDenied(let s), .unsupported(let s), .transport(let s), .storage(let s): s; case .credentialKindRefused(_, let message): message; case .approvalDenied: "The action was not approved."; case .authenticationFailed: "Provider authentication failed."; case .permissionMissing: "The provider token does not have the required permission."; case .destinationNotFound: "The bound provider destination was not found."; case .rateLimited: "The provider rate limited this request."; case .upstreamUnavailable: "The provider is temporarily unavailable."; case .providerResultInvalid: "The provider returned an unexpected result."; case .resultUnknown: "The provider result is unknown. Do not retry automatically." }
    }
    /// The compiled refusal name, for the one case that has one.
    public var credentialKindCode: String? {
        if case .credentialKindRefused(let code, _) = self { return code }
        return nil
    }
}
