import Foundation

// BL-117 (D50, D51) — what the stored secret is **used for**.
//
// `blueprint/design/credential-classes-spec.md` version 2 §1.1 is the normative
// page. Three types already answer three separate questions and this adds to
// none of them:
//
//   * `CompositeCredentialKind` — *how is the value custodied?*
//   * `ProviderCredentialKind` (VaultageProviders) — *what does the panel draw?*
//   * `ProviderCredentialHeader` — *where does the credential go on the wire?*
//
// What no type answered is what the stored secret is used **for**, and that is
// the new axis. Every provider shipped before BL-117 places one stored value
// verbatim in one documented header, and the provider checks that value. Two
// families cannot be reached that way: the stored secret may be *exchanged* for
// a short-lived token that goes in the header, or it may be the *key* that
// signs a per-request construction whose signature goes in the header. Both
// move a credential from a value Vaultage places to a value Vaultage computes
// with, which is a different security property — the reason D51 required a
// design and an independent pass before any adapter.
//
// Runbook §10 item 2: this is a compiled vocabulary. An onboarding change may
// not add a class, a grant or a signing scheme; extending one is a ticket with
// its own pass.

/// What the stored secret is used for on the wire.
///
/// `Codable` because `CatalogProvider` is, and for no other reason: nothing
/// persists a `CredentialClass` to disk, no wire format carries one, and the
/// synthesized representation is therefore not an on-disk stable shape the way
/// `CompositeCredentialField`'s raw values are.
public enum CredentialClass: Sendable, Hashable, Codable {
    /// Every provider shipped to date. The stored value is placed verbatim in
    /// one documented header. Unchanged in every respect.
    case fixedToken
    /// The stored value is exchanged at a compiled token endpoint for a
    /// short-lived access token, and the short-lived token is placed in the
    /// header. The stored value is never sent to the resource host.
    ///
    /// **No `tokenExchange` adapter exists at BL-117's AWS commit.** The case
    /// is compiled here because the pairing assertion, the seam coherence rules
    /// and the panel are written against the whole vocabulary rather than
    /// against the one class that has an adapter — a vocabulary with a hole in
    /// it is a vocabulary the next slot widens rather than fills.
    case tokenExchange(TokenExchangeGrant)
    /// The stored value is the key to a per-request signature. It is never
    /// sent anywhere, in any form.
    case signedRequest(RequestSigningScheme)

    /// Whether this class places the stored credential in a header verbatim.
    /// The seam-1 admission rule (§2.4) is written against this rather than
    /// against a list of provider ids.
    public var placesStoredCredentialInAHeader: Bool {
        if case .fixedToken = self { return true }
        return false
    }

    /// §1.2, borrowed from `research/vercel-connect-2026-09-14.md`: *whose*
    /// authority an agent is about to use. It is what a receipt and the connect
    /// panel need to be able to say, and it is derived from the grant or the
    /// scheme rather than declared beside it, so the two cannot disagree.
    ///
    /// Vercel's third subject type (federated / `jwt-bearer`) is out of scope:
    /// it needs a workload identity the Mac does not have, and D36 guarantee 1
    /// means Vaultage has no cloud runtime to federate from. Recorded as a
    /// decision rather than left as a gap.
    public var subjectType: CredentialSubjectType {
        switch self {
        case .fixedToken: .app
        case let .tokenExchange(grant): grant == .authorizationCodePKCE ? .user : .app
        case .signedRequest: .app
        }
    }
}

/// The three exchange shapes §1.1 admits. Compiled, closed, and not extendable
/// by an onboarding change (runbook §10 item 2).
public enum TokenExchangeGrant: String, Sendable, Codable, CaseIterable, Hashable {
    /// Act as the user.
    case authorizationCodePKCE
    /// Act as the app.
    case clientCredentials
    /// Act as the app, Google's shape.
    case serviceAccountJWT
}

/// The two signing schemes §1.1 admits. Only `.sigV4` has an adapter at this
/// commit; `.ociRequestSignature` is compiled for the same reason
/// `.tokenExchange` is.
public enum RequestSigningScheme: String, Sendable, Codable, CaseIterable, Hashable {
    /// AWS Signature Version 4, `Authorization` header form only. SigV4a is out
    /// of scope (§7.1).
    case sigV4
    /// Oracle Cloud Infrastructure request signatures.
    case ociRequestSignature
}

/// §1.2. Whose authority an action runs under, in the one word a receipt and
/// the connect panel can both use.
public enum CredentialSubjectType: String, Sendable, Codable, CaseIterable, Hashable {
    /// Vaultage acts as an application principal the owner authorised once.
    /// Nobody's session is being spent; the provider sees a service identity.
    case app
    /// Vaultage acts as the signed-in human. Everything the agent does is
    /// attributable to them at the provider, and their own permissions bound it.
    case user
}

public extension CredentialClass {

    /// §1.1's pairing rule, as a function rather than as prose, so the catalog
    /// contract and any future connect path ask the same question.
    ///
    /// *"a `.tokenExchange` manifest may not declare `.singleToken` custody, and
    /// a `.fixedToken` manifest may not declare a grant"* — the second half is
    /// structural (a `.fixedToken` value carries no grant), so what is checkable
    /// is the first: each class admits a closed set of custody kinds, and a
    /// manifest outside it is refused.
    func admits(custody: CompositeCredentialKind) -> Bool {
        admissibleCustodyKinds.contains(custody)
    }

    /// The custody kinds this class may be paired with, from §1.3's table.
    var admissibleCustodyKinds: Set<CompositeCredentialKind> {
        switch self {
        // A fixed token is whatever the provider documents as its one header
        // value: a bare token, or a pair sent together as HTTP basic
        // authentication. Both shipped before BL-117 and neither moves.
        case .fixedToken: [.singleToken, .identifierAndSecret]
        case let .signedRequest(scheme):
            switch scheme {
            case .sigV4: [.accessKeyPair]
            // OCI's `keyId` plus PEM. The kind is reserved in the same commit
            // as its fields; no adapter uses it yet.
            case .ociRequestSignature: []
            }
        case let .tokenExchange(grant):
            switch grant {
            // BL-117's Azure slot. The application (client) ID and the client
            // secret, exchanged at the token endpoint for a short-lived access
            // token. Widened here **in the same commit as the adapter**, which
            // is what runbook §10 item 2 asks for: the vocabulary and its
            // pairing pass existed first (D51), and a slot spends one entry of
            // it when it lands the adapter that needs it.
            case .clientCredentials: [.clientIDAndSecret]
            // BL-117's Google Cloud slot. The service-account key — the
            // account's address, the RSA private key and the key id — widened
            // here **in the same commit as the adapter**, which is what runbook
            // §10 item 2 asks for and what the Azure slot did one slot earlier.
            case .serviceAccountJWT: [.serviceAccountKey]
            // BL-117's GitHub slot. The two halves of a user grant, widened
            // here **in the same commit as the custody kind**, which is what
            // runbook §10 item 2 asks for and what the two slots before this
            // one did. Until this commit the set was empty and the pairing
            // assertion refused the class outright — the honest statement of
            // "specified, not yet built" — and the rule the Google slot's note
            // wrote down was that the two land together or the class stays
            // refused. They land together.
            case .authorizationCodePKCE: [.userGrant]
            }
        }
    }

    /// The whole compiled vocabulary, enumerated once.
    ///
    /// `CredentialClass` carries associated values, so it cannot be
    /// `CaseIterable` and a contract that wanted "every class" had to keep its
    /// own list — which is a second place to forget a grant. This is the one
    /// place, derived from the two grant and scheme enums' own `allCases`, so a
    /// new grant appears here without anybody editing a test.
    static var allCompiledClasses: [CredentialClass] {
        [.fixedToken]
            + TokenExchangeGrant.allCases.map(CredentialClass.tokenExchange)
            + RequestSigningScheme.allCases.map(CredentialClass.signedRequest)
    }

    /// The short, value-free word the Activity view and a receipt use for the
    /// class itself. Never provider text.
    var receiptLabel: String {
        switch self {
        case .fixedToken: "fixed-token"
        case let .tokenExchange(grant): "token-exchange/\(grant.rawValue)"
        case let .signedRequest(scheme): "signed-request/\(scheme.rawValue)"
        }
    }
}
