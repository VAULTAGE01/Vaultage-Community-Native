import Foundation

// BL-117 (D51) §4 — refresh, revocation and rotation for a user grant.
//
// `blueprint/design/credential-classes-spec.md` version 2 §4.1, §4.2 and §4.3
// are the normative pages. This file is the **policy**, as values and as an
// ordered list of steps, so every rule below can be driven without a browser, a
// Worker, a Keychain or a provider.
//
// **Why the policy is a type rather than a sequence inside a function.** §4.1's
// rules are all about *order* and *what a failure leaves behind*, and those are
// the two things a straight-line implementation asserts worst: a test can only
// observe the end state, so an implementation that wrote the new record after
// retiring the old one passes every test that checks the happy path. With the
// steps compiled as a list, the order is a value the suite compares, and the
// failure behaviour is a function of a step rather than of where an exception
// happened to be thrown.
//
// **CC-H5 is what this file exists for.** Version 1 of the design wrote the
// superseded record *"under the presence already held for the action"*. There is
// no such presence: `13-MULTI-DEVICE-CUSTODY.md` §2.4.1 admits none outside the
// seven batch flows, every `vkx` operation that opens an item key takes a
// `LAContext` created for that operation and used for no other, and a `value`
// subject is not in flow 7's set. The alternative — one broker operation whose
// single context covers a read and a rotate — is an **eighth batch flow**, which
// §2.3 tells everyone not to reach for. So a rotating refresh costs a **second**
// presence prompt, and since §2.2a claims BL-074's creation class for exactly
// this case, it raises that class's own native sheet rather than claiming the
// class and declining the control.

/// What a refresh reply did to the durable half of the grant.
///
/// Derived by comparing the refresh token that came back against the one that
/// went out — over bytes, through `VaultSecret`, so neither is ever a `String`
/// in order to be compared.
public enum UserGrantRefreshOutcome: Sendable, Equatable {
    /// The provider returned no refresh token, or returned the same one. The
    /// access token is replaced in memory and **nothing is written**: there is
    /// no vault write, so there is no second prompt and no sheet.
    case durableHalfUnchanged
    /// The provider returned a **different** refresh token. §2.2a: rotating a
    /// durable credential is a creation by the class's own test — a new secret
    /// that outlives the action and can be used elsewhere — so this is the case
    /// that costs a second presence prompt and raises BL-074's sheet.
    case durableHalfRotated
    /// The refresh itself was refused. §2.5 fail-closed (c): the connection is
    /// marked `reconnectRequired` and the operation refuses; it never silently
    /// drops to an older token.
    case refused

    /// §4.1. Whether this outcome costs a **second** presence prompt.
    public var requiresSecondPresenceProof: Bool { self == .durableHalfRotated }

    /// §2.2a and §4.1. Whether this outcome raises BL-074's native creation
    /// sheet. It is the same question as the line above and is deliberately a
    /// separate property: the two controls are separate — presence and approval
    /// — and a future author who relaxes one must not get the other for free.
    public var raisesCreationSheet: Bool { self == .durableHalfRotated }

    /// §2.5 fail-closed (c).
    public var marksReconnectRequired: Bool { self == .refused }
}

/// §4.1's ordered steps, compiled so the order is a value rather than the shape
/// of a function body.
///
/// The order is D36 guarantee 3 applied to the refresh token itself, plus the
/// egress precondition `Broker.deliverCredential` already states — *"The
/// durable, value-free pending receipt is the egress precondition: if local
/// persistence fails, nothing is read and nothing is sent."*
public enum UserGrantRefreshStep: String, Sendable, CaseIterable, Hashable {
    /// The value-free pending receipt, **before the refresh request leaves**.
    /// First, and it is first for the reason the delivery path gives: if local
    /// persistence fails there is nothing to explain afterwards, so nothing is
    /// sent.
    case pendingReceipt
    /// The second presence proof and BL-074's sheet, **before** the request, so
    /// an owner who declines costs the provider nothing and the old grant stays
    /// live.
    ///
    /// Asking afterwards would be worse in both directions: a decline would
    /// leave a rotated grant at the provider that this Mac had thrown away, and
    /// an approval would be approving something that had already happened.
    /// Since the Mac cannot know a reply will rotate before it asks for one,
    /// this step is taken whenever the connection's provider **documents**
    /// rotating refresh tokens — a compiled fact, not a guess about a reply.
    case presenceAndCreationSheet
    /// The exchange itself.
    case refreshRequest
    /// Persist the new record **at a new revision**, before the old one is
    /// retired.
    case persistNewRevision
    /// Retire the superseded record. Last, so a failure between the two leaves
    /// a working connection rather than none.
    case retireSupersededRevision
    /// The settled receipt.
    case settledReceipt
}

/// §4 as one compiled policy per connection.
public struct UserGrantLifecycle: Sendable {

    /// §4.1's cap: *"at most once per 8 hours per connection"*.
    ///
    /// It is a **cap on the prompt**, not on the refresh: an access token that
    /// expires inside the window is re-exchanged without one, because only a
    /// rotation writes to the vault. The number is GitHub's own documented
    /// access-token lifetime, which is what makes it the right cap rather than
    /// a chosen one — a connection whose token lasts eight hours cannot
    /// legitimately need two rotations inside eight hours.
    public static let rotationPromptInterval: TimeInterval = 8 * 60 * 60

    /// The ordered steps, as the policy says them. Compiled here so a caller
    /// runs `steps` rather than writing the order out again.
    public static let steps: [UserGrantRefreshStep] = [
        .pendingReceipt,
        .presenceAndCreationSheet,
        .refreshRequest,
        .persistNewRevision,
        .retireSupersededRevision,
        .settledReceipt
    ]

    /// The steps for a provider that documents **no** rotation, which is every
    /// grant whose durable half never changes — Slack's non-expiring bot token
    /// is §8.2's example.
    ///
    /// The sheet and the two vault steps drop out, because there is nothing to
    /// write. What stays is the receipt pair, which is not conditional: an
    /// owner is entitled to see in Activity that a token was minted on their
    /// behalf whether or not anything was stored.
    public static let stepsWithoutRotation: [UserGrantRefreshStep] = [
        .pendingReceipt,
        .refreshRequest,
        .settledReceipt
    ]

    /// §4.1's sheet line. BL-074's class supplies the sheet; this is the one
    /// sentence on it, and it names the provider rather than "the provider" so
    /// an owner reading it at 2 a.m. knows what they are approving.
    public static func creationSheetLine(provider: String) -> String {
        "\(provider) issued a new refresh token — replace the stored one?"
    }

    /// §2.5 fail-closed (c) / §4.1's failed-write rule, as the sentence the
    /// receipt carries.
    ///
    /// *"If the write fails after the provider has already invalidated the old
    /// token, mark the connection `reconnectRequired` and receipt it
    /// immediately, so a dead connection is a thing the owner is told rather
    /// than a thing they discover."*
    public static let reconnectRequiredLine =
        "This connection could not store the new token the provider issued, and the provider has already retired the old one. Nothing was sent and nothing was read. Reconnect to authorise it again."

    /// Classifies one refresh reply.
    ///
    /// - Parameters:
    ///   - presented: the refresh token this Mac sent, or nil on the first
    ///     exchange of a ceremony (where there is nothing to compare and the
    ///     durable half is new by definition).
    ///   - returned: the refresh token the provider sent back, or nil when it
    ///     sent none.
    ///
    /// The comparison is over **bytes**, inside both secrets' own borrows, so
    /// neither is a `String` in order to be compared — the same rule
    /// `VaultSecret.matches` follows, applied to two secrets rather than to a
    /// secret and a candidate.
    public static func outcome(presented: VaultSecret?, returned: VaultSecret?) -> UserGrantRefreshOutcome {
        guard let returned, returned.byteCount > 0 else { return .durableHalfUnchanged }
        guard let presented, presented.byteCount > 0 else { return .durableHalfRotated }
        return sameBytes(presented, returned) ? .durableHalfUnchanged : .durableHalfRotated
    }

    /// Whether the prompt cap allows a rotation prompt now.
    ///
    /// A refusal here is **not** a refusal of the refresh: it is the statement
    /// that a second rotation inside eight hours is not a thing a connection
    /// whose token lasts eight hours can legitimately need, so the operation
    /// refuses rather than prompting again. §2.5 fail-closed (b) is the shape —
    /// an expired token with no usable refresh path refuses rather than
    /// retrying.
    public static func rotationPromptAllowed(lastPromptedAt: Date?, now: Date = Date()) -> Bool {
        guard let lastPromptedAt else { return true }
        return now.timeIntervalSince(lastPromptedAt) >= rotationPromptInterval
    }

    private static func sameBytes(_ lhs: VaultSecret, _ rhs: VaultSecret) -> Bool {
        guard lhs.byteCount == rhs.byteCount else { return false }
        var equal = false
        lhs.withBytes { left in
            rhs.withBytes { right in
                guard let leftBase = left.baseAddress, let rightBase = right.baseAddress else { return }
                equal = memcmp(leftBase, rightBase, left.count) == 0
            }
        }
        return equal
    }
}

/// §4.2 — revocation, and the order that makes it true.
///
/// D44(c) is already the rule: *"when a provisioned token is revoked, the broker
/// deletes the protected value and keeps the value-free record marked revoked
/// for audit"*. §4.2 adds one step in front of it and the **order is the whole
/// point**: deleting locally first would leave a live grant at the provider that
/// the owner believes is gone.
public enum UserGrantRevocation {

    public enum Step: String, Sendable, CaseIterable, Hashable {
        /// The provider's own revocation endpoint, **where one is documented**.
        /// Skipped — not faked — where none is.
        case revokeAtProvider
        /// The vault value.
        case deleteStoredValue
        /// Rule C's entry for this connection.
        case dropCachedToken
        /// The value-free record, marked revoked, kept for audit.
        case markRecordRevoked
        /// The receipt, which says **both** things when the provider refused:
        /// that the remote revocation failed and that the local delete happened
        /// anyway.
        case receipt
    }

    public static let steps: [Step] = [.revokeAtProvider, .deleteStoredValue, .dropCachedToken, .markRecordRevoked, .receipt]

    /// §4.2: *"A revocation the provider refuses is reported, and the local
    /// delete still happens, with the receipt saying both things."*
    ///
    /// So a failure at step one does **not** stop the sequence, which is the
    /// opposite of the refresh path's behaviour and is deliberate: a refresh
    /// that cannot complete leaves a working connection, and a revocation that
    /// cannot complete remotely must still take the local value away.
    public static func continuesAfterProviderRefusal(_ step: Step) -> Bool { step == .revokeAtProvider }

    public static let providerRefusedLine =
        "The provider refused to revoke this grant, so it may still be live there. Vaultage deleted its copy anyway and kept the value-free record. Revoke it at the provider as well."

    /// The providers whose own revocation endpoint is compiled — **none, at
    /// this commit, and that is a statement rather than a gap.**
    ///
    /// §4.2 names two: Google's `https://oauth2.googleapis.com/revoke` and
    /// Linear's `https://api.linear.app/oauth/revoke`. Neither belongs to a
    /// provider this product has a user grant with — Google Cloud's connection
    /// is a service-account key, whose revocation is deleting the key in the
    /// console, and Linear has no compiled adapter at all (§8.3 records that as
    /// BL-118's own prerequisite). And §4.2 names **none for GitHub**.
    ///
    /// Nothing here invents one. A compiled URL is a fact read from a provider's
    /// own documentation on a dated read, and no GitHub page was read from the
    /// lane that wrote this file. So the map is empty, step one is **skipped
    /// rather than faked**, and the receipt tells the owner to revoke the grant
    /// at the provider by hand. Reading GitHub's revocation documentation and
    /// compiling the endpoint is owed and is recorded in the evidence note; it
    /// is one line here and one citation, and it must not be guessed at.
    public static let compiledEndpoints: [Provider: URL] = [:]

    public static func endpoint(for provider: Provider) -> URL? { compiledEndpoints[provider] }

    /// What the receipt says when step one is skipped because no endpoint is
    /// compiled — which is every revocation today, and which an owner has to be
    /// told plainly rather than left to infer from silence.
    public static let noCompiledEndpointLine =
        "Vaultage deleted its copy of this grant and marked the record revoked. It has no compiled way to revoke the grant at the provider, so the grant may still be live there until you revoke it yourself."
}
