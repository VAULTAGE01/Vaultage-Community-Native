import Foundation
import LocalAuthentication

/// BL-062 follow-up — **one OS prompt per human action.**
///
/// The defect this type exists to remove was observed by the owner on the
/// signed build (2026-09-11 afternoon): Reveal raised two Touch ID prompts back
/// to back. The cause is structural rather than accidental. A human flow
/// authenticates the owner with its *own* `LAContext` so the prompt can name
/// the destination and the item ("Reveal on screen: GitHub token"), and then
/// `KeychainVault.read` created a *fresh* `LAContext` for
/// `SecItemCopyMatching`. The item's access control is `.userPresence`, so the
/// Keychain had no evaluated credential to consult and asked the human again —
/// this time with the OS's own wording, naming nothing.
///
/// Two prompts is not merely untidy. It teaches the owner to click through
/// authentication prompts in pairs, which is exactly the habit that makes the
/// *first* prompt — the only one that states what is about to be disclosed —
/// stop being read.
///
/// The fix is to carry the already-evaluated context to the Keychain read as
/// `kSecUseAuthenticationContext`, so `SecItemCopyMatching` consults the
/// presence the human already proved instead of demanding a second proof. This
/// type is that carrier, and it is deliberately narrow:
///
/// * **It is bound to Keychain accounts.** `accounts` is the exact set of
///   `kSecAttrAccount` values the human was told about when they
///   authenticated. `isValid(for:at:)` refuses any other account, so an
///   authentication for one item can never unlock a different one. An
///   authentication created with an empty set is *unbound* and can unlock
///   nothing: it proves presence for a decision (creating a grant) rather than
///   for a read.
/// * **It expires.** `lifetime` is 60 seconds, the same bound the grant path
///   and `HumanDisclosureService` already enforce on their own authentications.
///   Reuse past that window falls back to a fresh prompt rather than to a
///   stale one.
/// * **It is invalidatable, and every caller invalidates it.** `invalidate()`
///   tears down the underlying `LAContext`, which drops the evaluated
///   credential, so the presence does not outlive the action that raised it
///   even if the value were retained by mistake.
///
/// The paths where the Keychain prompt is the *only* gate — every MCP, broker
/// and XPC read — are unchanged. They pass no authentication, `KeychainVault`
/// builds a fresh context as it always did, and they still cost exactly one
/// prompt.
public struct OwnerAuthentication: Sendable {
    /// How long an evaluated presence may be carried to a Keychain read.
    ///
    /// The same 60 seconds `HumanDisclosureService.authenticationLifetime` and
    /// `VaultageBroker.createGrant` already impose between authenticating and
    /// committing. Carrying the context does not lengthen the window a human's
    /// authentication is good for; it only stops the window from costing a
    /// second prompt.
    public static let lifetime: TimeInterval = 60

    /// The value written to `LAContext.touchIDAuthenticationAllowableReuseDuration`
    /// on a context Vaultage evaluates and then carries.
    ///
    /// macOS caps this at `LATouchIDAuthenticationMaximumAllowableReuseDuration`
    /// (five minutes). Vaultage sets it **explicitly** at 60 seconds — matching
    /// `lifetime` — rather than accepting the platform default, so the reuse
    /// window is a number in this file that a reader can check against the
    /// ticket instead of an implicit OS behaviour. Fresh, un-carried contexts
    /// are set to `0`: a read that is meant to raise its own prompt must never
    /// be satisfied by an unrelated Touch ID the owner performed moments ago.
    public static let keychainReuseDuration: TimeInterval = 60

    /// Identifies one evaluation. Tests assert that a single human action
    /// produced a single identifier; nothing in production branches on it.
    public let id: UUID
    /// When the human proved presence, on the clock of whoever authenticated.
    public let authenticatedAt: Date
    /// The exact Keychain accounts this presence may unlock. Empty means
    /// unbound: presence for a decision, usable for no read at all.
    public let accounts: Set<String>
    private let carrier: OwnerAuthenticationContext?

    public init(id: UUID = UUID(), authenticatedAt: Date, accounts: Set<String>, carrier: OwnerAuthenticationContext? = nil) {
        self.id = id
        self.authenticatedAt = authenticatedAt
        self.accounts = accounts
        self.carrier = carrier
    }

    /// A presence proved for a decision rather than for a read. It carries no
    /// account, so `isValid(for:at:)` is false for every account.
    public static func unbound(at date: Date, carrier: OwnerAuthenticationContext? = nil) -> OwnerAuthentication {
        OwnerAuthentication(authenticatedAt: date, accounts: [], carrier: carrier)
    }

    /// Whether this presence may be carried into a read of `account`.
    ///
    /// Every clause is a refusal the double-prompt fix must not cost us: a
    /// context that was never evaluated, an account the human was not told
    /// about, a clock that moved backwards, and an expired window.
    public func isValid(for account: String, at now: Date) -> Bool {
        guard carrier != nil, accounts.contains(account) else { return false }
        let elapsed = now.timeIntervalSince(authenticatedAt)
        return elapsed >= 0 && elapsed <= Self.lifetime
    }

    /// The evaluated `LAContext` to hand `SecItemCopyMatching`, or `nil` when
    /// this presence may not be carried into that read. `nil` means "prompt",
    /// never "proceed".
    public func keychainContext(for account: String, at now: Date = Date()) -> LAContext? {
        guard isValid(for: account, at: now) else { return nil }
        return carrier?.context
    }

    /// Drops the evaluated credential. Callers invoke this as soon as the reads
    /// the authentication was raised for have been attempted, so a carried
    /// presence cannot survive the action even by accident.
    public func invalidate() {
        carrier?.context.invalidate()
    }
}

/// A reference box around `LAContext`, which is not `Sendable`.
///
/// The unchecked conformance is the deliberate narrow exception. An
/// `OwnerAuthentication` is created by the authenticator and handed straight to
/// one vault read on the same actor; it is never shared between concurrent
/// readers and never stored anywhere durable. The alternative — making the
/// authenticating seam non-`Sendable` — would force the whole disclosure path
/// off the actor model for one Objective-C object.
public final class OwnerAuthenticationContext: @unchecked Sendable {
    let context: LAContext

    public init(_ context: LAContext) {
        self.context = context
    }
}
