import Foundation
import VaultageCore

/// The two explicit human destinations supported by the native Community UI.
/// This is not an agent or broker interface.
public enum CommunityDisclosurePurpose: Sendable, Equatable {
    case reveal, copy
}

/// Value-free identity for one authentication attempt. A late result must match
/// the exact attempt, secret and purpose before it can become ready.
public struct CommunityDisclosureRequest: Sendable, Equatable {
    public let id: UUID
    public let secretID: UUID
    public let purpose: CommunityDisclosurePurpose

    fileprivate init(secretID: UUID, purpose: CommunityDisclosurePurpose) {
        id = UUID()
        self.secretID = secretID
        self.purpose = purpose
    }
}

/// Safe UI status. The protected value remains inside the gate as VaultSecret;
/// readiness never creates a String or writes a clipboard item.
public struct PreparedCommunityDisclosure: Sendable, Equatable {
    public let requestID: UUID
    public let secretID: UUID
    public let purpose: CommunityDisclosurePurpose
    public let expiresAt: Date
}

/// Two-click disclosure: OS authentication prepares a short-lived protected
/// handle; only a second explicit click in an active window can consume it.
///
/// The native UI owns this gate on the main actor. Focus loss during an OS
/// authentication sheet preserves only its value-free request. Once a value
/// is ready, every focus loss clears it. Returning focus has no transition and
/// cannot disclose anything. Canceling a request prevents its later result
/// from becoming ready, even if another attempt targets the same secret.
/// State is protected by one lock. Aliases share the same one-use state, and
/// concurrent consumers cannot each receive the same protected handle.
public final class HumanDisclosureGate: @unchecked Sendable {
    public static let lifetime: TimeInterval = 20

    private enum State: Sendable {
        case idle
        case authenticating(CommunityDisclosureRequest)
        case ready(CommunityDisclosureRequest, VaultSecret, expiresAt: Date)
    }

    private var state: State = .idle
    private let lock = NSLock()

    public init() {}

    public func begin(secretID: UUID, purpose: CommunityDisclosurePurpose) -> CommunityDisclosureRequest {
        lock.withLock {
            let request = CommunityDisclosureRequest(secretID: secretID, purpose: purpose)
            state = .authenticating(request)
            return request
        }
    }

    public func isAuthenticating(_ request: CommunityDisclosureRequest) -> Bool {
        lock.withLock {
            guard case .authenticating(let current) = state else { return false }
            return current == request
        }
    }

    /// Called only after SecretVault's authenticated read has succeeded. A
    /// stale completion is refused without changing a newer pending attempt.
    @discardableResult
    public func prepare(_ secret: VaultSecret, for request: CommunityDisclosureRequest, at now: Date) -> PreparedCommunityDisclosure? {
        lock.withLock {
            guard case .authenticating(let current) = state, current == request else { return nil }
            let expiresAt = now.addingTimeInterval(Self.lifetime)
            state = .ready(request, secret, expiresAt: expiresAt)
            return status(request, expiresAt: expiresAt)
        }
    }

    public func preparedAction(at now: Date) -> PreparedCommunityDisclosure? {
        lock.withLock {
            expireLocked(at: now)
            guard case .ready(let request, _, let expiresAt) = state else { return nil }
            return status(request, expiresAt: expiresAt)
        }
    }

    /// No String conversion occurs here. The human UI makes the deliberate
    /// screen/clipboard conversion only after this one-use consume succeeds.
    public func consume(requestID: UUID, secretID: UUID, purpose: CommunityDisclosurePurpose, whileWindowActive: Bool, at now: Date) -> VaultSecret? {
        lock.withLock {
            expireLocked(at: now)
            guard whileWindowActive,
                  case .ready(let request, let secret, _) = state,
                  request.id == requestID, request.secretID == secretID, request.purpose == purpose else { return nil }
            state = .idle
            return secret
        }
    }

    public func focusLost() {
        lock.withLock {
            if case .authenticating = state { return }
            state = .idle
        }
    }

    public func cancel() { lock.withLock { state = .idle } }

    @discardableResult
    public func expire(at now: Date) -> Bool {
        lock.withLock { expireLocked(at: now) }
    }

    @discardableResult
    private func expireLocked(at now: Date) -> Bool {
        guard case .ready(_, _, let expiresAt) = state, now >= expiresAt else { return false }
        state = .idle
        return true
    }

    private func status(_ request: CommunityDisclosureRequest, expiresAt: Date) -> PreparedCommunityDisclosure {
        PreparedCommunityDisclosure(requestID: request.id, secretID: request.secretID, purpose: request.purpose, expiresAt: expiresAt)
    }
}
