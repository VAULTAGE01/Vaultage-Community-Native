import Foundation
import CommunityKit
import VaultageCore

/// Pure in-memory gate checks. No Keychain, clipboard, UI or real values.
struct HumanDisclosureGateTests: Sendable {
    private let now = Date(timeIntervalSince1970: 2_000_000_000)
    private func syntheticSecret() -> VaultSecret { VaultSecret(Data("synthetic-disclosure-gate-only".utf8)) }

    func testAuthenticationFocusLossRequiresSeparateExplicitConsume() async throws {
        let gate = HumanDisclosureGate()
        let secretID = UUID()
        let request = gate.begin(secretID: secretID, purpose: .reveal)
        gate.focusLost() // macOS authentication may move focus away.
        expectTrue(gate.isAuthenticating(request))
        expectTrue(gate.preparedAction(at: now) == nil)
        expectTrue(gate.consume(requestID: request.id, secretID: secretID, purpose: .reveal, whileWindowActive: true, at: now) == nil)
        let ready = try require(gate.prepare(syntheticSecret(), for: request, at: now))
        expectEqual(ready.secretID, secretID)
        expectEqual(ready.purpose, .reveal)
        // No activation transition consumes the value. Status is value-free,
        // and an inactive consume is refused while the same handle stays ready.
        expectTrue(gate.consume(requestID: request.id, secretID: secretID, purpose: .reveal, whileWindowActive: false, at: now) == nil)
        expectEqual(gate.preparedAction(at: now), ready)
        let consumed = try require(gate.consume(requestID: request.id, secretID: secretID, purpose: .reveal, whileWindowActive: true, at: now))
        expectTrue(consumed.matches("synthetic-disclosure-gate-only"))
        expectTrue(gate.preparedAction(at: now) == nil)
    }

    func testReadyFocusLossAndManualCancelDropPendingValue() async throws {
        for purpose in [CommunityDisclosurePurpose.reveal, .copy] {
            let gate = HumanDisclosureGate()
            let id = UUID()
            let request = gate.begin(secretID: id, purpose: purpose)
            _ = try require(gate.prepare(syntheticSecret(), for: request, at: now))
            gate.focusLost()
            expectTrue(gate.preparedAction(at: now) == nil)
            expectTrue(gate.consume(requestID: request.id, secretID: id, purpose: purpose, whileWindowActive: true, at: now) == nil)
            let second = gate.begin(secretID: id, purpose: purpose)
            _ = try require(gate.prepare(syntheticSecret(), for: second, at: now))
            gate.cancel()
            expectTrue(gate.consume(requestID: second.id, secretID: id, purpose: purpose, whileWindowActive: true, at: now) == nil)
        }
    }

    func testCanceledAndReplacedAuthenticationResultsCannotBecomeReady() async throws {
        let gate = HumanDisclosureGate()
        let id = UUID()
        let canceled = gate.begin(secretID: id, purpose: .reveal)
        gate.cancel() // Manual Hide, selection or section change.
        expectTrue(gate.prepare(syntheticSecret(), for: canceled, at: now) == nil)
        let stale = gate.begin(secretID: id, purpose: .reveal)
        let current = gate.begin(secretID: id, purpose: .reveal)
        expectTrue(stale.id != current.id)
        expectTrue(gate.prepare(syntheticSecret(), for: stale, at: now) == nil)
        expectTrue(gate.isAuthenticating(current))
        _ = try require(gate.prepare(syntheticSecret(), for: current, at: now))
        expectTrue(gate.consume(requestID: stale.id, secretID: id, purpose: .reveal, whileWindowActive: true, at: now) == nil)
        // A later stale completion also cannot erase or replace readiness.
        expectTrue(gate.prepare(syntheticSecret(), for: stale, at: now) == nil)
        expectEqual(gate.preparedAction(at: now)?.requestID, current.id)
    }

    func testSelectionAndPurposeCannotBeTransferred() async throws {
        let gate = HumanDisclosureGate()
        let selected = UUID()
        let request = gate.begin(secretID: selected, purpose: .reveal)
        _ = try require(gate.prepare(syntheticSecret(), for: request, at: now))
        expectTrue(gate.consume(requestID: request.id, secretID: UUID(), purpose: .reveal, whileWindowActive: true, at: now) == nil)
        expectTrue(gate.consume(requestID: request.id, secretID: selected, purpose: .copy, whileWindowActive: true, at: now) == nil)
        expectEqual(gate.preparedAction(at: now)?.requestID, request.id)
        gate.cancel() // Native selection/section handlers must explicitly cancel.
        expectTrue(gate.consume(requestID: request.id, secretID: selected, purpose: .reveal, whileWindowActive: true, at: now) == nil)
    }

    func testPendingValueExpiresAtTwentySecondsAndIsSingleUse() async throws {
        let gate = HumanDisclosureGate()
        let id = UUID()
        let request = gate.begin(secretID: id, purpose: .copy)
        let ready = try require(gate.prepare(syntheticSecret(), for: request, at: now))
        expectEqual(ready.expiresAt, now.addingTimeInterval(20))
        expectTrue(gate.preparedAction(at: now.addingTimeInterval(19.999)) != nil)
        expectTrue(gate.consume(requestID: request.id, secretID: id, purpose: .copy, whileWindowActive: true, at: now.addingTimeInterval(20)) == nil)
        expectTrue(gate.preparedAction(at: now) == nil) // Time rollback cannot revive it.
        let next = gate.begin(secretID: id, purpose: .copy)
        _ = try require(gate.prepare(syntheticSecret(), for: next, at: now))
        _ = try require(gate.consume(requestID: next.id, secretID: id, purpose: .copy, whileWindowActive: true, at: now))
        expectTrue(gate.consume(requestID: next.id, secretID: id, purpose: .copy, whileWindowActive: true, at: now) == nil)
    }

    func testAliasesAndConcurrentConsumersShareOneUse() async throws {
        let gate = HumanDisclosureGate()
        let id = UUID()
        let request = gate.begin(secretID: id, purpose: .copy)
        _ = try require(gate.prepare(syntheticSecret(), for: request, at: now))
        let alias = gate
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0..<8 {
                group.addTask {
                    alias.consume(requestID: request.id, secretID: id, purpose: .copy, whileWindowActive: true, at: now) != nil
                }
            }
            var results: [Bool] = []
            for await result in group { results.append(result) }
            return results
        }
        expectEqual(results.filter { $0 }.count, 1)
        expectTrue(gate.preparedAction(at: now) == nil)
    }
}
