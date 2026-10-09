import Darwin
import Foundation
import VaultageCore
@_spi(CommunityTesting) import CommunityKit

/// Tests use unique temporary directories and synthetic in-memory credentials.
/// They never open the owner's metadata or use the real Keychain.
struct CommunityStoreTests: Sendable {
    func testAccountlessEmptyWorkspaceAndLabelOnlyPersistence() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let initial = try await fixture.store.snapshot()
        expectEqual(initial, CommunitySnapshot())
        let summary = try await fixture.store.createSecret(title: "  Synthetic API  ", kind: .apiKey,
                                                          folder: "  Test Folder  ", value: Data("synthetic-not-a-real-key-582".utf8))
        expectEqual(summary.title, "Synthetic API")
        expectEqual(summary.folder, "Test Folder")
        let account = expectedAccount(for: summary.id)
        expectEqual(fixture.vault.accounts, [account])
        expectTrue(account.hasPrefix("community-v2.secret."))
        let reopened = CommunityStore(directory: fixture.directory, vault: fixture.vault)
        let snapshot = try await reopened.snapshot()
        expectEqual(snapshot.secrets, [summary])
        expectTrue(snapshot.projects.isEmpty)
        let result = try await reopened.readSecret(id: summary.id, prompt: "Reveal synthetic test item")
        expectTrue(result.matches("synthetic-not-a-real-key-582"))
        expectEqual(fixture.vault.reads.last?.account, account)
        expectEqual(fixture.vault.reads.last?.prompt, "Reveal synthetic test item")
        for file in try FileManager.default.contentsOfDirectory(at: fixture.directory, includingPropertiesForKeys: nil) {
            let contents = try Data(contentsOf: file)
            expectFalse(contents.range(of: Data("synthetic-not-a-real-key-582".utf8)) != nil)
        }
        let metadata = try Data(contentsOf: fixture.metadata)
        let json = try require(JSONSerialization.jsonObject(with: metadata) as? [String: Any])
        expectEqual(Set(json.keys), ["schemaVersion", "snapshot"])
        let attributes = try FileManager.default.attributesOfItem(atPath: fixture.metadata.path)
        expectEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let folderAttributes = try FileManager.default.attributesOfItem(atPath: fixture.directory.path)
        expectEqual((folderAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    func testFailedSaveRollsBackByteIdenticalMetadataAndRetainsExistingCredentials() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let existing = try await fixture.store.createSecret(title: "Existing", kind: .password, folder: "", value: Data("synthetic-existing".utf8))
        let before = try Data(contentsOf: fixture.metadata)
        fixture.vault.failNextSave()
        await assertFailure(.protectedValueUnavailable) {
            _ = try await fixture.store.createSecret(title: "New", kind: .password, folder: "", value: Data("synthetic-error-echo".utf8))
        }
        expectEqual(try Data(contentsOf: fixture.metadata), before)
        let after = try await fixture.store.snapshot()
        expectEqual(after.secrets, [existing])
        expectEqual(fixture.vault.accounts, [expectedAccount(for: existing.id)])
        expectFalse(FileManager.default.fileExists(atPath: fixture.rollback.path))
    }

    func testFailedFirstSaveRestoresAbsentMetadata() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        fixture.vault.failNextSave()
        await assertFailure(.protectedValueUnavailable) {
            _ = try await fixture.store.createSecret(title: "First", kind: .apiKey, folder: "", value: Data("synthetic-first".utf8))
        }
        expectFalse(FileManager.default.fileExists(atPath: fixture.metadata.path))
        expectFalse(FileManager.default.fileExists(atPath: fixture.rollback.path))
        let state = try await fixture.store.snapshot()
        expectEqual(state, CommunitySnapshot())
        expectTrue(fixture.vault.accounts.isEmpty)
    }

    func testMetadataWriteFailuresNeverMutateTheVaultOrPriorDocument() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let existing = try await fixture.store.createSecret(title: "Existing", kind: .apiKey, folder: "", value: Data("synthetic-existing".utf8))
        let before = try Data(contentsOf: fixture.metadata)
        let failing = CommunityStore(directory: fixture.directory, vault: fixture.vault, metadataWriteCheck: { throw SyntheticFailure() })
        let saves = fixture.vault.saveCalls
        let deletes = fixture.vault.deleteCalls
        await assertFailure(.storageUnavailable) {
            _ = try await failing.createSecret(title: "Not saved", kind: .apiKey, folder: "", value: Data("synthetic-not-saved".utf8))
        }
        await assertFailure(.storageUnavailable) { try await failing.deleteSecret(id: existing.id) }
        await assertFailure(.storageUnavailable) { _ = try await failing.createProject(name: "Not created") }
        expectEqual(fixture.vault.saveCalls, saves)
        expectEqual(fixture.vault.deleteCalls, deletes)
        expectEqual(try Data(contentsOf: fixture.metadata), before)
        let state = try await fixture.store.snapshot()
        expectEqual(state.secrets, [existing])
    }

    func testFailedDeleteRetainsSecretAndEveryBinding() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let secret = try await fixture.store.createSecret(title: "Bound", kind: .apiKey, folder: "", value: Data("synthetic-bound".utf8))
        let project = try await fixture.store.createProject(name: "Demo")
        for environment in project.environments {
            try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "API_KEY", secretID: secret.id)
        }
        let before = try await fixture.store.snapshot()
        let beforeBytes = try Data(contentsOf: fixture.metadata)
        fixture.vault.failNextDelete()
        await assertFailure(.protectedValueUnavailable) { try await fixture.store.deleteSecret(id: secret.id) }
        let after = try await fixture.store.snapshot()
        expectEqual(after, before)
        expectEqual(try Data(contentsOf: fixture.metadata), beforeBytes)
        expectTrue(fixture.vault.accounts.contains(expectedAccount(for: secret.id)))
        expectEqual(fixture.vault.deleteCalls.last, expectedAccount(for: secret.id))
    }

    func testSuccessfulDeleteRemovesAllReferencesAndPreservesOtherNamespaces() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let a = try await fixture.store.createSecret(title: "A", kind: .apiKey, folder: "", value: Data("synthetic-a".utf8))
        let b = try await fixture.store.createSecret(title: "B", kind: .password, folder: "", value: Data("synthetic-b".utf8))
        fixture.vault.seed(account: "pro-existing-record", value: Data("synthetic-pro-isolation".utf8))
        let first = try await fixture.store.createProject(name: "First")
        let second = try await fixture.store.createProject(name: "Second")
        for project in [first, second] {
            for environment in project.environments {
                try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "A_KEY", secretID: a.id)
                try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "B_KEY", secretID: b.id)
            }
        }
        try await fixture.store.deleteSecret(id: a.id)
        let state = try await fixture.store.snapshot()
        expectEqual(state.secrets, [b])
        expectTrue(state.projects.flatMap(\.environments).flatMap(\.bindings).allSatisfy { $0.secretID == b.id })
        expectEqual(fixture.vault.accounts, [expectedAccount(for: b.id), "pro-existing-record"])
        await assertFailure(.notFound) { _ = try await fixture.store.readSecret(id: a.id, prompt: "Reveal") }
        let deletes = fixture.vault.deleteCalls
        await assertFailure(.notFound) { try await fixture.store.deleteSecret(id: UUID()) }
        expectEqual(fixture.vault.deleteCalls, deletes)
    }

    func testProjectsBindingsUpsertAndProjectRemovalKeepCredentials() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let a = try await fixture.store.createSecret(title: "A", kind: .apiKey, folder: "", value: Data("synthetic-a".utf8))
        let b = try await fixture.store.createSecret(title: "B", kind: .apiKey, folder: "", value: Data("synthetic-b".utf8))
        let project = try await fixture.store.createProject(name: "  Demo  ")
        expectEqual(project.environments.map(\.name), ["Development", "Staging", "Production"])
        let environment = project.environments[0]
        try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "API_KEY", secretID: a.id)
        let first = try await fixture.store.snapshot()
        let initial = try require(first.projects[0].environments[0].bindings.first)
        try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "API_KEY", secretID: b.id)
        let updated = try await fixture.store.snapshot()
        expectEqual(updated.projects[0].environments[0].bindings, [EnvironmentBinding(id: initial.id, key: "API_KEY", secretID: b.id)])
        await assertFailure(.duplicateProject) { _ = try await fixture.store.createProject(name: "demo") }
        await assertFailure(.notFound) { try await fixture.store.setBinding(projectID: project.id, environmentID: environment.id, key: "MISSING", secretID: UUID()) }
        await assertFailure(.notFound) { try await fixture.store.setBinding(projectID: project.id, environmentID: UUID(), key: "WRONG", secretID: a.id) }
        try await fixture.store.removeBinding(projectID: project.id, environmentID: environment.id, bindingID: initial.id)
        let removed = try await fixture.store.snapshot()
        expectTrue(removed.projects[0].environments[0].bindings.isEmpty)
        try await fixture.store.deleteProject(id: project.id)
        let end = try await fixture.store.snapshot()
        expectEqual(end.secrets, [a, b])
        expectTrue(end.projects.isEmpty)
        expectTrue(fixture.vault.deleteCalls.isEmpty)
    }

    func testInvalidInputsAreRefusedBeforeVaultAccessOrMetadataChanges() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        for title in ["", "   ", "Bad\nName", String(repeating: "x", count: 201)] {
            await assertFailure(.invalidLabel) {
                _ = try await fixture.store.createSecret(title: title, kind: .password, folder: "", value: Data("synthetic".utf8))
            }
        }
        for value in [Data(), Data([0xFF]), Data(repeating: 65, count: 65_537)] {
            await assertFailure(.invalidValue) {
                _ = try await fixture.store.createSecret(title: "Valid", kind: .apiKey, folder: "", value: value)
            }
        }
        await assertFailure(.invalidLabel) { _ = try await fixture.store.createProject(name: "Bad\0Project") }
        for key in ["", "0KEY", "KEY VALUE", "KEY=VALUE", "KEY\nOTHER", "Á_KEY", String(repeating: "A", count: 129)] {
            await assertFailure(.invalidEnvironmentKey) {
                try await fixture.store.setBinding(projectID: UUID(), environmentID: UUID(), key: key, secretID: UUID())
            }
        }
        expectTrue(fixture.vault.saveCalls.isEmpty)
        expectTrue(fixture.vault.reads.isEmpty)
        expectFalse(FileManager.default.fileExists(atPath: fixture.metadata.path))
    }

    func testCorruptMetadataAndDanglingReferencesFailClosedWithoutVaultAccess() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        _ = try await fixture.store.createProject(name: "Fixture")
        let knownGood = try Data(contentsOf: fixture.metadata)
        var document = try require(JSONSerialization.jsonObject(with: knownGood) as? [String: Any])
        document["schemaVersion"] = 999
        try fixture.writeMetadata(JSONSerialization.data(withJSONObject: document))
        await assertFailure(.malformedMetadata) { _ = try await fixture.store.snapshot() }
        document["schemaVersion"] = 1
        var snapshot = try require(document["snapshot"] as? [String: Any])
        var projects = try require(snapshot["projects"] as? [[String: Any]])
        var environments = try require(projects[0]["environments"] as? [[String: Any]])
        environments[0]["bindings"] = [["id": UUID().uuidString, "key": "UNBOUND", "secretID": UUID().uuidString]]
        projects[0]["environments"] = environments
        snapshot["projects"] = projects
        document["snapshot"] = snapshot
        try fixture.writeMetadata(JSONSerialization.data(withJSONObject: document))
        await assertFailure(.malformedMetadata) { _ = try await fixture.store.snapshot() }
        await assertFailure(.malformedMetadata) { _ = try await fixture.store.createSecret(title: "No", kind: .apiKey, folder: "", value: Data("synthetic".utf8)) }
        expectTrue(fixture.vault.saveCalls.isEmpty)
        expectTrue(fixture.vault.reads.isEmpty)
        try fixture.writeMetadata(Data("not json".utf8))
        await assertFailure(.malformedMetadata) { _ = try await fixture.store.snapshot() }
    }

    func testMetadataSuppliedKeychainAccountsAreNeverUsed() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let summary = try await fixture.store.createSecret(title: "Synthetic", kind: .apiKey, folder: "", value: Data("synthetic-value".utf8))
        var document = try require(JSONSerialization.jsonObject(with: Data(contentsOf: fixture.metadata)) as? [String: Any])
        var snapshot = try require(document["snapshot"] as? [String: Any])
        var summaries = try require(snapshot["secrets"] as? [[String: Any]])
        summaries[0]["account"] = "pro-existing-record"
        snapshot["secrets"] = summaries
        document["snapshot"] = snapshot
        try fixture.writeMetadata(JSONSerialization.data(withJSONObject: document))
        _ = try await fixture.store.readSecret(id: summary.id, prompt: "Reveal")
        expectEqual(fixture.vault.reads.last?.account, expectedAccount(for: summary.id))
        try await fixture.store.deleteSecret(id: summary.id)
        expectEqual(fixture.vault.deleteCalls.last, expectedAccount(for: summary.id))
    }

    func testMetadataSymlinkAndInterruptedTransactionAreRefused() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let project = try await fixture.store.createProject(name: "Retained")
        let before = try Data(contentsOf: fixture.metadata)
        let outside = fixture.root.appendingPathComponent("unrelated.json")
        try before.write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
        try FileManager.default.removeItem(at: fixture.metadata)
        try FileManager.default.createSymbolicLink(at: fixture.metadata, withDestinationURL: outside)
        await assertFailure(.unsafeFile) { _ = try await fixture.store.snapshot() }
        await assertFailure(.unsafeFile) { _ = try await fixture.store.createProject(name: "No") }
        expectEqual(try Data(contentsOf: outside), before)
        try FileManager.default.removeItem(at: fixture.metadata)
        try fixture.writeMetadata(before)
        try before.write(to: fixture.rollback)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fixture.rollback.path)
        await assertFailure(.recoveryRequired) { _ = try await fixture.store.snapshot() }
        expectTrue(fixture.vault.deleteCalls.isEmpty)
        try FileManager.default.removeItem(at: fixture.rollback)
        let reopened = try await fixture.store.snapshot()
        expectEqual(reopened.projects, [project])
    }

    func testOversizedSharedAndHardLinkedMetadataAreRefused() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        _ = try await fixture.store.createProject(name: "Fixture")
        let before = try Data(contentsOf: fixture.metadata)
        try fixture.writeMetadata(Data(repeating: 32, count: 4 * 1024 * 1024 + 1))
        await assertFailure(.malformedMetadata) { _ = try await fixture.store.snapshot() }
        try fixture.writeMetadata(before)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fixture.metadata.path)
        await assertFailure(.unsafeFile) { _ = try await fixture.store.snapshot() }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fixture.metadata.path)
        let alias = fixture.root.appendingPathComponent("hard-linked.json")
        try FileManager.default.linkItem(at: fixture.metadata, to: alias)
        await assertFailure(.unsafeFile) { _ = try await fixture.store.snapshot() }
        expectTrue(fixture.vault.reads.isEmpty)
        expectTrue(fixture.vault.deleteCalls.isEmpty)
        expectEqual(try Data(contentsOf: alias), before)
    }

    func testFIFORecordsAndExportTargetsAreRefusedWithoutBlocking() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-fifo-test")
        let target = fixture.root.appendingPathComponent("pipe.env")
        expectEqual(mkfifo(target.path, 0o600), 0)
        await assertFailure(.unsafeFile) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                       to: target, confirmation: "EXPORT")
        }
        expectTrue(fixture.vault.reads.isEmpty)
        let previous = try Data(contentsOf: fixture.metadata)
        try FileManager.default.removeItem(at: fixture.metadata)
        expectEqual(mkfifo(fixture.metadata.path, 0o600), 0)
        await assertFailure(.unsafeFile) { _ = try await fixture.store.snapshot() }
        try FileManager.default.removeItem(at: fixture.metadata)
        try fixture.writeMetadata(previous)
        let lock = fixture.directory.appendingPathComponent(".workspace.lock")
        try FileManager.default.removeItem(at: lock)
        expectEqual(mkfifo(lock.path, 0o600), 0)
        await assertFailure(.unsafeFile) { _ = try await fixture.store.snapshot() }
        expectTrue(fixture.vault.reads.isEmpty)
    }

    func testExportRequiresConfirmationAndNeverOverwritesOrFollowsSymlinks() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-export")
        let target = fixture.root.appendingPathComponent("new.env")
        for confirmation in ["", "export", "EXPORT "] {
            await assertFailure(.exportConfirmationRequired) {
                try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: confirmation)
            }
        }
        expectTrue(fixture.vault.reads.isEmpty)
        expectFalse(FileManager.default.fileExists(atPath: target.path))
        try Data("existing unrelated content".utf8).write(to: target)
        await assertFailure(.unsafeFile) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
        }
        expectEqual(try String(contentsOf: target, encoding: .utf8), "existing unrelated content")
        let symlink = fixture.root.appendingPathComponent("linked.env")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        await assertFailure(.unsafeFile) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: symlink, confirmation: "EXPORT")
        }
        let linkedFolder = fixture.root.appendingPathComponent("linked-folder")
        try FileManager.default.createSymbolicLink(at: linkedFolder, withDestinationURL: fixture.directory)
        await assertFailure(.unsafeFile) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                       to: linkedFolder.appendingPathComponent("new.env"), confirmation: "EXPORT")
        }
        expectTrue(fixture.vault.reads.isEmpty)
    }

    func testExportPreservesSupportedValuesAndRoundTripsThroughShell() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let value = "  synthetic $(printf bad) $HOME `printf bad` \"# café = literal  "
        let binding = try await fixture.createBoundSecret(value: value)
        let target = fixture.root.appendingPathComponent("new.env")
        let metadataBefore = try Data(contentsOf: fixture.metadata)
        try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
        let output = try String(contentsOf: target, encoding: .utf8)
        expectTrue(output.contains("API_KEY='" + value + "'\n"))
        expectEqual(output.split(separator: "\n").count, 2)
        expectEqual(try Data(contentsOf: fixture.metadata), metadataBefore)
        expectEqual(fixture.vault.reads.count, 1)
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        expectEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let roundtrip = try runSyntheticParser(executable: URL(fileURLWithPath: "/bin/sh"), arguments: [
            "-c", ". \"$1\"; printf '%s' \"$API_KEY\"", "community-synthetic-roundtrip", target.path
        ])
        expectEqual(roundtrip.status, 0)
        expectEqual(roundtrip.output, Data(value.utf8))
    }

    func testExportRejectsAmbiguousCharactersWithoutAlteringMetadataOrValues() async throws {
        for value in ["synthetic'apostrophe", "synthetic\\backslash", "synthetic\rreturn", "synthetic\nline", "synthetic\0null", "synthetic\ttab", "synthetic\u{7f}delete", "synthetic\u{85}nextline", "synthetic\u{2028}separator"] {
            let fixture = try Fixture()
            defer { fixture.remove() }
            let binding = try await fixture.createBoundSecret(value: value)
            let target = fixture.root.appendingPathComponent("new.env")
            let before = try Data(contentsOf: fixture.metadata)
            do {
                try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
                recordFailure("Expected unsupported export refusal")
            } catch {
                expectEqual(error as? CommunityError, .exportValueUnsupported)
                expectFalse(error.localizedDescription.contains(value))
            }
            expectFalse(FileManager.default.fileExists(atPath: target.path))
            expectEqual(try Data(contentsOf: fixture.metadata), before)
            let retained = try await fixture.store.readSecret(id: binding.secret.id, prompt: "Verify synthetic retained item")
            expectTrue(retained.matches(value))
        }
    }

    /// Opt-in external parser check. Supply COMMUNITY_TEST_NODE with the exact
    /// Node executable to test. No credentials appear in its command arguments:
    /// both the export and comparison values are synthetic temporary files.
    func testExportRoundTripsThroughNodeParseEnv() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let value = "  synthetic $(printf bad) $HOME `printf bad` \"# café = literal  "
        let binding = try await fixture.createBoundSecret(value: value)
        let target = fixture.root.appendingPathComponent("new.env")
        try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
        let expected = fixture.root.appendingPathComponent("synthetic-expected.json")
        try JSONSerialization.data(withJSONObject: ["API_KEY": value]).write(to: expected)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: expected.path)
        let script = fixture.root.appendingPathComponent("parser-roundtrip.mjs")
        try Data("""
        import { readFileSync } from 'node:fs';
        import { parseEnv } from 'node:util';
        const actual = parseEnv(readFileSync(process.argv[2], 'utf8'));
        const expected = JSON.parse(readFileSync(process.argv[3], 'utf8'));
        // Never print parsed or expected credential fixture content, even on error.
        const passed = Object.keys(actual).length === 1 && actual.API_KEY === expected.API_KEY;
        console.log(`Node ${process.version} util.parseEnv synthetic roundtrip: ${passed ? 'PASS' : 'FAIL'}`);
        process.exitCode = passed ? 0 : 1;
        """.utf8).write(to: script)
        guard let nodePath = ProcessInfo.processInfo.environment["COMMUNITY_TEST_NODE"] else { throw SyntheticFailure() }
        let parsed = try runSyntheticParser(executable: URL(fileURLWithPath: nodePath), arguments: [script.path, target.path, expected.path])
        expectEqual(parsed.status, 0)
        // The script emits only a runtime version and pass/fail, not values.
        let message = String(decoding: parsed.output, as: UTF8.self)
        expectTrue(message.contains("synthetic roundtrip: PASS"))
        if parsed.status == 0 { print(message.trimmingCharacters(in: .whitespacesAndNewlines)) }
    }

    func testUnsafeExportValueAndDeniedReadNeverLeaveAPlaintextFile() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic\nINJECTED=bad")
        let target = fixture.root.appendingPathComponent("new.env")
        await assertFailure(.exportValueUnsupported) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
        }
        expectFalse(FileManager.default.fileExists(atPath: target.path))
        fixture.vault.failReads()
        await assertFailure(.protectedValueUnavailable) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id, to: target, confirmation: "EXPORT")
        }
        expectFalse(FileManager.default.fileExists(atPath: target.path))
        await assertFailure(.protectedValueUnavailable) { _ = try await fixture.store.readSecret(id: binding.secret.id, prompt: "Reveal") }
    }

    func testExportTargetCreationRaceCannotOverwriteOrDisclose() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-race-value")
        let target = fixture.root.appendingPathComponent("raced.env")
        fixture.vault.onRead {
            // The destination was absent during preflight; another operation
            // creates it while the human is authenticating. O_EXCL must still
            // refuse the actual write rather than replacing that new file.
            try? Data("unrelated-race-winner".utf8).write(to: target)
        }
        await assertFailure(.unsafeFile) {
            try await fixture.store.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                       to: target, confirmation: "EXPORT")
        }
        expectEqual(try String(contentsOf: target, encoding: .utf8), "unrelated-race-winner")
        expectEqual(fixture.vault.reads.count, 1)
    }

    func testFailedExportStagingLeavesNoPublicPartialFile() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-staged-value")
        let target = fixture.root.appendingPathComponent("new.env")
        let before = try Data(contentsOf: fixture.metadata)
        let failing = CommunityStore(directory: fixture.directory, vault: fixture.vault, metadataWriteCheck: {},
                                     exportPublicationCheck: { throw SyntheticFailure() })
        await assertFailure(.storageUnavailable) {
            try await failing.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                  to: target, confirmation: "EXPORT")
        }
        expectFalse(FileManager.default.fileExists(atPath: target.path))
        expectEqual(try Data(contentsOf: fixture.metadata), before)
        let temporaryFiles = try FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(".vaultage-export-") }
        expectTrue(temporaryFiles.isEmpty)
        let retained = try await fixture.store.readSecret(id: binding.secret.id, prompt: "Verify synthetic retained item")
        expectTrue(retained.matches("synthetic-staged-value"))
    }

    func testFailedExportCleanupPreservesCompetingFinalFile() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-staged-value")
        let target = fixture.root.appendingPathComponent("raced.env")
        let failing = CommunityStore(directory: fixture.directory, vault: fixture.vault, metadataWriteCheck: {}, exportPublicationCheck: {
            // A different writer wins the final path before an injected staging
            // failure. Cleanup may remove only our private UUID temporary inode.
            try Data("unrelated-final-file".utf8).write(to: target)
            throw SyntheticFailure()
        })
        await assertFailure(.storageUnavailable) {
            try await failing.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                  to: target, confirmation: "EXPORT")
        }
        expectEqual(try String(contentsOf: target, encoding: .utf8), "unrelated-final-file")
        let temporaryFiles = try FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(".vaultage-export-") }
        expectTrue(temporaryFiles.isEmpty)
    }

    func testFailedExportCleanupDoesNotDeleteReplacedTemporaryInode() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-staged-value")
        let target = fixture.root.appendingPathComponent("new.env")
        let moved = fixture.root.appendingPathComponent("moved-synthetic-staging.tmp")
        let failing = CommunityStore(directory: fixture.directory, vault: fixture.vault, metadataWriteCheck: {}, exportPublicationCheck: {
            let temporary = try require(FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
                .first { $0.lastPathComponent.hasPrefix(".vaultage-export-") })
            try FileManager.default.moveItem(at: temporary, to: moved)
            try Data("unrelated-temporary-replacement".utf8).write(to: temporary)
            throw SyntheticFailure()
        })
        await assertFailure(.storageUnavailable) {
            try await failing.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                  to: target, confirmation: "EXPORT")
        }
        expectFalse(FileManager.default.fileExists(atPath: target.path))
        let replacement = try require(FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
            .first { $0.lastPathComponent.hasPrefix(".vaultage-export-") })
        expectEqual(try String(contentsOf: replacement, encoding: .utf8), "unrelated-temporary-replacement")
        // The moved inode is our synthetic export, which this fixture owns and
        // removes at teardown; production cleanup does not chase renamed files.
        expectTrue(FileManager.default.fileExists(atPath: moved.path))
    }

    func testAtomicExportPublicationDoesNotOverwriteACompetingTarget() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binding = try await fixture.createBoundSecret(value: "synthetic-staged-value")
        let target = fixture.root.appendingPathComponent("raced.env")
        let competing = CommunityStore(directory: fixture.directory, vault: fixture.vault, metadataWriteCheck: {}, exportPublicationCheck: {
            // The temporary export has been completely written and fsynced;
            // create the final target immediately before atomic publication.
            try Data("unrelated-publication-winner".utf8).write(to: target)
        })
        await assertFailure(.unsafeFile) {
            try await competing.exportEnvironment(projectID: binding.project.id, environmentID: binding.environment.id,
                                                    to: target, confirmation: "EXPORT")
        }
        expectEqual(try String(contentsOf: target, encoding: .utf8), "unrelated-publication-winner")
        let temporaryFiles = try FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix(".vaultage-export-") }
        expectTrue(temporaryFiles.isEmpty)
    }

    func testSeparateActorsReadLatestStateAndSerializeMetadataMutations() async throws {
        // Exercise simultaneous first launch, not only an existing lock file.
        for _ in 0..<10 {
            let fixture = try Fixture()
            defer { fixture.remove() }
            let other = CommunityStore(directory: fixture.directory, vault: fixture.vault)
            async let first = fixture.store.createProject(name: "First")
            async let second = other.createProject(name: "Second")
            _ = try await (first, second)
            let state = try await fixture.store.snapshot()
            expectEqual(Set(state.projects.map(\.name)), ["First", "Second"])
            let latest = try await other.snapshot()
            expectEqual(state, latest)
        }
    }

    private func assertFailure(_ expected: CommunityError, operation: () async throws -> Void,
                               file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); recordFailure("Expected refusal", file: file, line: line) }
        catch {
            expectEqual(error as? CommunityError, expected, file: file, line: line)
            expectFalse(error.localizedDescription.contains("synthetic-error-echo"), file: file, line: line)
        }
    }
}

private struct Fixture: Sendable {
    let root: URL
    let directory: URL
    let vault: SyntheticVault
    let store: CommunityStore
    var metadata: URL { directory.appendingPathComponent("workspace.json") }
    var rollback: URL { directory.appendingPathComponent("workspace.previous.json") }

    init() throws {
        // Foundation may retain macOS's /var alias even after resolvingSymlinks.
        // Use realpath on the known system temp directory before adding our own
        // unique folder. The store itself still rejects every symlink component.
        guard let resolved = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw SyntheticFailure() }
        let temporary = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
        free(resolved)
        root = temporary.appendingPathComponent("VaultageCommunityTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        directory = root.appendingPathComponent("metadata", isDirectory: true)
        vault = SyntheticVault()
        store = CommunityStore(directory: directory, vault: vault)
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
    func writeMetadata(_ data: Data) throws {
        try data.write(to: metadata)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metadata.path)
    }
    func createBoundSecret(value: String) async throws -> (secret: SecretSummary, project: CommunityProject, environment: ProjectEnvironment) {
        let secret = try await store.createSecret(title: "Synthetic", kind: .apiKey, folder: "", value: Data(value.utf8))
        let project = try await store.createProject(name: "Synthetic Project")
        let environment = project.environments[0]
        try await store.setBinding(projectID: project.id, environmentID: environment.id, key: "API_KEY", secretID: secret.id)
        return (secret, project, environment)
    }
}

private struct SyntheticFailure: Error, LocalizedError {
    var errorDescription: String? { "synthetic-error-echo" }
}

/// Synthetic parser test only. Stderr is discarded rather than echoing arbitrary
/// parser error text, and stdout is captured for value comparisons, never logged.
private func runSyntheticParser(executable: URL, arguments: [String]) throws -> (status: Int32, output: Data) {
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    // Never inherit the owner's API keys, NODE_OPTIONS or other session state.
    process.environment = ["PATH": "/usr/bin:/bin", "HOME": "/synthetic-community-test-home"]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do { try process.run() }
    catch { throw SyntheticFailure() }
    let bytes = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, bytes)
}

private final class SyntheticVault: SecretVault, @unchecked Sendable {
    struct Read: Equatable { let account: String; let prompt: String }
    private let lock = NSLock()
    private var records: [String: Data] = [:]
    private var recordedSaves: [String] = []
    private var recordedDeletes: [String] = []
    private var recordedReads: [Read] = []
    private var saveFailure = false
    private var deleteFailure = false
    private var readFailure = false
    private var readHook: (@Sendable () -> Void)?

    var accounts: Set<String> { lock.withLock { Set(records.keys) } }
    var saveCalls: [String] { lock.withLock { recordedSaves } }
    var deleteCalls: [String] { lock.withLock { recordedDeletes } }
    var reads: [Read] { lock.withLock { recordedReads } }
    func failNextSave() { lock.withLock { saveFailure = true } }
    func failNextDelete() { lock.withLock { deleteFailure = true } }
    func failReads() { lock.withLock { readFailure = true } }
    func onRead(_ action: @escaping @Sendable () -> Void) { lock.withLock { readHook = action } }
    func seed(account: String, value: Data) { lock.withLock { records[account] = value } }

    func save(_ secret: Data, account: String) throws {
        try lock.withLock {
            recordedSaves.append(account)
            if saveFailure { saveFailure = false; throw SyntheticFailure() }
            guard records[account] == nil else { throw SyntheticFailure() }
            records[account] = secret
        }
    }
    func read(account: String, prompt: String) throws -> VaultSecret {
        try lock.withLock {
            recordedReads.append(Read(account: account, prompt: prompt))
            guard !readFailure, let value = records[account] else { throw SyntheticFailure() }
            readHook?()
            return VaultSecret(value)
        }
    }
    func delete(account: String) throws {
        try lock.withLock {
            recordedDeletes.append(account)
            if deleteFailure { deleteFailure = false; throw SyntheticFailure() }
            records.removeValue(forKey: account)
        }
    }
}

/// Expected namespace is part of the contract, independently checked here.
private func expectedAccount(for id: UUID) -> String { "community-v2.secret." + id.uuidString.lowercased() }
