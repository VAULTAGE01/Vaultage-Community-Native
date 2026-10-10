import Foundation
import CommunityKit

/// Command-line self-test harness for the macOS Command Line Tools toolchain,
/// which ships neither XCTest nor Swift Testing. All cases are synthetic.
@main
enum TestMain {
    static func main() async {
        let suite = CommunityStoreTests()
        let disclosure = HumanDisclosureGateTests()
        var cases: [(String, @Sendable () async throws -> Void)] = [
            ("accountless workspace, namespace and label-only persistence", suite.testAccountlessEmptyWorkspaceAndLabelOnlyPersistence),
            ("failed save rollback", suite.testFailedSaveRollsBackByteIdenticalMetadataAndRetainsExistingCredentials),
            ("failed first save restores empty workspace", suite.testFailedFirstSaveRestoresAbsentMetadata),
            ("failed writes preserve metadata and credentials", suite.testMetadataWriteFailuresNeverMutateTheVaultOrPriorDocument),
            ("failed delete preserves references", suite.testFailedDeleteRetainsSecretAndEveryBinding),
            ("delete removes all references and isolates namespaces", suite.testSuccessfulDeleteRemovesAllReferencesAndPreservesOtherNamespaces),
            ("projects and binding upsert", suite.testProjectsBindingsUpsertAndProjectRemovalKeepCredentials),
            ("invalid inputs", suite.testInvalidInputsAreRefusedBeforeVaultAccessOrMetadataChanges),
            ("corrupt metadata and dangling references", suite.testCorruptMetadataAndDanglingReferencesFailClosedWithoutVaultAccess),
            ("metadata cannot select a Keychain account", suite.testMetadataSuppliedKeychainAccountsAreNeverUsed),
            ("symlinks and interrupted transactions", suite.testMetadataSymlinkAndInterruptedTransactionAreRefused),
            ("oversized, shared and hard-linked metadata", suite.testOversizedSharedAndHardLinkedMetadataAreRefused),
            ("FIFO metadata and export targets are refused without blocking", suite.testFIFORecordsAndExportTargetsAreRefusedWithoutBlocking),
            ("export confirmation, overwrite and symlink refusal", suite.testExportRequiresConfirmationAndNeverOverwritesOrFollowsSymlinks),
            ("literal export, shell roundtrip and private permissions", suite.testExportPreservesSupportedValuesAndRoundTripsThroughShell),
            ("ambiguous export characters are refused unchanged", suite.testExportRejectsAmbiguousCharactersWithoutAlteringMetadataOrValues),
            ("unsafe value and denied export leave no file", suite.testUnsafeExportValueAndDeniedReadNeverLeaveAPlaintextFile),
            ("export target creation race preserves the other file", suite.testExportTargetCreationRaceCannotOverwriteOrDisclose),
            ("failed staging leaves no public partial export", suite.testFailedExportStagingLeavesNoPublicPartialFile),
            ("failed cleanup preserves a competing final file", suite.testFailedExportCleanupPreservesCompetingFinalFile),
            ("failed cleanup preserves a replaced temporary inode", suite.testFailedExportCleanupDoesNotDeleteReplacedTemporaryInode),
            ("atomic publication refuses a competing target", suite.testAtomicExportPublicationDoesNotOverwriteACompetingTarget),
            ("separate store actors serialize writes", suite.testSeparateActorsReadLatestStateAndSerializeMetadataMutations),
            ("authentication focus change requires a separate active click", disclosure.testAuthenticationFocusLossRequiresSeparateExplicitConsume),
            ("ready focus loss and manual Hide clear protected pending state", disclosure.testReadyFocusLossAndManualCancelDropPendingValue),
            ("canceled and replaced authentication results are refused", disclosure.testCanceledAndReplacedAuthenticationResultsCannotBecomeReady),
            ("disclosure cannot transfer secret selection or purpose", disclosure.testSelectionAndPurposeCannotBeTransferred),
            ("pending disclosure expires at 20 seconds and is single use", disclosure.testPendingValueExpiresAtTwentySecondsAndIsSingleUse),
            ("disclosure aliases and concurrent consumers share one use", disclosure.testAliasesAndConcurrentConsumersShareOneUse)
        ]
        if ProcessInfo.processInfo.environment["COMMUNITY_TEST_NODE"] != nil {
            cases.append(("Node util.parseEnv literal roundtrip", suite.testExportRoundTripsThroughNodeParseEnv))
        } else {
            print("Node util.parseEnv check is opt-in: set COMMUNITY_TEST_NODE to its exact executable path.")
        }
        for (name, run) in cases {
            let before = CheckLog.shared.count
            do { try await run() }
            catch {
                // Never print injected errors: a badly behaved SecretVault might
                // include a protected value in its description.
                let detail = (error as? CommunityError).map { String(describing: $0) } ?? String(describing: type(of: error))
                recordFailure("Unexpected test error: \(detail)")
            }
            print("\(CheckLog.shared.count == before ? "PASS" : "FAIL"): \(name)")
        }
        let failures = CheckLog.shared.count
        print("\(cases.count) synthetic cases completed; \(failures) failed checks.")
        if failures > 0 { exit(1) }
    }
}

private final class CheckLog: @unchecked Sendable {
    static let shared = CheckLog()
    private let lock = NSLock()
    private var failures = 0
    var count: Int { lock.withLock { failures } }
    func fail(_ message: String, file: StaticString, line: UInt) {
        lock.withLock { failures += 1 }
        print("FAILED: \(message) (\(file):\(line))")
    }
}

func recordFailure(_ message: String, file: StaticString = #filePath, line: UInt = #line) {
    CheckLog.shared.fail(message, file: file, line: line)
}

func expectEqual<T: Equatable>(_ left: T, _ right: T, file: StaticString = #filePath, line: UInt = #line) {
    if left != right { recordFailure("Expected equality", file: file, line: line) }
}

func expectTrue(_ condition: Bool, file: StaticString = #filePath, line: UInt = #line) {
    if !condition { recordFailure("Expected true", file: file, line: line) }
}

func expectFalse(_ condition: Bool, file: StaticString = #filePath, line: UInt = #line) {
    if condition { recordFailure("Expected false", file: file, line: line) }
}

private struct MissingFixture: Error {}
func require<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T {
    guard let value else {
        recordFailure("Required test fixture is missing", file: file, line: line)
        throw MissingFixture()
    }
    return value
}
