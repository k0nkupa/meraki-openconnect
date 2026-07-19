import Foundation
import XCTest
@testable import MerakiOpenConnect

final class ProcessVPNCLITests: XCTestCase {
    private var homes: [URL] = []

    override func tearDownWithError() throws {
        for home in homes {
            try? FileManager.default.removeItem(at: home)
        }
        homes.removeAll()
    }

    func testResolverRejectsMissingExecutable() throws {
        let home = try temporaryHome()

        XCTAssertThrowsError(try ProcessVPNCLI.resolveExecutable(homeDirectory: home)) {
            XCTAssertEqual($0 as? CLIProcessError, .executableMissing)
        }
    }

    func testResolverAllowsUserOwnedExecutableAtFixedPath() throws {
        let home = try temporaryHome(withExecutable: true)

        let resolved = try ProcessVPNCLI.resolveExecutable(homeDirectory: home)

        XCTAssertEqual(resolved.path, home.appendingPathComponent(".local/bin/meraki-openconnect").path)
    }

    func testResolverRejectsResolvedTargetOutsideHomeDirectory() throws {
        let home = try temporaryHome()
        let executable = home.appendingPathComponent(".local/bin/meraki-openconnect")
        try FileManager.default.createDirectory(
            at: executable.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createSymbolicLink(
            at: executable,
            withDestinationURL: fixtureURL
        )

        XCTAssertThrowsError(try ProcessVPNCLI.resolveExecutable(homeDirectory: home)) {
            XCTAssertEqual($0 as? CLIProcessError, .unsafeExecutable)
        }
    }

    func testDoctorUsesOnlyDoctorJSONArgumentsAndMinimalEnvironment() async throws {
        let home = try readyHome()
        setenv("MerakiOpenConnect_TEST_SECRET", "must-not-leak", 1)
        defer { unsetenv("MerakiOpenConnect_TEST_SECRET") }
        let cli = ProcessVPNCLI(homeDirectory: home)

        _ = try await cli.doctor()

        XCTAssertEqual(try text(at: home, name: "invocations"), "doctor --json\n")
        let environment = try text(at: home, name: "environment")
        XCTAssertFalse(environment.contains("MerakiOpenConnect_TEST_SECRET"))
        XCTAssertTrue(environment.contains("HOME=\(home.path)"))
        XCTAssertTrue(environment.contains("LANG=en_NZ.UTF-8"))
        XCTAssertTrue(environment.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"))
        XCTAssertFalse(environment.contains("/bin/sh -c"))
    }

    func testDoctorDecodesSetupReportFromExitFour() async throws {
        let home = try readyHome()
        try write("4\n", to: home, name: "doctor-exit")
        try write(doctorJSON(openconnect: false), to: home, name: "doctor.json")

        let report = try await ProcessVPNCLI(homeDirectory: home).doctor()

        XCTAssertFalse(report.openconnect)
        XCTAssertEqual(report.setupIssue?.command, "brew install openconnect")
    }

    func testStatusRejectsMalformedJSON() async throws {
        let home = try readyHome()
        try write("not-json\n", to: home, name: "status.json")

        await assertThrows(.invalidJSON) {
            _ = try await ProcessVPNCLI(homeDirectory: home).status()
        }
    }

    func testShortCommandTimesOutAfterInjectedDeadline() async throws {
        let home = try readyHome()
        try write("1\n", to: home, name: "disconnect-seconds")
        let cli = ProcessVPNCLI(
            homeDirectory: home,
            sleeper: { _ in }
        )

        await assertThrows(.timedOut) {
            _ = try await cli.disconnect()
        }
    }

    func testCaptureKeepsFirst64KiBAndDrainsRemainingOutput() async throws {
        let home = try readyHome()
        try write(String(repeating: "x", count: 80_000), to: home, name: "disconnect-output")

        let result = try await ProcessVPNCLI(homeDirectory: home).disconnect()

        XCTAssertEqual(result.stdout.utf8.count, 65_536)
        XCTAssertEqual(result.stdout, String(repeating: "x", count: 65_536))
    }

    func testStartConnectReturnsBeforeChildTerminates() async throws {
        let home = try readyHome()
        try write("1\n", to: home, name: "connect-seconds")

        let handle = try await ProcessVPNCLI(homeDirectory: home).startConnect()

        let immediateResult = await handle.resultIfFinished()
        XCTAssertNil(immediateResult)
        var completedResult: CommandResult?
        for _ in 0..<30 {
            completedResult = await handle.resultIfFinished()
            if completedResult != nil { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertEqual(completedResult?.exitCode, 0)
    }

    func testDisconnectRejectsNonzeroExit() async throws {
        let home = try readyHome()
        try write("9\n", to: home, name: "disconnect-exit")

        await assertThrows(.nonzeroExit(9, "test disconnect failure\n")) {
            _ = try await ProcessVPNCLI(homeDirectory: home).disconnect()
        }
    }

    private var fixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("TestSupport/fake-meraki-openconnect")
    }

    private func temporaryHome(withExecutable: Bool = false) throws -> URL {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("MerakiOpenConnectTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        homes.append(home)
        if withExecutable {
            let destination = home.appendingPathComponent(".local/bin/meraki-openconnect")
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try FileManager.default.copyItem(at: fixtureURL, to: destination)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: destination.path
            )
        }
        return home
    }

    private func readyHome() throws -> URL {
        let home = try temporaryHome(withExecutable: true)
        try write(doctorJSON(), to: home, name: "doctor.json")
        try write(#"{"connected":false,"pid":null,"interface":null,"transport":null}"#, to: home, name: "status.json")
        try write("0\n", to: home, name: "connect-seconds")
        return home
    }

    private func doctorJSON(openconnect: Bool = true) -> String {
        """
        {
          "openconnect": \(openconnect),
          "openconnect_saml": true,
          "chrome_available": true,
          "chrome_profile_available": true,
          "profile_configured": true,
          "settings_configured": true,
          "extension_configured": true,
          "native_messaging_configured": true,
          "extension_permission_granted": true,
          "certificate_pinned": true,
          "privileged_helper_installed": true,
          "native_worker_installed": true,
          "policy_digest_matches": true,
          "cisco_connected": false,
          "connected": false,
          "pid": null,
          "interface": null,
          "transport": null
        }
        """
    }

    private func write(_ value: String, to home: URL, name: String) throws {
        try Data(value.utf8).write(to: home.appendingPathComponent(name))
    }

    private func text(at home: URL, name: String) throws -> String {
        try String(contentsOf: home.appendingPathComponent(name), encoding: .utf8)
    }

    private func assertThrows(
        _ expected: CLIProcessError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected \(expected)")
        } catch {
            XCTAssertEqual(error as? CLIProcessError, expected)
        }
    }
}
