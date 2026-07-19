import Foundation
import XCTest
@testable import MerakiOpenConnect

@MainActor
final class VPNControllerTests: XCTestCase {
    func testMenuIconAndActionMappings() {
        XCTAssertEqual(AppPhase.disconnected.systemImage, "shield")
        XCTAssertEqual(AppPhase.connecting.systemImage, "shield.lefthalf.filled")
        XCTAssertEqual(AppPhase.connected(connectedStatus).systemImage, "checkmark.shield.fill")
        XCTAssertEqual(AppPhase.error("safe").systemImage, "exclamationmark.shield.fill")

        XCTAssertEqual(AppPhase.disconnected.menuAction(verifiedConnected: false), .connect)
        XCTAssertEqual(AppPhase.connecting.menuAction(verifiedConnected: false), .disconnect)
        XCTAssertEqual(AppPhase.connected(connectedStatus).menuAction(verifiedConnected: true), .disconnect)
        XCTAssertEqual(AppPhase.error("safe").menuAction(verifiedConnected: true), .disconnect)
        XCTAssertEqual(AppPhase.error("safe").menuAction(verifiedConnected: false), .none)
        XCTAssertEqual(AppPhase.setupRequired(doctor(openconnect: false).setupIssue!).menuAction(verifiedConnected: false), .none)
        XCTAssertFalse(AppPhase.connecting.mutationEnabled)
        XCTAssertFalse(AppPhase.disconnecting.mutationEnabled)
    }

    func testStartShowsSetupRequiredBeforeConnectIsEnabled() async {
        let fake = FakeVPNCLI(doctors: [.success(doctor(openconnect: false))], statuses: [.success(disconnected)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.start()

        XCTAssertEqual(controller.phase, .setupRequired(doctor(openconnect: false).setupIssue!))
        XCTAssertNotNil(controller.setupIssue)
        let calls = await fake.recordedCalls()
        XCTAssertEqual(calls, ["doctor", "status"])
    }

    func testStartShowsDisconnectedWhenDoctorIsReady() async {
        let fake = FakeVPNCLI(doctors: [.success(doctor())], statuses: [.success(disconnected)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.start()

        XCTAssertEqual(controller.phase, .disconnected)
        XCTAssertEqual(controller.statusLine, "Disconnected")
    }

    func testStartAdoptsExistingVerifiedConnection() async {
        let connected = VPNStatus(connected: true, pid: 44, interface: "utun9", transport: "dtls")
        let fake = FakeVPNCLI(doctors: [.success(doctor())], statuses: [.success(connected)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.start()

        XCTAssertEqual(controller.phase, .connected(connected))
        XCTAssertEqual(controller.connectionDetail, "utun9 · dtls")
    }

    func testMalformedDoctorBecomesErrorNotDisconnected() async {
        let fake = FakeVPNCLI(doctors: [.failure(.invalidJSON)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.start()

        XCTAssertEqual(controller.phase, .error("Unable to verify Meraki OpenConnect readiness."))
        XCTAssertNil(controller.status)
    }

    func testCiscoConflictIsSetupRequiredWithoutACommand() async {
        let conflict = doctor(ciscoConnected: true)
        let fake = FakeVPNCLI(doctors: [.success(conflict)], statuses: [.success(disconnected)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.start()

        XCTAssertEqual(controller.setupIssue?.command, nil)
        XCTAssertEqual(controller.statusLine, "Setup required")
    }

    func testConnectPreflightsDoctorAndStatusBeforeStartingChild() async {
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(connectedStatus)],
            handles: [ConnectHandle()]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.connect()

        let calls = await fake.recordedCalls()
        XCTAssertEqual(calls, ["doctor", "status", "startConnect", "status"])
    }

    func testConnectTransitionsConnectingToConnectedOnVerifiedStatus() async {
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(disconnected), .success(connectedStatus)],
            handles: [ConnectHandle()]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.connect()

        XCTAssertEqual(controller.phase, .connected(connectedStatus))
        let startCount = await fake.callCount("startConnect")
        XCTAssertEqual(startCount, 1)
    }

    func testConnectReportsChildFailureBeforeConnected() async {
        let failed = ConnectHandle(result: CommandResult(exitCode: 1, stdout: "", stderr: "secret"))
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(disconnected)],
            handles: [failed]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.connect()

        XCTAssertEqual(controller.phase, .error("Meraki OpenConnect connect exited before a verified connection."))
        XCTAssertFalse(controller.message?.contains("secret") ?? true)
    }

    func testConnectDoesNotAutomaticallyRetry() async {
        let failed = ConnectHandle(result: CommandResult(exitCode: 1, stdout: "", stderr: ""))
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(disconnected)],
            handles: [failed]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)

        await controller.connect()

        let startCount = await fake.callCount("startConnect")
        XCTAssertEqual(startCount, 1)
    }

    func testRepeatedConnectIsIgnoredWhileConnecting() async {
        let gate = SleepGate()
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(disconnected), .success(connectedStatus)],
            handles: [ConnectHandle()]
        )
        let controller = VPNController(cli: fake, sleep: { _ in await gate.pause() })

        let firstConnect = Task { await controller.connect() }
        await gate.waitUntilPaused()
        await controller.connect()
        await gate.resume()
        await firstConnect.value

        let startCount = await fake.callCount("startConnect")
        XCTAssertEqual(startCount, 1)
    }

    func testDisconnectTransitionsToDisconnectedAfterVerifiedStatus() async {
        let fake = FakeVPNCLI(
            statuses: [.success(connectedStatus), .success(disconnected)],
            disconnects: [.success(CommandResult(exitCode: 0, stdout: "", stderr: ""))]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)
        await controller.refresh()

        let disconnectedCleanly = await controller.disconnect()
        XCTAssertTrue(disconnectedCleanly)
        XCTAssertEqual(controller.phase, .disconnected)
    }

    func testDisconnectWaitsForConnectChildToExit() async {
        let handle = ConnectHandle()
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(connectedStatus), .success(disconnected)],
            handles: [handle],
            disconnects: [.success(CommandResult(exitCode: 0, stdout: "", stderr: ""))]
        )
        let controller = VPNController(cli: fake, sleep: { _ in
            await handle.finish(CommandResult(exitCode: 0, stdout: "", stderr: ""))
        })
        await controller.connect()

        let disconnectedCleanly = await controller.disconnect()
        XCTAssertTrue(disconnectedCleanly)
        XCTAssertEqual(controller.phase, .disconnected)
    }

    func testCleanupTimeoutLeavesErrorAndForceQuitAvailable() async {
        let fake = FakeVPNCLI(
            doctors: [.success(doctor())],
            statuses: [.success(disconnected), .success(connectedStatus), .success(disconnected)],
            handles: [ConnectHandle()],
            disconnects: [.success(CommandResult(exitCode: 0, stdout: "", stderr: ""))]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)
        await controller.connect()

        let disconnectedCleanly = await controller.disconnect()
        XCTAssertFalse(disconnectedCleanly)
        XCTAssertTrue(controller.forceQuitAvailable)
        XCTAssertEqual(controller.status?.connected, false)
        XCTAssertEqual(controller.statusLine, "Error")
    }

    func testPrepareToQuitReturnsTrueWhenAlreadyDisconnected() async {
        let fake = FakeVPNCLI(statuses: [.success(disconnected)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        let prepared = await controller.prepareToQuit()
        let disconnectCount = await fake.callCount("disconnect")
        XCTAssertTrue(prepared)
        XCTAssertEqual(disconnectCount, 0)
    }

    func testPrepareToQuitDisconnectsAdoptedConnection() async {
        let fake = FakeVPNCLI(
            statuses: [.success(connectedStatus), .success(disconnected)],
            disconnects: [.success(CommandResult(exitCode: 0, stdout: "", stderr: ""))]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)

        let prepared = await controller.prepareToQuit()
        let disconnectCount = await fake.callCount("disconnect")
        XCTAssertTrue(prepared)
        XCTAssertEqual(disconnectCount, 1)
    }

    func testPrepareToQuitReturnsFalseWhenCleanupFails() async {
        let fake = FakeVPNCLI(statuses: [.failure(.invalidJSON)])
        let controller = VPNController(cli: fake, sleep: noSleep)

        let prepared = await controller.prepareToQuit()
        XCTAssertFalse(prepared)
        XCTAssertTrue(controller.forceQuitAvailable)
    }

    func testForceQuitOnlyChangesExplicitPermissionFlag() {
        let controller = VPNController(cli: FakeVPNCLI(), sleep: noSleep)
        let originalPhase = controller.phase
        let originalStatus = controller.status

        controller.allowForceQuit()

        XCTAssertTrue(controller.forceQuitApproved)
        XCTAssertEqual(controller.phase, originalPhase)
        XCTAssertEqual(controller.status, originalStatus)
    }

    func testTerminationRequestDisconnectsOnceAndRepliesTrue() async {
        let fake = FakeVPNCLI(
            statuses: [.success(connectedStatus), .success(disconnected)],
            disconnects: [.success(CommandResult(exitCode: 0, stdout: "", stderr: ""))]
        )
        let controller = VPNController(cli: fake, sleep: noSleep)
        let coordinator = TerminationCoordinator(controller: controller)
        let reply = expectation(description: "termination reply")
        var replied: Bool?

        let immediate = coordinator.requestTermination {
            replied = $0
            reply.fulfill()
        }
        let duplicateImmediate = coordinator.requestTermination { _ in
            XCTFail("Duplicate termination request must not create a second reply task")
        }

        XCTAssertFalse(immediate)
        XCTAssertFalse(duplicateImmediate)
        await fulfillment(of: [reply])
        XCTAssertEqual(replied, true)
        let disconnectCount = await fake.callCount("disconnect")
        XCTAssertEqual(disconnectCount, 1)
    }

    func testTerminationFailureRepliesFalse() async {
        let fake = FakeVPNCLI(statuses: [.failure(.invalidJSON)])
        let controller = VPNController(cli: fake, sleep: noSleep)
        let coordinator = TerminationCoordinator(controller: controller)
        let reply = expectation(description: "termination reply")
        var replied: Bool?

        let immediate = coordinator.requestTermination {
            replied = $0
            reply.fulfill()
        }

        XCTAssertFalse(immediate)
        await fulfillment(of: [reply])
        XCTAssertEqual(replied, false)
        XCTAssertTrue(controller.forceQuitAvailable)
    }

    func testForceQuitReturnsImmediateWithoutCleanupReply() async {
        let fake = FakeVPNCLI()
        let controller = VPNController(cli: fake, sleep: noSleep)
        controller.allowForceQuit()
        let coordinator = TerminationCoordinator(controller: controller)
        var replied = false

        let immediate = coordinator.requestTermination { _ in replied = true }

        XCTAssertTrue(immediate)
        XCTAssertFalse(replied)
        let calls = await fake.recordedCalls()
        XCTAssertEqual(calls, [])
    }

    private var noSleep: VPNController.Sleeper { { _ in } }
    private var disconnected: VPNStatus { VPNStatus(connected: false, pid: nil, interface: nil, transport: nil) }
    private var connectedStatus: VPNStatus { VPNStatus(connected: true, pid: 44, interface: "utun9", transport: "dtls") }

    private func doctor(openconnect: Bool = true, ciscoConnected: Bool = false) -> DoctorReport {
        DoctorReport(
            openconnect: openconnect,
            openconnectSaml: true,
            chromeAvailable: true,
            chromeProfileAvailable: true,
            profileConfigured: true,
            settingsConfigured: true,
            extensionConfigured: true,
            nativeMessagingConfigured: true,
            extensionPermissionGranted: true,
            certificatePinned: true,
            privilegedHelperInstalled: true,
            nativeWorkerInstalled: true,
            policyDigestMatches: true,
            ciscoConnected: ciscoConnected,
            connected: false,
            pid: nil,
            interface: nil,
            transport: nil
        )
    }
}

private enum FakeValue<Value: Sendable>: Sendable {
    case success(Value)
    case failure(CLIProcessError)
}

private actor FakeVPNCLI: VPNCLI {
    private var doctors: [FakeValue<DoctorReport>]
    private var statuses: [FakeValue<VPNStatus>]
    private var handles: [ConnectHandle]
    private var disconnects: [FakeValue<CommandResult>]
    private var calls: [String] = []

    init(
        doctors: [FakeValue<DoctorReport>] = [],
        statuses: [FakeValue<VPNStatus>] = [],
        handles: [ConnectHandle] = [],
        disconnects: [FakeValue<CommandResult>] = []
    ) {
        self.doctors = doctors
        self.statuses = statuses
        self.handles = handles
        self.disconnects = disconnects
    }

    func doctor() throws -> DoctorReport {
        calls.append("doctor")
        return try take(&doctors)
    }

    func status() throws -> VPNStatus {
        calls.append("status")
        return try take(&statuses)
    }

    func startConnect() throws -> ConnectHandle {
        calls.append("startConnect")
        guard !handles.isEmpty else { throw CLIProcessError.launchFailed }
        return handles.removeFirst()
    }

    func disconnect() throws -> CommandResult {
        calls.append("disconnect")
        return try take(&disconnects)
    }

    func recordedCalls() -> [String] { calls }
    func callCount(_ name: String) -> Int { calls.filter { $0 == name }.count }

    private func take<Value>(_ values: inout [FakeValue<Value>]) throws -> Value {
        guard !values.isEmpty else { throw CLIProcessError.launchFailed }
        switch values.removeFirst() {
        case let .success(value): return value
        case let .failure(error): throw error
        }
    }
}

private actor SleepGate {
    private var pauseContinuation: CheckedContinuation<Void, Never>?
    private var observedContinuation: CheckedContinuation<Void, Never>?
    private var isPaused = false

    func pause() async {
        isPaused = true
        observedContinuation?.resume()
        observedContinuation = nil
        await withCheckedContinuation { continuation in
            pauseContinuation = continuation
        }
    }

    func waitUntilPaused() async {
        if isPaused { return }
        await withCheckedContinuation { continuation in
            observedContinuation = continuation
        }
    }

    func resume() {
        pauseContinuation?.resume()
        pauseContinuation = nil
    }
}
