import Combine
import Foundation

@MainActor
final class VPNController: ObservableObject {
    typealias Sleeper = @Sendable (Duration) async throws -> Void

    @Published private(set) var phase: AppPhase = .disconnected
    @Published private(set) var status: VPNStatus?
    @Published private(set) var message: String?
    @Published private(set) var setupIssue: SetupIssue?
    @Published private(set) var forceQuitAvailable = false
    private(set) var forceQuitApproved = false

    private let cli: any VPNCLI
    private let sleep: Sleeper
    private var mutationInProgress = false
    private var connectHandle: ConnectHandle?

    init(
        cli: any VPNCLI,
        sleep: @escaping Sleeper = { duration in
            try await Task.sleep(for: duration)
        }
    ) {
        self.cli = cli
        self.sleep = sleep
    }

    var canMutate: Bool {
        phase != .connecting && phase != .disconnecting
    }

    var mayTerminateImmediately: Bool {
        forceQuitApproved || (phase == .disconnected && status?.connected == false)
    }

    var statusLine: String {
        switch phase {
        case .setupRequired: "Setup required"
        case .disconnected: "Disconnected"
        case .connecting: "Connecting…"
        case .connected: "Connected"
        case .disconnecting: "Disconnecting…"
        case .error: "Error"
        }
    }

    var connectionDetail: String? {
        guard let interface = status?.interface,
              let transport = status?.transport else {
            return nil
        }
        return "\(interface) · \(transport)"
    }

    func start() async {
        resetTransientState()
        let report: DoctorReport
        do {
            report = try await cli.doctor()
        } catch {
            status = nil
            setError("Unable to verify Meraki OpenConnect readiness.")
            return
        }

        let verifiedStatus: VPNStatus
        do {
            verifiedStatus = try await cli.status()
        } catch {
            status = nil
            setError("Unable to verify Meraki OpenConnect status.")
            return
        }

        status = verifiedStatus
        if let issue = report.setupIssue {
            setupIssue = issue
            phase = .setupRequired(issue)
        } else {
            adopt(verifiedStatus)
        }
    }

    func refresh() async {
        do {
            let verifiedStatus = try await cli.status()
            status = verifiedStatus
            if setupIssue == nil {
                adopt(verifiedStatus)
            }
        } catch {
            status = nil
            setError("Unable to verify Meraki OpenConnect status.")
        }
    }

    func connect() async {
        guard !mutationInProgress, canMutate else { return }
        mutationInProgress = true
        defer { mutationInProgress = false }
        resetTransientState()

        do {
            let report = try await cli.doctor()
            let verifiedStatus = try await cli.status()
            status = verifiedStatus

            if let issue = report.setupIssue {
                setupIssue = issue
                phase = .setupRequired(issue)
                return
            }
            if verifiedStatus.connected {
                adopt(verifiedStatus)
                return
            }

            phase = .connecting
            let handle = try await cli.startConnect()
            connectHandle = handle

            while true {
                let current = try await cli.status()
                status = current
                if current.connected {
                    phase = .connected(current)
                    return
                }
                if await handle.resultIfFinished() != nil {
                    connectHandle = nil
                    setError("Meraki OpenConnect connect exited before a verified connection.")
                    return
                }
                try await sleep(.seconds(1))
            }
        } catch {
            setError("Unable to connect Meraki OpenConnect safely.")
        }
    }

    func disconnect() async -> Bool {
        guard !mutationInProgress else { return false }
        mutationInProgress = true
        defer { mutationInProgress = false }
        message = nil
        setupIssue = nil
        forceQuitAvailable = false
        phase = .disconnecting

        do {
            _ = try await cli.disconnect()
            for attempt in 0..<20 {
                let current = try await cli.status()
                status = current
                if !current.connected {
                    return await finishDisconnect(after: current)
                }
                if attempt < 19 {
                    try await sleep(.seconds(1))
                }
            }
        } catch {
            return cleanupFailed()
        }
        return cleanupFailed()
    }

    func prepareToQuit() async -> Bool {
        do {
            let current = try await cli.status()
            status = current
            if !current.connected {
                phase = .disconnected
                message = nil
                setupIssue = nil
                forceQuitAvailable = false
                return true
            }
            phase = .connected(current)
            return await disconnect()
        } catch {
            return cleanupFailed()
        }
    }

    func allowForceQuit() {
        forceQuitApproved = true
    }

    private func finishDisconnect(after current: VPNStatus) async -> Bool {
        if let connectHandle {
            if await connectHandle.resultIfFinished() == nil {
                for _ in 0..<5 {
                    do {
                        try await sleep(.seconds(1))
                    } catch {
                        return cleanupFailed()
                    }
                    if await connectHandle.resultIfFinished() != nil {
                        break
                    }
                }
            }
            guard await connectHandle.resultIfFinished() != nil else {
                return cleanupFailed()
            }
            self.connectHandle = nil
        }

        status = current
        phase = .disconnected
        message = nil
        forceQuitAvailable = false
        return true
    }

    private func cleanupFailed() -> Bool {
        forceQuitAvailable = true
        setError("Unable to confirm complete Meraki OpenConnect cleanup.")
        return false
    }

    private func adopt(_ verifiedStatus: VPNStatus) {
        status = verifiedStatus
        setupIssue = nil
        message = nil
        phase = verifiedStatus.connected ? .connected(verifiedStatus) : .disconnected
    }

    private func setError(_ text: String) {
        message = text
        setupIssue = nil
        phase = .error(text)
    }

    private func resetTransientState() {
        message = nil
        setupIssue = nil
        forceQuitAvailable = false
    }
}
