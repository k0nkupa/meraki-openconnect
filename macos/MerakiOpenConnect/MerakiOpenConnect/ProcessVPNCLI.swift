import Darwin
import Foundation

protocol VPNCLI: Sendable {
    func doctor() async throws -> DoctorReport
    func status() async throws -> VPNStatus
    func startConnect() async throws -> ConnectHandle
    func disconnect() async throws -> CommandResult
}

struct CommandResult: Equatable, Sendable {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

enum CLIProcessError: Error, Equatable {
    case executableMissing
    case unsafeExecutable
    case launchFailed
    case timedOut
    case nonzeroExit(Int32, String)
    case invalidJSON
}

actor ConnectHandle {
    private var result: CommandResult?

    init(result: CommandResult? = nil) {
        self.result = result
    }

    func resultIfFinished() -> CommandResult? {
        result
    }

    func finish(_ result: CommandResult) {
        self.result = result
    }
}

final class ProcessVPNCLI: VPNCLI, @unchecked Sendable {
    typealias Sleeper = @Sendable (Duration) async throws -> Void

    private let homeDirectory: URL
    private let shortCommandTimeout: Duration
    private let sleeper: Sleeper

    init(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        shortCommandTimeout: Duration = .seconds(10),
        sleeper: @escaping Sleeper = { duration in
            try await Task.sleep(for: duration)
        }
    ) {
        self.homeDirectory = homeDirectory.standardizedFileURL
        self.shortCommandTimeout = shortCommandTimeout
        self.sleeper = sleeper
    }

    func doctor() async throws -> DoctorReport {
        let result = try await runShort(.doctor)
        guard result.exitCode == 0 || result.exitCode == 4 else {
            throw CLIProcessError.nonzeroExit(result.exitCode, result.stderr)
        }
        return try decode(DoctorReport.self, from: result.stdout)
    }

    func status() async throws -> VPNStatus {
        let result = try await runShort(.status)
        guard result.exitCode == 0 else {
            throw CLIProcessError.nonzeroExit(result.exitCode, result.stderr)
        }
        return try decode(VPNStatus.self, from: result.stdout)
    }

    func startConnect() async throws -> ConnectHandle {
        let running = try launch(.connect)
        let handle = ConnectHandle()
        Task {
            await handle.finish(await running.result())
        }
        return handle
    }

    func disconnect() async throws -> CommandResult {
        let result = try await runShort(.disconnect)
        guard result.exitCode == 0 else {
            throw CLIProcessError.nonzeroExit(result.exitCode, result.stderr)
        }
        return result
    }

    static func resolveExecutable(homeDirectory: URL) throws -> URL {
        let manager = FileManager.default
        let fixedURL = homeDirectory
            .appendingPathComponent(".local/bin/meraki-openconnect", isDirectory: false)
            .standardizedFileURL
        guard manager.fileExists(atPath: fixedURL.path) else {
            throw CLIProcessError.executableMissing
        }

        let resolvedHome = homeDirectory.resolvingSymlinksInPath().standardizedFileURL
        let resolved = fixedURL.resolvingSymlinksInPath().standardizedFileURL
        let homePrefix = resolvedHome.path.hasSuffix("/")
            ? resolvedHome.path
            : resolvedHome.path + "/"
        guard resolved.path.hasPrefix(homePrefix) else {
            throw CLIProcessError.unsafeExecutable
        }

        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try manager.attributesOfItem(atPath: resolved.path)
        } catch {
            throw CLIProcessError.unsafeExecutable
        }
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let owner = attributes[.ownerAccountID] as? NSNumber,
              owner.uint32Value == getuid(),
              let permissions = attributes[.posixPermissions] as? NSNumber,
              permissions.uint16Value & 0o022 == 0,
              manager.isExecutableFile(atPath: resolved.path) else {
            throw CLIProcessError.unsafeExecutable
        }
        return resolved
    }

    private enum Command {
        case doctor
        case status
        case connect
        case disconnect

        var arguments: [String] {
            switch self {
            case .doctor: ["doctor", "--json"]
            case .status: ["status", "--json"]
            case .connect: ["connect"]
            case .disconnect: ["disconnect"]
            }
        }
    }

    private enum ShortOutcome {
        case completed(CommandResult)
        case timedOut
    }

    private func runShort(_ command: Command) async throws -> CommandResult {
        let running = try launch(command)
        return try await withThrowingTaskGroup(of: ShortOutcome.self) { group in
            group.addTask {
                .completed(await running.result())
            }
            group.addTask { [sleeper, shortCommandTimeout] in
                try await sleeper(shortCommandTimeout)
                return .timedOut
            }

            guard let first = try await group.next() else {
                throw CLIProcessError.launchFailed
            }
            group.cancelAll()
            switch first {
            case let .completed(result):
                return result
            case .timedOut:
                running.terminate()
                _ = await running.result()
                throw CLIProcessError.timedOut
            }
        }
    }

    private func launch(_ command: Command) throws -> RunningCommand {
        let executable = try Self.resolveExecutable(homeDirectory: homeDirectory)
        let process = Process()
        let stdout = BoundedPipeCapture()
        let stderr = BoundedPipeCapture()
        let resultBox = ProcessResultBox()

        process.executableURL = executable
        process.arguments = command.arguments
        process.environment = [
            "HOME": homeDirectory.path,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
            "LANG": "en_NZ.UTF-8",
        ]
        process.standardOutput = stdout.pipe
        process.standardError = stderr.pipe
        process.terminationHandler = { process in
            let result = CommandResult(
                exitCode: process.terminationStatus,
                stdout: String(decoding: stdout.finalData(), as: UTF8.self),
                stderr: String(decoding: stderr.finalData(), as: UTF8.self)
            )
            Task { await resultBox.store(result) }
        }

        do {
            try process.run()
        } catch {
            stdout.close()
            stderr.close()
            throw CLIProcessError.launchFailed
        }
        return RunningCommand(process: process, resultBox: resultBox)
    }

    private func decode<Value: Decodable>(_ type: Value.Type, from output: String) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: Data(output.utf8))
        } catch {
            throw CLIProcessError.invalidJSON
        }
    }
}

private actor ProcessResultBox {
    private var stored: CommandResult?
    private var waiters: [CheckedContinuation<CommandResult, Never>] = []

    func store(_ result: CommandResult) {
        guard stored == nil else { return }
        stored = result
        let currentWaiters = waiters
        waiters.removeAll()
        for waiter in currentWaiters {
            waiter.resume(returning: result)
        }
    }

    func value() async -> CommandResult {
        if let stored {
            return stored
        }
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

private final class RunningCommand: @unchecked Sendable {
    private let process: Process
    private let resultBox: ProcessResultBox

    init(process: Process, resultBox: ProcessResultBox) {
        self.process = process
        self.resultBox = resultBox
    }

    func result() async -> CommandResult {
        await resultBox.value()
    }

    func terminate() {
        if process.isRunning {
            process.terminate()
        }
    }
}

private final class BoundedPipeCapture: @unchecked Sendable {
    let pipe = Pipe()

    private let limit: Int
    private let queue = DispatchQueue(label: "io.github.k0nkupa.merakiopenconnect.pipe-capture")
    private let finished = DispatchGroup()
    private var data = Data()
    private var isFinished = false

    init(limit: Int = 65_536) {
        self.limit = limit
        finished.enter()
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            self?.queue.async {
                guard let self, !self.isFinished else { return }
                if chunk.isEmpty {
                    self.isFinished = true
                    handle.readabilityHandler = nil
                    self.finished.leave()
                    return
                }
                let remaining = self.limit - self.data.count
                if remaining > 0 {
                    self.data.append(chunk.prefix(remaining))
                }
            }
        }
    }

    func finalData() -> Data {
        finished.wait()
        return queue.sync { data }
    }

    func close() {
        pipe.fileHandleForReading.readabilityHandler = nil
        queue.sync {
            guard !isFinished else { return }
            isFinished = true
            finished.leave()
        }
    }
}
