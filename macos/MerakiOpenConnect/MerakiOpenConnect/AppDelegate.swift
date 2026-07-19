import AppKit

@MainActor
final class TerminationCoordinator {
    private let controller: VPNController
    private var cleanupInProgress = false

    init(controller: VPNController) {
        self.controller = controller
    }

    func requestTermination(reply: @escaping @MainActor (Bool) -> Void) -> Bool {
        if controller.mayTerminateImmediately {
            return true
        }
        guard !cleanupInProgress else {
            return false
        }

        cleanupInProgress = true
        Task {
            let safeToTerminate = await controller.prepareToQuit()
            cleanupInProgress = false
            reply(safeToTerminate)
        }
        return false
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let controller: VPNController
    private lazy var terminationCoordinator = TerminationCoordinator(controller: controller)

    override init() {
        controller = AppComposition.controller
        super.init()
    }

    init(controller: VPNController) {
        self.controller = controller
        super.init()
    }

    func applicationShouldTerminate(
        _ sender: NSApplication
    ) -> NSApplication.TerminateReply {
        let terminateImmediately = terminationCoordinator.requestTermination { safeToTerminate in
            sender.reply(toApplicationShouldTerminate: safeToTerminate)
        }
        return terminateImmediately ? .terminateNow : .terminateLater
    }
}
