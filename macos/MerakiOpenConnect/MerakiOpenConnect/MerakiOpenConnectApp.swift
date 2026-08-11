import SwiftUI

@MainActor
enum AppComposition {
    static let cli = ProcessVPNCLI()
    static let controller = VPNController(cli: cli)
}

@main
struct MerakiOpenConnectApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var controller: VPNController
    @State private var hasStarted = false

    init() {
        _controller = StateObject(wrappedValue: AppComposition.controller)
    }

    var body: some Scene {
        MenuBarExtra {
            MenuContentView(controller: controller)
                .task {
                    guard !hasStarted else { return }
                    hasStarted = true
                    await controller.start()
                }
        }
        label: {
            TunnelStatusIcon(phase: controller.phase)
                .accessibilityLabel(controller.statusLine)
        }
        .menuBarExtraStyle(.menu)
    }
}
