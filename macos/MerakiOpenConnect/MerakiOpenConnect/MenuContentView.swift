import AppKit
import SwiftUI

enum MenuMutationAction: Equatable, Sendable {
    case connect
    case disconnect
    case none
}

extension AppPhase {
    var systemImage: String {
        switch self {
        case .setupRequired: "exclamationmark.shield"
        case .disconnected: "shield"
        case .connecting, .disconnecting: "shield.lefthalf.filled"
        case .connected: "checkmark.shield.fill"
        case .error: "exclamationmark.shield.fill"
        }
    }

    var mutationEnabled: Bool {
        switch self {
        case .connecting, .disconnecting: false
        default: true
        }
    }

    func menuAction(verifiedConnected: Bool?) -> MenuMutationAction {
        switch self {
        case .disconnected:
            .connect
        case .connecting, .connected:
            .disconnect
        case .error where verifiedConnected == true:
            .disconnect
        default:
            .none
        }
    }
}

struct MenuContentView: View {
    @ObservedObject var controller: VPNController

    var body: some View {
        VStack(alignment: .leading) {
            Text(controller.statusLine)
            if let connection = controller.connectionDetail {
                Text(connection)
            }
            if let setupMessage = controller.setupIssue?.message {
                Text(setupMessage)
            } else if let message = controller.message {
                Text(message)
            }

            Divider()
            mutationButton
            Button("Diagnostics") {
                Task { await controller.refresh() }
            }
            .disabled(!controller.phase.mutationEnabled)

            if let command = controller.setupIssue?.command {
                Button("Copy Setup Command") {
                    copy(command)
                }
            }
            Button("Open Setup Guide") {
                openSetupGuide()
            }

            Divider()
            Button("Quit") {
                NSApp.terminate(nil)
            }
            if controller.forceQuitAvailable {
                Button("Force Quit") {
                    controller.allowForceQuit()
                    NSApp.terminate(nil)
                }
            }
        }
    }

    @ViewBuilder
    private var mutationButton: some View {
        switch controller.phase.menuAction(verifiedConnected: controller.status?.connected) {
        case .connect:
            Button("Connect") {
                Task { await controller.connect() }
            }
            .disabled(!controller.phase.mutationEnabled)
        case .disconnect:
            Button("Disconnect") {
                Task { _ = await controller.disconnect() }
            }
            .disabled(!controller.phase.mutationEnabled)
        case .none:
            EmptyView()
        }
    }

    private func copy(_ command: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
    }

    private func openSetupGuide() {
        guard let url = URL(
            string: "https://github.com/k0nkupa/meraki-openconnect#menu-bar-app-local-xcode-build"
        ) else { return }
        NSWorkspace.shared.open(url)
    }
}
