import Foundation

struct SetupIssue: Equatable, Sendable {
    let message: String
    let command: String?
}

struct DoctorReport: Decodable, Equatable, Sendable {
    let openconnect: Bool
    let openconnectSaml: Bool
    let chromeAvailable: Bool
    let chromeProfileAvailable: Bool
    let profileConfigured: Bool
    let settingsConfigured: Bool
    let extensionConfigured: Bool
    let nativeMessagingConfigured: Bool
    let extensionPermissionGranted: Bool
    let certificatePinned: Bool
    let privilegedHelperInstalled: Bool
    let nativeWorkerInstalled: Bool
    let policyDigestMatches: Bool
    let ciscoConnected: Bool
    let connected: Bool
    let pid: Int?
    let interface: String?
    let transport: String?

    enum CodingKeys: String, CodingKey {
        case openconnect
        case openconnectSaml = "openconnect_saml"
        case chromeAvailable = "chrome_available"
        case chromeProfileAvailable = "chrome_profile_available"
        case profileConfigured = "profile_configured"
        case settingsConfigured = "settings_configured"
        case extensionConfigured = "extension_configured"
        case nativeMessagingConfigured = "native_messaging_configured"
        case extensionPermissionGranted = "extension_permission_granted"
        case certificatePinned = "certificate_pinned"
        case privilegedHelperInstalled = "privileged_helper_installed"
        case nativeWorkerInstalled = "native_worker_installed"
        case policyDigestMatches = "policy_digest_matches"
        case ciscoConnected = "cisco_connected"
        case connected
        case pid
        case interface
        case transport
    }

    var setupIssue: SetupIssue? {
        if !openconnect {
            return SetupIssue(
                message: "OpenConnect is not installed.",
                command: "brew install openconnect"
            )
        }
        if !openconnectSaml {
            return SetupIssue(
                message: "The Meraki OpenConnect Python environment is incomplete.",
                command: nil
            )
        }
        if !chromeAvailable {
            return SetupIssue(
                message: "Google Chrome is not installed in the expected location.",
                command: nil
            )
        }
        if !chromeProfileAvailable {
            return SetupIssue(
                message: "The configured Chrome profile is not available.",
                command: nil
            )
        }
        if !profileConfigured {
            return SetupIssue(
                message: "No organization profile is configured.",
                command: nil
            )
        }
        if !settingsConfigured {
            return SetupIssue(
                message: "Machine settings are not configured.",
                command: nil
            )
        }
        if !extensionConfigured || !nativeMessagingConfigured {
            return SetupIssue(
                message: "The Chrome extension or native host is not configured.",
                command: nil
            )
        }
        if !extensionPermissionGranted {
            return SetupIssue(
                message: "Chrome gateway permission does not match the organization profile.",
                command: nil
            )
        }
        if !certificatePinned {
            return SetupIssue(
                message: "The VPN server certificate is not pinned.",
                command: nil
            )
        }
        if !privilegedHelperInstalled || !nativeWorkerInstalled {
            return SetupIssue(
                message: "Privileged Meraki OpenConnect components are not installed.",
                command: nil
            )
        }
        if !policyDigestMatches {
            return SetupIssue(
                message: "The installed VPN policy does not match this profile.",
                command: nil
            )
        }
        if ciscoConnected {
            return SetupIssue(
                message: "Disconnect the existing Cisco VPN session before using Meraki OpenConnect.",
                command: nil
            )
        }
        return nil
    }
}

struct VPNStatus: Decodable, Equatable, Sendable {
    let connected: Bool
    let pid: Int?
    let interface: String?
    let transport: String?
}

enum AppPhase: Equatable, Sendable {
    case setupRequired(SetupIssue)
    case disconnected
    case connecting
    case connected(VPNStatus)
    case disconnecting
    case error(String)
}
