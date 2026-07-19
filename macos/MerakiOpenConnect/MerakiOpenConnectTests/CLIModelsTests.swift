import XCTest
@testable import MerakiOpenConnect

final class CLIModelsTests: XCTestCase {
    func testCompleteDoctorReportDecodesEveryStableField() throws {
        let report = try decode()

        XCTAssertNil(report.setupIssue)
        XCTAssertTrue(report.profileConfigured)
        XCTAssertTrue(report.settingsConfigured)
        XCTAssertTrue(report.nativeMessagingConfigured)
        XCTAssertTrue(report.extensionPermissionGranted)
        XCTAssertTrue(report.policyDigestMatches)
        XCTAssertFalse(report.connected)
        XCTAssertNil(report.pid)
        XCTAssertNil(report.interface)
        XCTAssertNil(report.transport)
    }

    func testDiagnosisUsesRequiredReadinessPriority() throws {
        let cases: [(DoctorReport, String, String?)] = [
            (try decode(openconnect: false), "OpenConnect is not installed.", "brew install openconnect"),
            (try decode(openconnectSaml: false), "The Meraki OpenConnect Python environment is incomplete.", nil),
            (try decode(chromeAvailable: false), "Google Chrome is not installed in the expected location.", nil),
            (try decode(chromeProfileAvailable: false), "The configured Chrome profile is not available.", nil),
            (try decode(profileConfigured: false), "No organization profile is configured.", nil),
            (try decode(settingsConfigured: false), "Machine settings are not configured.", nil),
            (try decode(extensionConfigured: false), "The Chrome extension or native host is not configured.", nil),
            (try decode(nativeMessagingConfigured: false), "The Chrome extension or native host is not configured.", nil),
            (try decode(extensionPermissionGranted: false), "Chrome gateway permission does not match the organization profile.", nil),
            (try decode(certificatePinned: false), "The VPN server certificate is not pinned.", nil),
            (try decode(privilegedHelperInstalled: false), "Privileged Meraki OpenConnect components are not installed.", nil),
            (try decode(policyDigestMatches: false), "The installed VPN policy does not match this profile.", nil),
            (try decode(ciscoConnected: true), "Disconnect the existing Cisco VPN session before using Meraki OpenConnect.", nil),
        ]

        for (report, message, command) in cases {
            XCTAssertEqual(report.setupIssue, SetupIssue(message: message, command: command))
        }
    }

    func testMultipleFailuresReturnOnlyHighestPriorityIssue() throws {
        let report = try decode(
            openconnect: false,
            profileConfigured: false,
            policyDigestMatches: false,
            ciscoConnected: true
        )

        XCTAssertEqual(
            report.setupIssue,
            SetupIssue(message: "OpenConnect is not installed.", command: "brew install openconnect")
        )
    }

    func testDisconnectedStatusAcceptsNullFields() throws {
        let status = try JSONDecoder().decode(
            VPNStatus.self,
            from: Data(
                #"{"connected":false,"pid":null,"interface":null,"transport":null}"#.utf8
            )
        )

        XCTAssertFalse(status.connected)
        XCTAssertNil(status.pid)
        XCTAssertNil(status.interface)
        XCTAssertNil(status.transport)
    }

    func testConnectedStatusDecodesVerifiedDetails() throws {
        let status = try JSONDecoder().decode(
            VPNStatus.self,
            from: Data(
                #"{"connected":true,"pid":321,"interface":"utun9","transport":"dtls"}"#.utf8
            )
        )

        XCTAssertEqual(status.pid, 321)
        XCTAssertEqual(status.interface, "utun9")
        XCTAssertEqual(status.transport, "dtls")
    }

    func testMissingRequiredDoctorKeyFailsClosed() {
        let incomplete = Data(#"{"openconnect":true}"#.utf8)

        XCTAssertThrowsError(try JSONDecoder().decode(DoctorReport.self, from: incomplete))
    }

    private func decode(
        openconnect: Bool = true,
        openconnectSaml: Bool = true,
        chromeAvailable: Bool = true,
        chromeProfileAvailable: Bool = true,
        profileConfigured: Bool = true,
        settingsConfigured: Bool = true,
        extensionConfigured: Bool = true,
        nativeMessagingConfigured: Bool = true,
        extensionPermissionGranted: Bool = true,
        certificatePinned: Bool = true,
        privilegedHelperInstalled: Bool = true,
        nativeWorkerInstalled: Bool = true,
        policyDigestMatches: Bool = true,
        ciscoConnected: Bool = false
    ) throws -> DoctorReport {
        let data = Data(
            """
            {
              "openconnect": \(openconnect),
              "openconnect_saml": \(openconnectSaml),
              "chrome_available": \(chromeAvailable),
              "chrome_profile_available": \(chromeProfileAvailable),
              "profile_configured": \(profileConfigured),
              "settings_configured": \(settingsConfigured),
              "extension_configured": \(extensionConfigured),
              "native_messaging_configured": \(nativeMessagingConfigured),
              "extension_permission_granted": \(extensionPermissionGranted),
              "certificate_pinned": \(certificatePinned),
              "privileged_helper_installed": \(privilegedHelperInstalled),
              "native_worker_installed": \(nativeWorkerInstalled),
              "policy_digest_matches": \(policyDigestMatches),
              "cisco_connected": \(ciscoConnected),
              "connected": false,
              "pid": null,
              "interface": null,
              "transport": null
            }
            """.utf8
        )
        return try JSONDecoder().decode(DoctorReport.self, from: data)
    }
}
