import Foundation
import XCTest
@testable import ToolboxPermissions

final class OriginatorCanonicalizerTests: XCTestCase {
    func testCanonicalizesHostsAndDefaultPorts() {
        let cases = [
            (" Example.COM ", "example.com"),
            ("https://Example.COM:443/path", "example.com"),
            ("http://Example.COM:80/path", "example.com"),
            ("https://Example.COM:8443/path", "example.com:8443"),
            ("http://localhost:3000/app", "localhost:3000"),
            ("https://[::1]:443/path", "[::1]"),
        ]
        for (input, expected) in cases {
            XCTAssertEqual(OriginatorCanonicalizer.normalize(input), expected)
        }
    }

    func testNonDefaultPortRemainsDistinct() throws {
        XCTAssertNotEqual(
            try CanonicalOriginator("example.com"),
            try CanonicalOriginator("example.com:8443")
        )
    }

    func testEmptyOriginatorIsRejected() {
        XCTAssertThrowsError(try CanonicalOriginator("   ")) { error in
            XCTAssertEqual(error as? PermissionPolicyError, .missingOriginator)
        }
    }

    func testDecodedOriginatorIsRecanonicalized() throws {
        let decoded = try JSONDecoder().decode(
            CanonicalOriginator.self,
            from: Data(#""HTTPS://EXAMPLE.COM:443/path""#.utf8)
        )
        XCTAssertEqual(decoded, try CanonicalOriginator("example.com"))
    }

    func testDecodedCounterpartyIsCanonicalOrRejected() throws {
        let publicKey = try testKey(2)
        let uppercase = CanonicalCounterparty(publicKey: publicKey).rawValue.uppercased()
        let decoded = try JSONDecoder().decode(
            CanonicalCounterparty.self,
            from: Data("\"\(uppercase)\"".utf8)
        )
        XCTAssertEqual(decoded, CanonicalCounterparty(publicKey: publicKey))
        XCTAssertThrowsError(try JSONDecoder().decode(
            CanonicalCounterparty.self,
            from: Data(#""not-a-counterparty""#.utf8)
        ))
    }
}
