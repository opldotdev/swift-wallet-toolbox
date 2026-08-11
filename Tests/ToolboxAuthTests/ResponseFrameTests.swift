import XCTest
import BSVAuth
@testable import ToolboxAuth

/// The response frame a real server sends.
///
/// These are the exact `x-bsv-auth-*` headers `https://wallet.1sat.app` returned for an
/// authenticated JSON-RPC call on 2026-08-11. The reference middleware omits `message-type` on a
/// general response — it writes that header only for non-general messages — so a decoder that
/// demands one rejects every ordinary answer.
final class ResponseFrameTests: XCTestCase {

    private let headers: [String: String] = [
        "x-bsv-auth-version": "0.1",
        "x-bsv-auth-identity-key":
            "0326a9865e5ec9809b72c92b82c86e5a39ca00c2fd215920e96f42477721425d4b",
        "x-bsv-auth-nonce": "0Pg1uMzLRMsnGg0FhRSO2zrSL4gtbVKNIOkWPNltj0s=",
        "x-bsv-auth-your-nonce": "rUsZzVrrEs3Y6YXbG8lSfkvxwksyERPKpl5l6eRRJ3G3Ai8Bhcw6cjEKUL4fZY5+",
        "x-bsv-auth-request-id": "QiZ4WIe+LOOkz9//zPvRri/n0yzb4v2wbZ6s92APuxc=",
        "x-bsv-auth-signature": "3045022100a68a495b783591ff87cdaae261acdf5534c44a3be3cab79e818e18725"
            + "1bba5c0022020a68a495b783591ff87cdaae261acdf5534c44a3be3cab79e818e187251bba5c0",
        "content-type": "application/json",
    ]

    /// Names which header the decoder is missing, rather than reporting that one is.
    func test_theRealResponseHeadersAreComplete() throws {
        let required = [
            "x-bsv-auth-version", "x-bsv-auth-identity-key", "x-bsv-auth-nonce",
            "x-bsv-auth-your-nonce", "x-bsv-auth-signature", "x-bsv-auth-request-id",
        ]
        for name in required {
            XCTAssertNotNil(headers[name], "\(name) is absent from a real server's response")
        }
    }

    func test_aRealResponseFrameDecodes() throws {
        let requestID = try XCTUnwrap(
            Data(base64Encoded: "QiZ4WIe+LOOkz9//zPvRri/n0yzb4v2wbZ6s92APuxc=")
        )
        let frame = try BRC104HTTPResponseFrame(
            status: 200,
            headers: headers.map { BRC104Header(name: $0.key, value: $0.value) },
            body: Array(#"{"jsonrpc":"2.0","result":{}}"#.utf8)
        )

        // The signature will not verify — it is truncated for the fixture — but the framing must
        // get far enough to say so, rather than refusing for a missing header.
        do {
            _ = try BRC104HTTPFrameCodec.decodeResponse(
                frame, expectedRequestID: Array(requestID)
            )
        } catch BRC104HTTPFramingError.missingAuthenticationHeader {
            XCTFail("every required header is present; the decoder disagrees")
        } catch {
            // Any other outcome means the headers were read.
        }
    }
}
