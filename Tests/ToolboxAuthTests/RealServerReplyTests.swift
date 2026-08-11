import XCTest
import BSVAuth
@testable import ToolboxAuth

/// A real server's handshake reply, decoded offline.
///
/// The bytes below came from `https://wallet.1sat.app/.well-known/auth` on 2026-08-11, in answer
/// to an initial request. Keeping them here turns a finding that needed the network into a test
/// that does not: if the SDK's decoder ever stops accepting what this server really sends, this
/// fails on somebody's laptop rather than in production.
///
/// The identity key and nonces are the server's own public values. Nothing secret is recorded.
final class RealServerReplyTests: XCTestCase {

    private let reply = """
        {"version":"0.1","messageType":"initialResponse",\
        "identityKey":"0326a9865e5ec9809b72c92b82c86e5a39ca00c2fd215920e96f42477721425d4b",\
        "initialNonce":"5pWocAeCkZ77XOyPV8uETRpdLm4e+uGw4HpGFmrlOI8kkdeykp81jpsfYFXY8YDm",\
        "yourNonce":"eVH/uo34waIbxchwZghOZT/XaXsWgXf/AEf7tEMVnuc=",\
        "requestedCertificates":{"certifiers":[],"types":{}},\
        "signature":[48,69,2,33,0,197,176,152,141,55,167,91,149,2,197,121,254,181,11,98,251,3,\
        222,58,127,200,236,93,168,50,219,199,6,110,14,101,86,2,32,42,168,205,144,166,239,199,\
        215,87,138,115,60,69,205,1,59,63,59,164,15,108,118,203,251,6,176,109,235,195,181,149,233]}
        """

    /// What the live handshake failed on. The reply is well formed BRC-103 as the server sends it,
    /// so a decoder that refuses it is a decoder that cannot talk to this server.
    func test_theServersReplyDecodes() throws {
        let message = try AuthMessageCodec.decode(Array(reply.utf8))

        XCTAssertEqual(message.messageType, .initialResponse)
        XCTAssertEqual(message.yourNonce, "eVH/uo34waIbxchwZghOZT/XaXsWgXf/AEf7tEMVnuc=")
        XCTAssertEqual(message.signature?.count, 71, "a DER signature, sent as a number array")
    }
}
