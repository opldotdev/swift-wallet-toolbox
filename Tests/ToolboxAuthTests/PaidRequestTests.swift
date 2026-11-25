import Foundation
import XCTest
import BSVAuth
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import ToolboxStorage
@testable import ToolboxAuth

/// BRC-105 over an authenticated session, against `@bsv/sdk` 2.0.16's `AuthFetch`.
///
/// The vectors were captured with bun from `ts-sdk` `src/` (`ProtoWallet`, `P2PKH`, `Beef`,
/// `Utils`) with the client key `0x11 * 32`, the server key `0x22 * 32`, and each nonce's random
/// half fixed: the same calls `createNonce` and `createPaymentContext` make.
final class PaidRequestTests: XCTestCase {

    // MARK: - TypeScript vectors

    private enum TS {
        static let serverKey = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"
        /// `createNonce(server)` with the random half `random` below.
        static let prefix = "Pv+/+wB/gJzS4VoiD/iIEHfBIVjIygVhx41Fa7b//LDQD8jsUsln08VWxSApdCz2"
        /// `createNonce(client)` with the random half `invalid` below.
        static let suffix = "//6AwyjigvCfmMCv7aCAQQe1+3lKuBi2B50M+7hPVznjLPggfseOZb2eJuCThFzg"
        static let lockingScript = "76a9144969fe9c5596c903b53be5c9d1af584f76c69f2a88ac"
        static let txid = "fbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbefefefefefefefefefefefefefefefef"
        /// `new Beef(); mergeTxidOnly(txid); toBinaryAtomic(txid)`.
        static let atomicHex = "01010101efefefefefefefefefefefefefefefeffbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb"
            + "0200beef000102efefefefefefefefefefefefefefefeffbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb"
        static let description = "Payment for request to https://wallet.example"
        static let customInstructions = #"{"derivationPrefix":"Pv+/+wB/gJzS4VoiD/iIEHfBIVjIygVhx41Fa7b//LDQD8jsUsln08VWxSApdCz2","derivationSuffix":"//6AwyjigvCfmMCv7aCAQQe1+3lKuBi2B50M+7hPVznjLPggfseOZb2eJuCThFzg","payee":"02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"}"#
        static let header = #"{"derivationPrefix":"Pv+/+wB/gJzS4VoiD/iIEHfBIVjIygVhx41Fa7b//LDQD8jsUsln08VWxSApdCz2","derivationSuffix":"//6AwyjigvCfmMCv7aCAQQe1+3lKuBi2B50M+7hPVznjLPggfseOZb2eJuCThFzg","transaction":"AQEBAe/v7+/v7+/v7+/v7+/v7+/7+/v7+/v7+/v7+/v7+/v7AgC+7wABAu/v7+/v7+/v7+/v7+/v7+/7+/v7+/v7+/v7+/v7+/v7"}"#

        /// Random halves, the UTF-8 of `Utils.toUTF8(half)` and `createNonce(client)` over them.
        static let nonces: [(name: String, half: String, keyIDUTF8: String, nonce: String)] = [
            ("ascii", "30313233343536373839616263646566", "30313233343536373839616263646566",
             "MDEyMzQ1Njc4OWFiY2RlZiTtzETAuH0RS1KOgWAYVwlyMki2ZcYo4bzz2zHG4Z8j"),
            ("invalid", "fffe80c328e282f09f98c0afeda08041",
             "efbfbdefbfbdefbfbdefbfbd28efbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbd41", suffix),
            ("bom", "efbbbf4142f4908080e080affbfcfd7f",
             "4142efbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbd7f",
             "77u/QUL0kICA4ICv+/z9fyEZZ2kid8WI/xp+c7cycj2OBBT3kZy1wMnqRVo2DRq9"),
            ("random", "3effbffb007f809cd2e15a220ff88810",
             "3eefbfbdefbfbdefbfbd007fefbfbdefbfbdefbfbdefbfbd5a220fefbfbdefbfbd10",
             "Pv+/+wB/gJzS4VoiD/iIECLfDFOO9PJpQK9mDuLB/iRoOLcrRu0UxfZyfcuyQ84H"),
        ]
        static let invalidHalf = "fffe80c328e282f09f98c0afeda08041"
        static let randomHalf = "3effbffb007f809cd2e15a220ff88810"

        /// `parseInt(text)`; nil is `NaN`.
        static let parseInt: [(String, Int64?)] = [
            ("42", 42), (" 42", 42), ("42abc", 42), ("0x10", 16), ("1e3", 1), ("-5", -5),
            ("0", 0), ("abc", nil), ("+7", 7), ("\t\n 9", 9), ("00012", 12), ("0X1f", 31),
            ("3.9", 3), ("\u{a0}5", 5), ("\u{feff}6", 6),
        ]
    }

    // MARK: - A wallet that pays

    private struct NotUsed: Error {}

    /// Keys from a real `ProtoWallet`; `createAction` is recorded and answered with a fixed
    /// Atomic BEEF.
    private actor FakePayer: WalletPublicKeyProviding, WalletHMACOperations, WalletActionOperations {
        /// What `createAction` answers with.
        enum Result {
            /// The signed payment, as Atomic BEEF.
            case signed
            /// The same transaction left unsigned, under ``reference``.
            case unsigned
            /// Only the transaction ID.
            case transactionIDOnly
        }

        static let reference: [UInt8] = Array("payment-action".utf8)

        let keys: ProtoWallet
        var transaction: [UInt8]
        var createActionError: (any Error)?
        var result = Result.signed
        var abortAnswer = true
        private(set) var createActions: [WalletCreateActionRequest] = []
        private(set) var aborted: [WalletAbortActionRequest] = []

        init(key: PrivateKey, transaction: [UInt8]) {
            self.keys = ProtoWallet(rootKey: key)
            self.transaction = transaction
        }

        func setCreateActionError(_ error: (any Error)?) { createActionError = error }
        func setResult(_ result: Result) { self.result = result }
        func setAbortAnswer(_ aborted: Bool) { abortAnswer = aborted }

        func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
            try await keys.getPublicKey(request)
        }
        func createHMAC(_ request: WalletCreateHMACRequest) async throws -> WalletCreateHMACResult {
            try await keys.createHMAC(request)
        }
        func verifyHMAC(_ request: WalletVerifyHMACRequest) async throws -> WalletVerifyHMACResult {
            try await keys.verifyHMAC(request)
        }
        func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult {
            createActions.append(request)
            if let createActionError { throw createActionError }
            let atomic = try AtomicBEEF(bytes: transaction, limits: StorageLimits.beef)
            switch result {
            case .signed:
                return try WalletCreateActionResult(transaction: atomic)
            case .unsigned:
                return try WalletCreateActionResult(signableTransaction: WalletSignableTransaction(
                    transaction: atomic, reference: try WalletBase64Data(Self.reference)
                ))
            case .transactionIDOnly:
                return try WalletCreateActionResult(transactionID: atomic.subjectTransactionID)
            }
        }
        func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult {
            throw NotUsed()
        }
        func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult {
            aborted.append(request)
            return WalletAbortActionResult(aborted: abortAnswer)
        }
        func listActions(_ request: WalletListActionsRequest) async throws -> WalletListActionsResult {
            throw NotUsed()
        }
        func internalizeAction(
            _ request: WalletInternalizeActionRequest
        ) async throws -> WalletInternalizeActionResult {
            throw NotUsed()
        }
    }

    /// The server's side of BRC-105, one scripted answer per application request.
    private actor PaymentServer {
        enum Answer {
            /// A signed 402 with these payment headers (nil leaves a header out).
            case paymentRequired(version: String? = "1.0", satoshis: String? = "1000",
                prefix: String? = TS.prefix)
            case status(Int, body: String = "{\"ok\":true}")
            /// The request reached the server, but no reply reached the client.
            case dropped
            /// The transport could not connect, so the request never left. The server's record of
            /// it stands in for the attempt.
            case unreachable
        }

        private var answers: [Answer]
        /// The `x-bsv-payment` header of each request, nil for an unpaid one.
        private(set) var payments: [String?] = []
        private(set) var requests: [BRC104Request] = []

        init(_ answers: [Answer]) { self.answers = answers }

        func answer(_ request: BRC104Request) throws -> TestPeerReply {
            requests.append(request)
            payments.append(request.headers.first { $0.name == "x-bsv-payment" }?.value)
            guard !answers.isEmpty else { throw NotUsed() }
            switch answers.removeFirst() {
            case .paymentRequired(let version, let satoshis, let prefix):
                var headers: [String: String] = [:]
                headers["x-bsv-payment-version"] = version
                headers["x-bsv-payment-satoshis-required"] = satoshis
                headers["x-bsv-payment-derivation-prefix"] = prefix
                return TestPeerReply(status: 402, headers: headers,
                    body: Array(#"{"status":"error","code":"ERR_PAYMENT_REQUIRED"}"#.utf8))
            case .status(let status, let body):
                return TestPeerReply(status: status, body: Array(body.utf8))
            case .dropped:
                throw URLError(.networkConnectionLost)
            case .unreachable:
                throw URLError(.cannotConnectToHost)
            }
        }
    }

    /// Records each payment `onPayment` saw, and how many requests the server had read by then.
    private actor PaymentLog {
        private(set) var entries: [(payment: BRC105Payment, requestsSent: Int)] = []
        func record(_ payment: BRC105Payment, requestsSent: Int) {
            entries.append((payment, requestsSent))
        }
    }

    // MARK: - Fixtures

    private let baseURL = URL(string: "https://Wallet.Example:443")!

    private func keys() throws -> (client: PrivateKey, server: PrivateKey) {
        (try PrivateKey(Array(repeating: 0x11, count: 32)),
         try PrivateKey(Array(repeating: 0x22, count: 32)))
    }

    private struct Fixture {
        let session: AuthenticatedSession
        let peer: TestPeer
        let server: PaymentServer
        let payer: FakePayer
        let log: PaymentLog
    }

    private func fixture(_ answers: [PaymentServer.Answer], payerKey: PrivateKey? = nil) throws -> Fixture {
        let keys = try keys()
        let peer = TestPeer(key: keys.server)
        let server = PaymentServer(answers)
        let payer = FakePayer(key: payerKey ?? keys.client, transaction: try Hex.decode(TS.atomicHex, maximumDecodedByteCount: 1_000))
        let session = AuthenticatedSession(baseURL: baseURL, wallet: ProtoWallet(rootKey: keys.client), transport: peer)
        return Fixture(session: session, peer: peer, server: server, payer: payer, log: PaymentLog())
    }

    private func start(_ fixture: Fixture) async {
        let server = fixture.server
        await fixture.peer.setResponder { try await server.answer($0) }
    }

    /// `sendPaid` with each suffix taken from TypeScript's `invalid` half, so the payment is the
    /// vector's, and `onPayment` logged.
    private func sendPaid(
        _ fixture: Fixture, payment: BRC105Payment? = nil, attempts: Int = 3,
        onPayment: (@Sendable (BRC105Payment) async throws -> Void)? = nil
    ) async throws -> AuthenticatedResponse {
        let server = fixture.server
        let log = fixture.log
        let half = try Hex.decode(TS.invalidHalf, maximumDecodedByteCount: 16)
        return try await fixture.session.sendPaid(
            method: "POST", path: "/jobs", query: "?x=1",
            headers: ["content-type": "application/json"], body: Array(#"{"name":"luke"}"#.utf8),
            payer: fixture.payer, payment: payment, paymentRetryAttempts: attempts,
            onPayment: onPayment ?? { payment in
                await log.record(payment, requestsSent: await server.requests.count)
            },
            makeSuffix: { try await AuthNonce.create($0, counterparty: .self, random: half) }
        )
    }

    private func vectorPayment() throws -> BRC105Payment {
        try BRC105Payment(
            derivationPrefix: TS.prefix, derivationSuffix: TS.suffix, serverIdentityKey: TS.serverKey,
            satoshisRequired: 1000, transaction: try Hex.decode(TS.atomicHex, maximumDecodedByteCount: 1_000)
        )
    }

    // MARK: - The peer's identity on every response

    func test_aResponseNamesThePeerThatSignedIt() async throws {
        let keys = try keys()
        let peer = TestPeer(key: keys.server)
        let session = AuthenticatedSession(baseURL: baseURL, wallet: ProtoWallet(rootKey: keys.client), transport: peer)

        let response = try await session.send(method: "GET", path: "/price")

        XCTAssertEqual(response.headers["x-bsv-auth-identity-key"], TS.serverKey)
        XCTAssertEqual(response.header("X-BSV-Auth-Identity-Key"), TS.serverKey)
        XCTAssertNil(response.header("x-bsv-payment-version"))
    }

    func test_signedReplyHeadersAreReadWhateverTheirCase() {
        let response = AuthenticatedResponse(
            statusCode: 402, headers: ["x-bsv-payment-version": "1.0"], body: []
        )
        XCTAssertEqual(response.header("X-BSV-Payment-Version"), "1.0")
        XCTAssertEqual(response.header("x-bsv-payment-version"), "1.0")
    }

    // MARK: - createNonce

    func test_aNonceMatchesTypeScriptForTheSameRandomHalf() async throws {
        let wallet = ProtoWallet(rootKey: try keys().client)
        for vector in TS.nonces {
            let half = try Hex.decode(vector.half, maximumDecodedByteCount: 16)
            XCTAssertEqual(Hex.encode(Array(AuthNonce.keyID(for: half).utf8)), vector.keyIDUTF8, vector.name)
            let nonce = try await AuthNonce.create(wallet, counterparty: .self, random: half)
            XCTAssertEqual(nonce, vector.nonce, vector.name)
        }
    }

    /// `verifyNonce` checks the HMAC of the first sixteen bytes under the same key ID.
    func test_aFreshNonceVerifiesWithTheWalletThatMadeIt() async throws {
        let wallet = ProtoWallet(rootKey: try keys().client)
        let nonce = try await AuthNonce.create(wallet)
        let bytes = try XCTUnwrap(Data(base64Encoded: nonce))
        XCTAssertEqual(bytes.count, 48)
        let half = Array(bytes.prefix(16))
        let verified = try await wallet.verifyHMAC(WalletVerifyHMACRequest(
            protocolID: WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "server hmac"),
            keyID: WalletKeyID(AuthNonce.keyID(for: half)), data: half,
            hmac: WalletHMAC(bytes: Array(bytes.dropFirst(16)))
        ))
        XCTAssertTrue(verified.valid)
        let other = try await AuthNonce.create(wallet)
        XCTAssertNotEqual(nonce, other)
    }

    // MARK: - Pay and retry

    func test_a402IsPaidAsAuthFetchPaysItAndTheRequestRetried() async throws {
        let fixture = try fixture([.paymentRequired(), .status(201, body: #"{"jobId":"abc"}"#)])
        await start(fixture)

        let response = try await sendPaid(fixture)

        XCTAssertEqual(response.statusCode, 201)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), #"{"jobId":"abc"}"#)
        XCTAssertEqual(response.header("x-bsv-auth-identity-key"), TS.serverKey)

        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
        let action = try XCTUnwrap(actions.first)
        XCTAssertEqual(action.description, TS.description)
        XCTAssertNil(action.inputs)
        XCTAssertNil(action.inputBEEF)
        XCTAssertNil(action.labels)
        XCTAssertNil(action.lockTime)
        XCTAssertNil(action.version)
        XCTAssertEqual(action.options, try WalletCreateActionOptions(randomizeOutputs: false))
        let outputs = try XCTUnwrap(action.outputs)
        XCTAssertEqual(outputs.count, 1)
        let output = try XCTUnwrap(outputs.first)
        XCTAssertEqual(Hex.encode(output.lockingScript), TS.lockingScript)
        XCTAssertEqual(output.satoshis, 1000)
        XCTAssertEqual(output.outputDescription, "HTTP request payment")
        XCTAssertEqual(output.customInstructions, TS.customInstructions)
        XCTAssertNil(output.basket)
        XCTAssertEqual(output.tags, [])

        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header])
        let requests = await fixture.server.requests
        XCTAssertEqual(requests.count, 2)
        for request in requests {
            XCTAssertEqual(request.method, "POST")
            XCTAssertEqual(request.path, "/jobs")
            XCTAssertEqual(request.query, "?x=1")
            XCTAssertEqual(request.body, Array(#"{"name":"luke"}"#.utf8))
            XCTAssertTrue(request.headers.contains(BRC104Header(name: "content-type", value: "application/json")))
        }

        let logged = await fixture.log.entries
        XCTAssertEqual(logged.count, 1)
        XCTAssertEqual(logged.first?.requestsSent, 1, "onPayment runs before the paid send")
        let payment = try XCTUnwrap(logged.first?.payment)
        XCTAssertEqual(payment, try vectorPayment())
        XCTAssertEqual(payment.transactionID, TS.txid)
        XCTAssertEqual(payment.headerValue, TS.header)
    }

    /// The vector's Atomic BEEF is what this SDK writes for the same transaction ID, so a real
    /// wallet's result serializes to the bytes TypeScript would send.
    func test_theVectorAtomicBEEFIsWhatThisSDKWrites() throws {
        let txid = try TransactionID(displayHex: TS.txid)
        let beef = try BEEF(version: .v2, merklePaths: [], transactions: [.transactionID(txid)], limits: StorageLimits.beef)
        let atomic = try AtomicBEEF(subjectTransactionID: txid, beef: beef, limits: StorageLimits.beef)
        XCTAssertEqual(Hex.encode(try atomic.serialized(limits: StorageLimits.beef)), TS.atomicHex)
    }

    func test_aReplyOtherThan402IsReturnedWithoutPaying() async throws {
        let fixture = try fixture([.status(200, body: #"{"priceSats":1000}"#)])
        await start(fixture)

        let response = try await sendPaid(fixture)

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), #"{"priceSats":1000}"#)
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
        let logged = await fixture.log.entries
        XCTAssertTrue(logged.isEmpty)
    }

    /// Each 402 the client can't meet is refused with AuthFetch's message for it, in AuthFetch's
    /// order, before anything is paid.
    func test_eachUnusable402IsRefusedWithTypeScriptsMessage() async throws {
        let cases: [(PaymentServer.Answer, BRC105Error, String)] = [
            (.paymentRequired(version: nil), .unsupportedVersion(server: nil),
             "Unsupported x-bsv-payment-version response header. Client version: 1.0, Server version: null"),
            (.paymentRequired(version: "2.0", satoshis: nil), .unsupportedVersion(server: "2.0"),
             "Unsupported x-bsv-payment-version response header. Client version: 1.0, Server version: 2.0"),
            (.paymentRequired(satoshis: nil, prefix: nil), .missingSatoshisRequired,
             "Missing x-bsv-payment-satoshis-required response header."),
            (.paymentRequired(satoshis: ""), .missingSatoshisRequired,
             "Missing x-bsv-payment-satoshis-required response header."),
            (.paymentRequired(satoshis: "abc", prefix: nil), .invalidSatoshisRequired("abc"),
             "Invalid x-bsv-payment-satoshis-required response header value."),
            (.paymentRequired(satoshis: "0"), .invalidSatoshisRequired("0"),
             "Invalid x-bsv-payment-satoshis-required response header value."),
            (.paymentRequired(satoshis: "-5"), .invalidSatoshisRequired("-5"),
             "Invalid x-bsv-payment-satoshis-required response header value."),
            (.paymentRequired(prefix: nil), .missingDerivationPrefix,
             "Missing x-bsv-payment-derivation-prefix response header."),
            (.paymentRequired(prefix: ""), .missingDerivationPrefix,
             "Missing x-bsv-payment-derivation-prefix response header."),
        ]
        for (answer, expected, message) in cases {
            let fixture = try fixture([answer])
            await start(fixture)
            do {
                _ = try await sendPaid(fixture)
                XCTFail("\(expected) was not thrown")
            } catch let error as BRC105Error {
                XCTAssertEqual(error, expected)
                XCTAssertEqual(error.message, message)
                XCTAssertNotNil(error.errorDescription)
            }
            let actions = await fixture.payer.createActions
            XCTAssertTrue(actions.isEmpty, "\(expected)")
            let requests = await fixture.server.requests
            XCTAssertEqual(requests.count, 1, "\(expected)")
        }
    }

    func test_theAmountIsReadAsJavaScriptsParseIntReadsIt() {
        for (text, expected) in TS.parseInt {
            let wanted: UInt64? = expected.flatMap { $0 >= 0 ? UInt64($0) : nil }
            XCTAssertEqual(BRC105Requirement.javaScriptParseInt(text), wanted, text.debugDescription)
        }
        // TypeScript reads this as 1e20 and fails later, in createAction; it is refused here.
        XCTAssertNil(BRC105Requirement.javaScriptParseInt("99999999999999999999"))
        XCTAssertNil(BRC105Requirement.javaScriptParseInt("0x"))
        XCTAssertNil(BRC105Requirement.javaScriptParseInt(""))
    }

    func test_aHexAmountIsPaidAsTypeScriptPaysIt() async throws {
        let fixture = try fixture([.paymentRequired(satoshis: "0x10"), .status(201)])
        await start(fixture)

        _ = try await sendPaid(fixture)

        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.first?.outputs?.first?.satoshis, 16)
    }

    func test_anUnsigned402IsNeverPaid() async throws {
        let fixture = try fixture([])
        await fixture.peer.setUnsignedReplies(true, status: 402)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("an unsigned 402 was answered")
        } catch let error as AuthTransportError {
            guard case .unauthenticatedReply(let status, _, _) = error else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(status, 402)
        }
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty)
        let logged = await fixture.log.entries
        XCTAssertTrue(logged.isEmpty)
    }

    // MARK: - Retries

    func test_aPaidSendThatFailsIsRetriedWithTheSamePayment() async throws {
        let fixture = try fixture([.paymentRequired(), .unreachable, .status(201)])
        await start(fixture)

        let response = try await sendPaid(fixture)

        XCTAssertEqual(response.statusCode, 201)
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1, "the same payment is resent, never a second one")
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header, TS.header])
        let logged = await fixture.log.entries
        XCTAssertEqual(logged.count, 1)
    }

    func test_paidSendsStopAfterThreeAttemptsWithTypeScriptsMessage() async throws {
        let fixture = try fixture([.paymentRequired(), .unreachable, .unreachable, .unreachable, .status(201)])
        await start(fixture)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request succeeded")
        } catch let error as BRC105Error {
            guard case .paymentFailed(let url, let attempts, let maximum, let satoshis, let payee, let txid, _) = error else {
                return XCTFail("\(error)")
            }
            // AuthFetch names the URL as the caller wrote it, not normalized as the origin is.
            XCTAssertEqual(url, "https://Wallet.Example:443/jobs?x=1")
            XCTAssertEqual(attempts, 3)
            XCTAssertEqual(maximum, 3)
            XCTAssertEqual(satoshis, 1000)
            XCTAssertEqual(payee, TS.serverKey)
            XCTAssertEqual(txid, TS.txid)
            XCTAssertEqual(error.message, "Paid request to https://Wallet.Example:443/jobs?x=1 failed after "
                + "3/3 attempts. Sent 1000 satoshis to \(TS.serverKey).")
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header, TS.header, TS.header])
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
    }

    func test_theCallerSetsHowManyPaidSendsAreMade() async throws {
        let two = try fixture([.paymentRequired(), .unreachable, .unreachable, .status(201)])
        await start(two)
        do {
            _ = try await sendPaid(two, attempts: 2)
            XCTFail("the paid request succeeded")
        } catch BRC105Error.paymentFailed(_, let attempts, let maximum, _, _, _, _) {
            XCTAssertEqual(attempts, 2)
            XCTAssertEqual(maximum, 2)
        }
        let twoPayments = await two.server.payments
        XCTAssertEqual(twoPayments.count, 3)

        // Not positive is AuthFetch's default of three.
        let fallback = try fixture([.paymentRequired(), .unreachable, .unreachable, .status(201)])
        await start(fallback)
        let response = try await sendPaid(fallback, attempts: 0)
        XCTAssertEqual(response.statusCode, 201)
        let fallbackPayments = await fallback.server.payments
        XCTAssertEqual(fallbackPayments.count, 4)
    }

    /// A paid send answered with the same 402 is sent again with the same payment, at once, until
    /// the attempts are spent.
    func test_theSame402AfterPayingResendsTheSamePayment() async throws {
        let fixture = try fixture([.paymentRequired(), .paymentRequired(), .paymentRequired(), .paymentRequired()])
        await start(fixture)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request succeeded")
        } catch BRC105Error.paymentFailed(_, let attempts, _, _, _, _, let lastError) {
            XCTAssertEqual(attempts, 3)
            XCTAssertEqual(lastError, "Maximum payment attempts exceeded before retrying")
        }
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header, TS.header, TS.header])
    }

    func test_aChangedPriceOrPrefixIsPaidAgain() async throws {
        let otherPrefix = TS.nonces[0].nonce
        let fixture = try fixture([
            .paymentRequired(),
            .paymentRequired(prefix: otherPrefix),
            .paymentRequired(satoshis: "2000", prefix: otherPrefix),
            .status(201),
        ])
        await start(fixture)

        let response = try await sendPaid(fixture)

        XCTAssertEqual(response.statusCode, 201)
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.map { $0.outputs?.first?.satoshis }, [1000, 1000, 2000])
        let logged = await fixture.log.entries
        XCTAssertEqual(logged.map { $0.payment.derivationPrefix }, [TS.prefix, otherPrefix, otherPrefix])
        XCTAssertEqual(logged.map { $0.payment.satoshisRequired }, [1000, 1000, 2000])
        XCTAssertEqual(logged.map { $0.requestsSent }, [1, 2, 3], "each new payment is saved before it is sent")
        let payments = await fixture.server.payments
        XCTAssertEqual(Array(payments.dropFirst()), logged.map { Optional($0.payment.headerValue) })
    }

    /// With no paid send left, a changed 402 is not paid for: the payment could never be sent.
    func test_noNewPaymentIsMadeWhenNoAttemptIsLeft() async throws {
        let fixture = try fixture([.paymentRequired(), .paymentRequired(prefix: TS.nonces[0].nonce)])
        await start(fixture)

        do {
            _ = try await sendPaid(fixture, attempts: 1)
            XCTFail("the paid request succeeded")
        } catch BRC105Error.paymentFailed(_, let attempts, let maximum, _, _, _, _) {
            XCTAssertEqual(attempts, 1)
            XCTAssertEqual(maximum, 1)
        }
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
    }

    // MARK: - onPayment and resuming

    func test_anOnPaymentErrorStopsTheCallBeforeThePaidSend() async throws {
        struct SaveFailed: Error, Equatable {}
        let fixture = try fixture([.paymentRequired(), .status(201)])
        await start(fixture)

        do {
            _ = try await sendPaid(fixture, onPayment: { _ in throw SaveFailed() })
            XCTFail("the paid request was sent")
        } catch BRC105Error.paymentNotSaved(let payment, let reason) {
            XCTAssertEqual(payment, try vectorPayment(), "the payment is not lost with the save")
            XCTAssertTrue(reason.contains("SaveFailed"), reason)
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
    }

    func test_aWalletThatCannotPayIsReportedAndNothingIsSent() async throws {
        struct Broke: Error {}
        let fixture = try fixture([.paymentRequired(), .status(201)])
        await start(fixture)
        await fixture.payer.setCreateActionError(Broke())

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request was sent")
        } catch is Broke {}
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
        let logged = await fixture.log.entries
        XCTAssertTrue(logged.isEmpty)
    }

    /// A saved payment goes out with the first send: an unpaid request would get a new prefix
    /// and so a second payment.
    func test_aSavedPaymentIsResentWithoutPayingAgain() async throws {
        let fixture = try fixture([.status(201, body: #"{"jobId":"abc"}"#)])
        await start(fixture)

        let response = try await sendPaid(fixture, payment: try vectorPayment())

        XCTAssertEqual(response.statusCode, 201)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [TS.header])
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty)
        let logged = await fixture.log.entries
        XCTAssertTrue(logged.isEmpty)
    }

    func test_aSavedPaymentThatFailsIsRetriedAsItIs() async throws {
        let fixture = try fixture([.unreachable, .status(201)])
        await start(fixture)

        let response = try await sendPaid(fixture, payment: try vectorPayment())

        XCTAssertEqual(response.statusCode, 201)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [TS.header, TS.header])
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty)
    }

    func test_aPaidSendThatMayHaveRunIsNotResent() async throws {
        let fixture = try fixture([.paymentRequired(), .dropped, .status(201)])
        await start(fixture)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request succeeded")
        } catch let error as BRC105Error {
            guard case .outcomeUnknown(let url, let attempts, let payment, let lastError) = error else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(url, "https://Wallet.Example:443/jobs?x=1")
            XCTAssertEqual(attempts, 1)
            XCTAssertEqual(payment, try vectorPayment())
            XCTAssertFalse(lastError.isEmpty)
            XCTAssertNotNil(error.errorDescription)
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header], "the paid request is sent once")
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 1)
    }

    /// The server ran the paid request and signed its reply for a session this side lost: the
    /// session does not resend it, and neither does sendPaid.
    func test_aSignedReplyForALostSessionIsNotResent() async throws {
        let fixture = try fixture([.status(201), .status(201)])
        await start(fixture)
        await fixture.peer.setUnknownSessionNonceRemaining(1)

        do {
            _ = try await sendPaid(fixture, payment: try vectorPayment())
            XCTFail("the paid request succeeded")
        } catch BRC105Error.outcomeUnknown(_, let attempts, let payment, _) {
            XCTAssertEqual(attempts, 1)
            XCTAssertEqual(payment, try vectorPayment())
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [TS.header])
    }

    /// An unsigned 5xx may come from a proxy after the server ran the request.
    func test_anUnsignedServerErrorToAPaidSendIsNotResent() async throws {
        let fixture = try fixture([])
        await start(fixture)
        await fixture.peer.setUnsignedReplies(true, status: 503)

        do {
            _ = try await sendPaid(fixture, payment: try vectorPayment())
            XCTFail("the paid request succeeded")
        } catch BRC105Error.outcomeUnknown(_, let attempts, _, _) {
            XCTAssertEqual(attempts, 1)
        }
        let general = await fixture.peer.pathsSeen.filter { $0 == "/jobs" }
        XCTAssertEqual(general.count, 1)
    }

    /// An unsigned 401 is the server's auth refusing the request before it ran, so the paid send
    /// is resent once the session's own recovery is spent.
    func test_aPaidSendTheServerRefusedBeforeRunningItIsResent() async throws {
        let fixture = try fixture([.status(201)])
        await start(fixture)
        await fixture.peer.setUnauthorizedRemaining(AuthenticatedSession.sessionRecoveryRetries + 1)

        let response = try await sendPaid(fixture, payment: try vectorPayment())

        XCTAssertEqual(response.statusCode, 201)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [TS.header])
        let general = await fixture.peer.pathsSeen.filter { $0 == "/jobs" }
        XCTAssertEqual(general.count, AuthenticatedSession.sessionRecoveryRetries + 2)
    }

    func test_onlyAFailureBeforeAnyByteIsSentCountsAsNeverLeft() {
        XCTAssertTrue(AuthenticatedSession.neverLeft(URLError(.cannotConnectToHost)))
        XCTAssertTrue(AuthenticatedSession.neverLeft(URLError(.cannotFindHost)))
        XCTAssertTrue(AuthenticatedSession.neverLeft(URLError(.notConnectedToInternet)))
        XCTAssertTrue(AuthenticatedSession.neverLeft(URLError(.secureConnectionFailed)))
        XCTAssertFalse(AuthenticatedSession.neverLeft(URLError(.networkConnectionLost)))
        XCTAssertFalse(AuthenticatedSession.neverLeft(URLError(.timedOut)))
        XCTAssertFalse(AuthenticatedSession.neverLeft(AuthTransportError.transportFailed("x")))
    }

    // MARK: - Who pays whom

    func test_aPayerOtherThanTheSessionIdentityPaysNothing() async throws {
        let other = try PrivateKey(Array(repeating: 0x33, count: 32))
        let fixture = try fixture([.paymentRequired(), .status(201)], payerKey: other)
        await start(fixture)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request was sent")
        } catch let error as BRC105Error {
            guard case .payerMismatch(let payer, let session) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(payer, Hex.encode(other.publicKey.compressedBytes))
            XCTAssertEqual(session, Hex.encode(try keys().client.publicKey.compressedBytes))
            XCTAssertNotNil(error.errorDescription)
        }
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty, "no payment is built")
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
        let logged = await fixture.log.entries
        XCTAssertTrue(logged.isEmpty)
    }

    /// A mismatched payer is not retried as an attempt's failure when a changed 402 asks for a
    /// new payment.
    func test_aMismatchedPayerEndsTheCallWhenTheServerAsksAgain() async throws {
        let other = try PrivateKey(Array(repeating: 0x33, count: 32))
        let fixture = try fixture([.paymentRequired(prefix: TS.nonces[0].nonce), .status(201)], payerKey: other)
        await start(fixture)

        do {
            _ = try await sendPaid(fixture, payment: try vectorPayment())
            XCTFail("the paid request succeeded")
        } catch BRC105Error.payerMismatch {}
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [TS.header])
        let actions = await fixture.payer.createActions
        XCTAssertTrue(actions.isEmpty)
    }

    func test_aResumedPaymentForAnotherPeerIsNotSent() async throws {
        let fixture = try fixture([.status(201)])
        await start(fixture)
        let elsewhere = Hex.encode(try PrivateKey(Array(repeating: 0x33, count: 32)).publicKey.compressedBytes)
        let payment = try BRC105Payment(
            derivationPrefix: TS.prefix, derivationSuffix: TS.suffix, serverIdentityKey: elsewhere,
            satoshisRequired: 1000, transaction: try Hex.decode(TS.atomicHex, maximumDecodedByteCount: 1_000)
        )

        do {
            _ = try await sendPaid(fixture, payment: payment)
            XCTFail("the payment was sent")
        } catch let error as BRC105Error {
            XCTAssertEqual(error, .paymentPeerMismatch(payee: elsewhere, peer: TS.serverKey))
            XCTAssertNotNil(error.errorDescription)
        }
        let requests = await fixture.server.requests
        XCTAssertTrue(requests.isEmpty)
    }

    // MARK: - A funded payment is never dropped

    func test_anUnsignedPaymentIsAbortedAndReported() async throws {
        let fixture = try fixture([.paymentRequired(), .status(201)])
        await start(fixture)
        await fixture.payer.setResult(.unsigned)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request was sent")
        } catch BRC105Error.paymentUnusable(let txid, let aborted, _) {
            XCTAssertEqual(txid, TS.txid)
            XCTAssertTrue(aborted)
        }
        let aborts = await fixture.payer.aborted
        XCTAssertEqual(aborts.map(\.reference), [try WalletBase64Data(FakePayer.reference)])
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
    }

    func test_anAbortTheWalletRefusesIsReported() async throws {
        let fixture = try fixture([.paymentRequired(), .status(201)])
        await start(fixture)
        await fixture.payer.setResult(.unsigned)
        await fixture.payer.setAbortAnswer(false)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request was sent")
        } catch let error as BRC105Error {
            XCTAssertEqual(error, .paymentUnusable(transactionID: TS.txid, aborted: false,
                reason: "the wallet returned it unsigned"))
            XCTAssertTrue(error.message.contains(TS.txid), error.message)
        }
    }

    func test_aPaymentWithNoTransactionIsReportedWithItsTransactionID() async throws {
        let fixture = try fixture([.paymentRequired(), .status(201)])
        await start(fixture)
        await fixture.payer.setResult(.transactionIDOnly)

        do {
            _ = try await sendPaid(fixture)
            XCTFail("the paid request was sent")
        } catch BRC105Error.paymentUnusable(let txid, let aborted, _) {
            XCTAssertEqual(txid, TS.txid)
            XCTAssertFalse(aborted)
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil])
    }

    /// A new payment the wallet funds but can't hand back ends the call: it is not swallowed as a
    /// failed attempt and the old payment resent.
    func test_anUnusableNewPaymentIsNotSwallowed() async throws {
        let otherPrefix = TS.nonces[0].nonce
        let fixture = try fixture([.paymentRequired(), .paymentRequired(prefix: otherPrefix), .status(201)])
        await start(fixture)
        let payer = fixture.payer

        do {
            _ = try await sendPaid(fixture, onPayment: { _ in await payer.setResult(.transactionIDOnly) })
            XCTFail("the paid request succeeded")
        } catch BRC105Error.paymentUnusable(let txid, _, _) {
            XCTAssertEqual(txid, TS.txid)
        }
        let actions = await fixture.payer.createActions
        XCTAssertEqual(actions.count, 2)
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header], "the old payment is not resent")
    }

    func test_aNewPaymentThatCannotBeSavedIsThrownWithThePayment() async throws {
        struct SaveFailed: Error {}
        let otherPrefix = TS.nonces[0].nonce
        let fixture = try fixture([.paymentRequired(), .paymentRequired(prefix: otherPrefix), .status(201)])
        await start(fixture)
        let log = fixture.log

        do {
            _ = try await sendPaid(fixture, onPayment: { payment in
                await log.record(payment, requestsSent: 0)
                if await log.entries.count == 2 { throw SaveFailed() }
            })
            XCTFail("the paid request succeeded")
        } catch BRC105Error.paymentNotSaved(let payment, _) {
            XCTAssertEqual(payment.derivationPrefix, otherPrefix)
            XCTAssertEqual(payment.transactionID, TS.txid)
        }
        let payments = await fixture.server.payments
        XCTAssertEqual(payments, [nil, TS.header], "the unsaved payment is not sent")
    }

    // MARK: - The payment value

    func test_aPaymentSurvivesBeingSaved() throws {
        let payment = try vectorPayment()
        let data = try JSONEncoder().encode(payment)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["transaction"] as? String,
            Data(try Hex.decode(TS.atomicHex, maximumDecodedByteCount: 1_000)).base64EncodedString())
        XCTAssertEqual(try JSONDecoder().decode(BRC105Payment.self, from: data), payment)
    }

    func test_aPaymentMustCarryAnAtomicBEEF() throws {
        XCTAssertThrowsError(try BRC105Payment(
            derivationPrefix: TS.prefix, derivationSuffix: TS.suffix, serverIdentityKey: TS.serverKey,
            satoshisRequired: 1, transaction: Array(repeating: 0, count: 40)
        )) { XCTAssertEqual($0 as? BRC105Error, .invalidTransaction) }
        XCTAssertThrowsError(try BRC105Payment(
            derivationPrefix: TS.prefix, derivationSuffix: TS.suffix, serverIdentityKey: TS.serverKey,
            satoshisRequired: 1, transaction: [1, 1, 1, 1]
        )) { XCTAssertEqual($0 as? BRC105Error, .invalidTransaction) }
    }

    func test_thePaymentHeaderReplacesOneTheCallerSet() throws {
        let headers = AuthenticatedSession.headers(
            ["X-BSV-Payment": "stale", "content-type": "application/json"], paying: try vectorPayment()
        )
        XCTAssertEqual(headers, ["x-bsv-payment": TS.header, "content-type": "application/json"])
    }

    func test_retriesWaitAsAuthFetchWaits() {
        XCTAssertEqual(AuthenticatedSession.paymentRetryDelay(afterAttempt: 1), 250_000_000)
        XCTAssertEqual(AuthenticatedSession.paymentRetryDelay(afterAttempt: 2), 500_000_000)
        XCTAssertEqual(AuthenticatedSession.paymentRetryDelay(afterAttempt: 9), 1_250_000_000)
    }
}
