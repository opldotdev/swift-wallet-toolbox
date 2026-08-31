import XCTest
@testable import ToolboxPortable

final class BRC38Tests: XCTestCase {
    private let timestamp = "2026-01-02T03:04:05.006Z"

    func test_minimalDocumentParsesAndSerializesAsCanonicalJCS() throws {
        let document = try BRC38WalletData.parse(minimalJSON())
        let canonical = try document.canonicalJSON()

        XCTAssertTrue(canonical.hasPrefix("{\"brc\":38,\"exportedAt\":"))
        XCTAssertFalse(canonical.contains(":null"))
        XCTAssertEqual(try BRC38WalletData.parse(canonical), document)
    }

    func test_canonicalSerializationSortsTablesAndUsesECMAScriptNumbers() throws {
        let json = minimalJSON(transactions: """
            [{"created_at":"\(timestamp)","updated_at":"\(timestamp)","transactionId":2,"userId":1,"satoshis":1e-7},
             {"created_at":"\(timestamp)","updated_at":"\(timestamp)","transactionId":1,"userId":1,"satoshis":1e20}]
            """)
        let canonical = try BRC38WalletData.parse(json).canonicalJSON()

        XCTAssertLessThan(
            try XCTUnwrap(canonical.range(of: "\"transactionId\":1")?.lowerBound),
            try XCTUnwrap(canonical.range(of: "\"transactionId\":2")?.lowerBound)
        )
        XCTAssertTrue(canonical.contains("\"satoshis\":100000000000000000000"))
        XCTAssertTrue(canonical.contains("\"satoshis\":1e-7"))
    }

    func test_rejectsNullMalformedEncodingAndDanglingRelationships() throws {
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(userExtra: ",\"name\":null"))) {
            XCTAssertEqual($0 as? BRC38Error, .nullValue("document.user.name"))
        }
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(transactions: "[{\"transactionId\":1,\"userId\":1,\"rawTx\":\"abc\"}]")
        )) {
            guard case .invalidBase64? = $0 as? BRC38Error else {
                return XCTFail("unexpected error: \($0)")
            }
        }
        let output = "[{\"outputId\":1,\"userId\":1,\"transactionId\":99}]"
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(outputs: output))) {
            XCTAssertEqual($0 as? BRC38Error, .relationship("output.transactionId"))
        }
    }

    func test_rejectsInvalidTimestampAndResourceLimits() throws {
        let invalidDate = minimalJSON().replacingOccurrences(of: timestamp, with: "2026-02-30T03:04:05.006Z")
        XCTAssertThrowsError(try BRC38WalletData.parse(invalidDate))
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(), limits: BRC38Limits(maximumUTF8ByteCount: 8, maximumRowCount: 10)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .documentTooLarge(maximumByteCount: 8))
        }
    }

    func test_optionalStructuredJSONFieldsMayBeOmitted() throws {
        let syncState = """
            [{"syncStateId":1,"userId":1,"storageIdentityKey":"remote","storageName":"remote",\
            "syncMap":{}}]
            """
        XCTAssertNoThrow(try BRC38WalletData.parse(minimalJSON(syncStates: syncState)))
    }

    private func minimalJSON(
        userExtra: String = "",
        transactions: String = "[]",
        outputs: String = "[]",
        syncStates: String = "[]"
    ) -> String {
        """
        {"brc":38,"title":"User Wallet Data Format","formatVersion":1,
        "exportedAt":"\(timestamp)",
        "sourceStorage":{"created_at":"\(timestamp)","updated_at":"\(timestamp)","storageIdentityKey":"source","storageName":"source","chain":"test"},
        "user":{"created_at":"\(timestamp)","updated_at":"\(timestamp)","userId":1,"identityKey":"identity","activeStorage":"source"\(userExtra)},
        "tables":{"provenTxs":[],"provenTxReqs":[],"outputBaskets":[],"transactions":\(transactions),"commissions":[],"outputs":\(outputs),"outputTags":[],"outputTagMaps":[],"txLabels":[],"txLabelMaps":[],"certificates":[],"certificateFields":[],"syncStates":\(syncStates)}}
        """
    }
}
