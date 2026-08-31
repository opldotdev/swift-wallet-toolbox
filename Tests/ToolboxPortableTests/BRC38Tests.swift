import Foundation
import XCTest
@testable import ToolboxPortable

final class BRC38Tests: XCTestCase {
    private struct FieldOrderVector: Decodable {
        let fieldNames: [String]
        let canonicalOrder: [String]
    }

    private let timestamp = "2026-01-02T03:04:05.006Z"

    func test_minimalDocumentParsesAndSerializesAsCanonicalJCS() throws {
        let document = try BRC38WalletData.parse(minimalJSON())
        let canonical = try document.canonicalJSON()
        XCTAssertTrue(canonical.hasPrefix("{\"brc\":38,\"exportedAt\":"))
        XCTAssertFalse(canonical.contains(":null"))
        XCTAssertEqual(try BRC38WalletData.parse(canonical), document)
    }

    func test_canonicalSerializationSortsTablesAndUsesECMAScriptNumbers() throws {
        let rows = "[\(transaction(id: 2, extensionNumber: "1e-7")),\(transaction(id: 1, extensionNumber: "1e20"))]"
        let canonical = try BRC38WalletData.parse(minimalJSON(transactions: rows)).canonicalJSON()
        XCTAssertLessThan(
            try XCTUnwrap(canonical.range(of: "\"transactionId\":1")?.lowerBound),
            try XCTUnwrap(canonical.range(of: "\"transactionId\":2")?.lowerBound)
        )
        XCTAssertTrue(canonical.contains("\"extensionNumber\":100000000000000000000"))
        XCTAssertTrue(canonical.contains("\"extensionNumber\":1e-7"))
    }

    func test_rejectsDuplicateAndUnknownObjectNamesButPreservesDistinctUnicodeNames() throws {
        let duplicate = minimalJSON().replacingOccurrences(
            of: "\"brc\":38", with: "\"brc\":38,\"\\u0062rc\":38"
        )
        XCTAssertThrowsError(try BRC38WalletData.parse(duplicate)) {
            XCTAssertEqual($0 as? BRC38Error, .duplicateJSONKey("brc"))
        }

        let normalizationEquivalent = minimalJSON().replacingOccurrences(
            of: "\"activeStorage\":\"source\"",
            with: "\"activeStorage\":\"source\",\"é\":1,\"e\\u0301\":2"
        )
        let document = try BRC38WalletData.parse(normalizationEquivalent)
        let canonical = try document.canonicalJSON()
        XCTAssertTrue(canonical.contains("\"e\u{301}\":2"))
        XCTAssertTrue(canonical.contains("\"é\":1"))
        XCTAssertEqual(try BRC38WalletData.parse(canonical), document)

        let forbiddenTable = minimalJSON().replacingOccurrences(
            of: "\"syncStates\":[]", with: "\"syncStates\":[],\"monitorEvents\":[]"
        )
        XCTAssertThrowsError(try BRC38WalletData.parse(forbiddenTable)) {
            XCTAssertEqual($0 as? BRC38Error, .unknownField("tables.monitorEvents"))
        }
    }

    func test_rejectsMissingRequiredFieldsAndMalformedNestedObjects() throws {
        let missing = transaction(id: 1).replacingOccurrences(of: ",\"status\":\"completed\"", with: "")
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(transactions: "[\(missing)]"))) {
            XCTAssertEqual($0 as? BRC38Error, .missingField("transactions[0].status"))
        }

        let request = provenTxReq(history: "{\"notes\":[{\"what\":7}]}")
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(provenTxReqs: "[\(request)]", transactions: "[\(transaction(id: 1, txid: "tx"))]")
        )) {
            XCTAssertEqual($0 as? BRC38Error, .invalidString("provenTxReqs[0].history.notes[0].what"))
        }

        let badSync = syncState().replacingOccurrences(
            of: "\"entityName\":\"commission\"", with: "\"entityName\":7"
        )
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(syncStates: "[\(badSync)]")))
    }

    func test_rejectsNullMalformedEncodingAndDanglingRelationships() throws {
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON().replacingOccurrences(of: "\"activeStorage\":\"source\"", with: "\"activeStorage\":null")
        ))

        let reference = Data("reference-1".utf8).base64EncodedString()
        let badBase64 = transaction(id: 1).replacingOccurrences(
            of: "\"reference\":\"\(reference)\"", with: "\"reference\":\"abc\""
        )
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(transactions: "[\(badBase64)]"))) {
            guard case .invalidBase64? = $0 as? BRC38Error else {
                return XCTFail("unexpected error: \($0)")
            }
        }

        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(outputs: "[\(output(transactionID: 99))]"))) {
            XCTAssertEqual($0 as? BRC38Error, .relationship("output.transactionId"))
        }
    }

    func test_rejectsDuplicatePrimaryAndCompositeKeys() throws {
        let transactions = "[\(transaction(id: 1)),\(transaction(id: 1))]"
        XCTAssertThrowsError(try BRC38WalletData.parse(minimalJSON(transactions: transactions))) {
            XCTAssertEqual($0 as? BRC38Error, .duplicateID("transactions.transactionId"))
        }

        let commissions = "[\(commission(id: 1)),\(commission(id: 2))]"
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(transactions: "[\(transaction(id: 1))]", commissions: commissions)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .duplicateID("commissions.transactionId"))
        }

        let fields = "[\(certificateField("email")),\(certificateField("email"))]"
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(certificates: "[\(certificate())]", certificateFields: fields)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .duplicateID("certificateFields.certificateId+fieldName"))
        }
    }

    func test_certificateFieldsUseDeterministicUTF16Ordering() throws {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "brc38-field-order", withExtension: "json", subdirectory: "Fixtures"
        ))
        let vector = try JSONDecoder().decode(FieldOrderVector.self, from: Data(contentsOf: url))
        let fields = "[\(vector.fieldNames.map(certificateField).joined(separator: ","))]"
        let canonical = try BRC38WalletData.parse(
            minimalJSON(certificates: "[\(certificate())]", certificateFields: fields)
        ).canonicalJSON()

        let canonicalBytes = Data(canonical.utf8)
        let offsets = try vector.canonicalOrder.map { fieldName in
            let needle = Data("\"fieldName\":\"\(fieldName)\"".utf8)
            return try XCTUnwrap(canonicalBytes.range(of: needle)?.lowerBound)
        }
        XCTAssertEqual(offsets, offsets.sorted())
    }

    func test_rejectsInvalidTimestampAndResourceLimits() throws {
        let invalidDate = minimalJSON().replacingOccurrences(of: timestamp, with: "2026-02-30T03:04:05.006Z")
        XCTAssertThrowsError(try BRC38WalletData.parse(invalidDate))
        XCTAssertThrowsError(try BRC38WalletData.parse(
            minimalJSON(), limits: BRC38Limits(maximumUTF8ByteCount: 8, maximumRowCount: 10)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .documentTooLarge(maximumByteCount: 8))
        }
        let unsafeInteger = minimalJSON().replacingOccurrences(
            of: "\"userId\":1", with: "\"userId\":9007199254740992"
        )
        XCTAssertThrowsError(try BRC38WalletData.parse(unsafeInteger)) {
            XCTAssertEqual($0 as? BRC38Error, .invalidInteger("user[0].userId"))
        }
    }

    func test_structuralBudgetsAcceptBoundaryAndRejectNextToken() throws {
        XCTAssertNoThrow(try StrictJSONPreflight.decode(
            Array("[0,1]".utf8), limits: structuralLimits(values: 3, members: 0, elements: 2)
        ))
        XCTAssertThrowsError(try StrictJSONPreflight.decode(
            Array("[0,1]".utf8), limits: structuralLimits(values: 2, members: 0, elements: 2)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .tooManyJSONValues(maximum: 2))
        }

        XCTAssertNoThrow(try StrictJSONPreflight.decode(
            Array("{\"a\":0,\"b\":1}".utf8),
            limits: structuralLimits(values: 3, members: 2, elements: 0)
        ))
        XCTAssertThrowsError(try StrictJSONPreflight.decode(
            Array("{\"a\":0,\"b\":1}".utf8),
            limits: structuralLimits(values: 3, members: 1, elements: 0)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .tooManyJSONObjectMembers(maximum: 1))
        }

        XCTAssertNoThrow(try StrictJSONPreflight.decode(
            Array("[[],[0]]".utf8), limits: structuralLimits(values: 4, members: 0, elements: 3)
        ))
        XCTAssertThrowsError(try StrictJSONPreflight.decode(
            Array("[[],[0]]".utf8), limits: structuralLimits(values: 4, members: 0, elements: 2)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .tooManyJSONArrayElements(maximum: 2))
        }
    }

    func test_objectMemberBudgetWinsBeforeDuplicateSetInsertion() throws {
        XCTAssertThrowsError(try StrictJSONPreflight.decode(
            Array("{\"a\":0,\"a\":1}".utf8),
            limits: structuralLimits(values: 3, members: 1, elements: 0)
        )) {
            XCTAssertEqual($0 as? BRC38Error, .tooManyJSONObjectMembers(maximum: 1))
        }
    }

    private func structuralLimits(
        values: Int,
        members: Int,
        elements: Int
    ) -> BRC38Limits {
        BRC38Limits(
            maximumUTF8ByteCount: 1_024,
            maximumRowCount: 10,
            maximumTotalValueCount: values,
            maximumTotalObjectMemberCount: members,
            maximumTotalArrayElementCount: elements
        )
    }

    private func minimalJSON(
        provenTxReqs: String = "[]",
        transactions: String = "[]",
        commissions: String = "[]",
        outputs: String = "[]",
        certificates: String = "[]",
        certificateFields: String = "[]",
        syncStates: String = "[]"
    ) -> String {
        """
        {"brc":38,"title":"User Wallet Data Format","formatVersion":1,
        "exportedAt":"\(timestamp)",
        "sourceStorage":{"created_at":"\(timestamp)","updated_at":"\(timestamp)","storageIdentityKey":"source","storageName":"source","chain":"test","dbtype":"SQLite","maxOutputScript":1024},
        "user":{"created_at":"\(timestamp)","updated_at":"\(timestamp)","userId":1,"identityKey":"identity","activeStorage":"source"},
        "tables":{"provenTxs":[],"provenTxReqs":\(provenTxReqs),"outputBaskets":[],"transactions":\(transactions),"commissions":\(commissions),"outputs":\(outputs),"outputTags":[],"outputTagMaps":[],"txLabels":[],"txLabelMaps":[],"certificates":\(certificates),"certificateFields":\(certificateFields),"syncStates":\(syncStates)}}
        """
    }

    private func transaction(
        id: Int,
        satoshis: String = "1",
        txid: String? = nil,
        extensionNumber: String? = nil
    ) -> String {
        let txidField = txid.map { ",\"txid\":\"\($0)\"" } ?? ""
        let extensionField = extensionNumber.map { ",\"extensionNumber\":\($0)" } ?? ""
        let reference = Data("reference-\(id)".utf8).base64EncodedString()
        return """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","transactionId":\(id),"userId":1,"status":"completed","reference":"\(reference)","isOutgoing":true,"satoshis":\(satoshis),"description":"payment"\(txidField)\(extensionField)}
        """
    }

    private func provenTxReq(history: String) -> String {
        """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","provenTxReqId":1,"status":"completed","attempts":1,"notified":true,"txid":"tx","history":\(history),"notify":{},"rawTx":"AA=="}
        """
    }

    private func commission(id: Int) -> String {
        """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","commissionId":\(id),"userId":1,"transactionId":1,"satoshis":1,"keyOffset":"key","isRedeemed":false,"lockingScript":"AA=="}
        """
    }

    private func output(transactionID: Int) -> String {
        """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","outputId":1,"userId":1,"transactionId":\(transactionID),"spendable":true,"change":false,"outputDescription":"output","vout":0,"satoshis":1,"providedBy":"you","purpose":"payment","type":"P2PKH"}
        """
    }

    private func certificate() -> String {
        """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","certificateId":1,"userId":1,"type":"AA==","serialNumber":"AA==","certifier":"02","subject":"03","revocationOutpoint":"tx.0","signature":"00","isDeleted":false}
        """
    }

    private func certificateField(_ name: String) -> String {
        """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","userId":1,"certificateId":1,"fieldName":"\(name)","fieldValue":"value","masterKey":"AA=="}
        """
    }

    private func syncState() -> String {
        let names = [
            "provenTx", "outputBasket", "transaction", "provenTxReq", "txLabel", "txLabelMap",
            "output", "outputTag", "outputTagMap", "certificate", "certificateField", "commission",
        ]
        let entries = names.map {
            "\"\($0)\":{\"entityName\":\"\($0)\",\"idMap\":{},\"count\":0}"
        }.joined(separator: ",")
        return """
        {"created_at":"\(timestamp)","updated_at":"\(timestamp)","syncStateId":1,"userId":1,"storageIdentityKey":"remote","storageName":"remote","status":"success","init":true,"refNum":"ref","syncMap":{\(entries)}}
        """
    }
}
