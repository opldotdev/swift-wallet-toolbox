import XCTest
import ToolboxCore
@testable import ToolboxActions

/// The manifest digest against `actionBatchManifestDigest` from `@bsv/wallet-toolbox` 2.15.3.
///
/// The expected digest is what the reference computes, under Node.js 22, for the same manifest
/// text. The manifest exercises what the payload rewrites: `rawTx` in place of `rawTxDigest`,
/// `dependencyBeef` in place of its digest, plan inputs with a `sourceLockingScript` to drop,
/// output scripts to blank, absent and present optional members, and strings with quotes,
/// backslashes, control characters and non-ASCII text.
final class ActionBatchDigestTests: XCTestCase {

    private let manifest = #"""
    {"format":2,"batchId":"YmF0Y2gtaWQtZm9yLXZlY3Rvcg==","actions":[{"reference":"cmVmLW9uZQ==","txid":"aa00000000000000000000000000000000000000000000000000000000000001","rawTx":[1,0,0,0,0,0,0,0,0,0],"lockingScriptDigests":["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],"deriveLockingScripts":true,"plan":{"reference":"cmVmLW9uZQ==","version":1,"lockTime":0,"inputs":[{"vin":0,"sourceTxid":"bb00000000000000000000000000000000000000000000000000000000000002","sourceVout":3,"sourceSatoshis":1000,"sourceLockingScript":"76a914","unlockingScriptLength":107,"providedBy":"storage","type":"P2PKH","spendingDescription":"","derivationPrefix":"cHJl","derivationSuffix":"c3Vm"}],"outputs":[{"vout":1,"satoshis":2,"lockingScript":"51","providedBy":"you","purpose":"","basket":"sigma","tags":["a","é☃😀"],"outputDescription":"anchor \"quoted\" \\ back"},{"vout":0,"satoshis":897,"lockingScript":"","providedBy":"storage","purpose":"change","basket":"default","tags":[],"outputDescription":"","derivationSuffix":"ZGVy"}],"derivationPrefix":"cHJlZml4","noSendChangeOutputVouts":[0]},"metadata":{"description":"tab\there\nnewline \u0001 ctl \u001f end","labels":["l1"],"isNoSend":true,"isDelayed":false,"inputs":[],"outputs":[{"lockingScript":"51","satoshis":2,"outputDescription":"anchor","basket":"sigma","tags":[]}]}},{"reference":"cmVmLXR3bw==","txid":"cc00000000000000000000000000000000000000000000000000000000000003","rawTxDigest":"0000000000000000000000000000000000000000000000000000000000000000","lockingScriptDigests":[],"deriveLockingScripts":true,"plan":{"reference":"cmVmLXR3bw==","version":2,"lockTime":500000,"inputs":[],"outputs":[],"derivationPrefix":"eA=="},"metadata":{"description":"two","labels":[],"isNoSend":false,"isDelayed":false,"inputs":[{"outpoint":{"txid":"aa00000000000000000000000000000000000000000000000000000000000001","vout":1},"inputDescription":"spend","unlockingScriptLength":1,"sequenceNumber":4294967295}],"outputs":[]}}],"dependencyBeef":[2,0,190,239,0,0],"inlineBlobs":{"x":[1]},"sendWith":["aa00000000000000000000000000000000000000000000000000000000000001","cc00000000000000000000000000000000000000000000000000000000000003"],"isDelayed":false}
    """#

    func test_theDigestMatchesTheReference() throws {
        let parsed = try OrderedJSON.parse(manifest)
        XCTAssertEqual(
            try ActionBatchDigest.manifest(parsed),
            "59da3ade3e43b219152e05d248aa83b96a97c8cfc1ecd753e6e0631066261ad5"
        )
    }

    func test_verifyRecomputesFromTheManifestItself() throws {
        let parsed = try OrderedJSON.parse(manifest)
        let signed = parsed.setting("digest", .string(try ActionBatchDigest.manifest(parsed)))
        XCTAssertTrue(try ActionBatchDigest.verify(signed))
        // Reordering a member changes the bytes storage hashes.
        let metadata = try XCTUnwrap(signed["actions"]?.arrayValue?.first?["metadata"]?.members)
        let reordered = OrderedJSON.object(metadata.reversed())
        var actions = try XCTUnwrap(signed["actions"]?.arrayValue)
        actions[0] = actions[0].setting("metadata", reordered)
        XCTAssertFalse(try ActionBatchDigest.verify(signed.setting("actions", .array(actions))))
    }

    func test_blobDigestIsLowercaseSHA256() {
        XCTAssertEqual(
            ActionBatchDigest.blob([]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    func test_onlyFormatTwoIsDigested() throws {
        let parsed = try OrderedJSON.parse(manifest).setting("format", .integer(1))
        XCTAssertThrowsError(try ActionBatchDigest.manifest(parsed))
    }
}
