import CryptoKit
import XCTest

final class DerivationTests: XCTestCase {

    private func unwrap(_ name: String) throws -> (VaultKeys, [String: Any]) {
        let vault = Vectors.object("vaults", name)
        let record = try VaultRecord(json: try Vectors.json(vault, "record"))
        let code = try RecoveryCode(parsing: Vectors.string(vault, "code"))
        return (try Derivation.unwrap(record: record, code: code), Vectors.object("vaults", name, "expected"))
    }

    func testTheChainReproducesTheAppsKeys() throws {
        for name in ["alice", "bob"] {
            let (keys, expected) = try unwrap(name)
            XCTAssertEqual(keys.kek.bytes.hex, Vectors.string(expected, "kek"), name)
            XCTAssertEqual(keys.masterDEK.bytes.hex, Vectors.string(expected, "masterDEK"), name)
            XCTAssertEqual(keys.curvePrivate.rawRepresentation.hex, Vectors.string(expected, "curvePrivate"), name)
            XCTAssertEqual(keys.signingPrivate.rawRepresentation.hex, Vectors.string(expected, "signingPrivate"), name)
        }
    }

    func testPublicHalvesMatchWhatTheServerPublishes() throws {
        let (keys, expected) = try unwrap("alice")
        let record = try VaultRecord(json: try Vectors.json(Vectors.object("vaults", "alice"), "record"))
        XCTAssertEqual(keys.curvePublic.base64EncodedString(), Vectors.string(expected, "curvePublic"))
        XCTAssertEqual(keys.signingPublic.base64EncodedString(), Vectors.string(expected, "signingPublic"))
        XCTAssertEqual(keys.signingPublic, record.signingPublicKey)
    }

    func testWrongCodeFailsAtTheFirstUnwrap() throws {
        let vault = Vectors.object("vaults", "alice")
        let record = try VaultRecord(json: try Vectors.json(vault, "record"))
        let bobsCode = try RecoveryCode(parsing: Vectors.string(Vectors.object("vaults", "bob"), "code"))
        XCTAssertThrowsError(try Derivation.unwrap(record: record, code: bobsCode)) { error in
            guard case Derivation.Error.wrappedKEK(.authenticationFailed) = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testHyphensMatter() throws {
        // The same characters without hyphens are a different key (SPEC § 3).
        let vault = Vectors.object("vaults", "alice")
        let record = try VaultRecord(json: try Vectors.json(vault, "record"))
        let stripped = Vectors.string(vault, "code").replacingOccurrences(of: "-", with: "")
        let wrongKEK = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(stripped.utf8)),
            salt: record.kdfSalt,
            info: Data(Derivation.Constants.recoveryInfo.utf8),
            outputByteCount: 32
        )
        XCTAssertThrowsError(try Envelope(json: record.masterKekRecoveryWrapped).open(with: wrongKEK))
        let rightKEK = Derivation.recoveryKEK(code: try RecoveryCode(parsing: stripped), salt: record.kdfSalt)
        XCTAssertNoThrow(try Envelope(json: record.masterKekRecoveryWrapped).open(with: rightKEK))
    }

    func testSubkeyTree() throws {
        let v = Vectors.object("subkeys")
        let tree = Derivation.subkeys(masterDEK: Vectors.key(v, "masterDEK"))
        XCTAssertEqual(tree.personalBlocksKey.bytes.hex, Vectors.string(v, "personalBlocksKey"))
        XCTAssertEqual(tree.sharedRootKey.bytes.hex, Vectors.string(v, "sharedRootKey"))
        XCTAssertEqual(tree.ownerWrapKey.bytes.hex, Vectors.string(v, "ownerWrapKey"))
        XCTAssertEqual(tree.shareExtensionKey.bytes.hex, Vectors.string(v, "shareExtensionKey"))
        for mint in v["audienceMint"] as! [[String: Any]] {
            XCTAssertEqual(tree.audienceMintKey(Vectors.string(mint, "audienceId")).bytes.hex, Vectors.string(mint, "key"))
        }
    }

    func testSubkeysAreDistinctAndOneWay() throws {
        let tree = Derivation.subkeys(masterDEK: Vectors.key(Vectors.object("subkeys"), "masterDEK"))
        let all = [tree.personalBlocksKey, tree.sharedRootKey, tree.ownerWrapKey, tree.shareExtensionKey].map(\.bytes)
        XCTAssertEqual(Set(all).count, all.count)
        // Nothing below sharedRootKey reproduces personalBlocksKey.
        let fromRoot = Derivation.subkeys(masterDEK: tree.sharedRootKey)
        XCTAssertNotEqual(fromRoot.personalBlocksKey.bytes, tree.personalBlocksKey.bytes)
    }

    func testAudienceIds() {
        for v in Vectors.root["audienceIds"] as! [[String: Any]] {
            let peers = v["peerIds"] as! [String]
            XCTAssertEqual(Derivation.audienceId(ownerId: Vectors.string(v, "ownerId"), peerIds: peers), Vectors.string(v, "expect"))
            XCTAssertEqual(Derivation.audienceId(ownerId: Vectors.string(v, "ownerId"), peerIds: peers.reversed()), Vectors.string(v, "expect"))
        }
    }
}
