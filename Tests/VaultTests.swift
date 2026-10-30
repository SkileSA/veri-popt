import CryptoKit
import XCTest

final class VaultCryptoTests: XCTestCase {
    let vault = Vectors.object("vault")
    var slot0: [String: Any] { (vault["slots"] as! [[String: Any]])[0] }
    var slot1: [String: Any] { (vault["slots"] as! [[String: Any]])[1] }
    var personalKey: SymmetricKey { Vectors.key(Vectors.object("blocks", "personal"), "key") }

    func testConfigBlockId() {
        let master = Vectors.key(Vectors.object("vaults", "alice", "expected"), "masterDEK")
        XCTAssertEqual(VaultCrypto.configBlockId(masterDEK: master), Vectors.string(vault, "configBlockId"))
    }

    func testSlotsAndPassphrase() throws {
        let config = try BlockCrypto.open(payload: Vectors.string(vault, "configPayload"), with: personalKey)
        XCTAssertTrue(JSON.equal(config.object, vault["configExpected"]))
        let slots = try VaultCrypto.slots(in: config)
        XCTAssertEqual(slots.map(\.name), ["Diary", "Diary"])
        XCTAssertEqual(slots.map(\.hidden), [false, true])
        XCTAssertEqual(slots[0].vaultId, Vectors.string(slot0, "vaultId"))

        let passphrase = Vectors.string(slot0, "passphrase")
        XCTAssertEqual(try VaultCrypto.kek(passphrase: passphrase, salt: slots[0].kekSalt).bytes.hex, Vectors.string(slot0, "kek"))
        let dek = try VaultCrypto.vaultDEK(slot: slots[0], passphrase: passphrase)
        XCTAssertEqual(dek.bytes.hex, Vectors.string(slot0, "vaultDEK"))
        XCTAssertThrowsError(try VaultCrypto.vaultDEK(slot: slots[0], passphrase: Vectors.string(slot1, "passphrase"))) {
            XCTAssertEqual($0 as? VaultCrypto.Error, .wrongPassphrase)
        }
        XCTAssertThrowsError(try VaultCrypto.vaultDEK(slot: slots[1], passphrase: passphrase))
        XCTAssertNoThrow(try VaultCrypto.vaultDEK(slot: slots[1], passphrase: Vectors.string(slot1, "passphrase")))

        XCTAssertEqual(VaultCrypto.thumbnailKey(vaultDEK: dek, hkdfSalt: slots[0].hkdfSalt).bytes.hex, Vectors.string(slot0, "thumbnailKey"))
        for (group, id) in slot0["defaultContainerIds"] as! [String: String] {
            XCTAssertEqual(VaultCrypto.defaultContainerId(vaultDEK: dek, uiGroup: Int(group)!), id)
        }
        XCTAssertEqual(VaultCrypto.dictionaryId(vaultDEK: dek, type: "dashboard", scope: "vault"), Vectors.string(slot0, "dashboardId"))
    }

    func testWrapperOpensToTheInnerBlock() throws {
        let w = Vectors.object("vault", "wrapper")
        let outer = try BlockCrypto.open(payload: Vectors.string(w, "payload"), with: personalKey)
        XCTAssertTrue(JSON.equal(outer.object, w["outerExpected"]))
        let wrapper = try VaultCrypto.wrapper(in: outer)
        XCTAssertEqual(wrapper.vaultId, Vectors.string(slot0, "vaultId"))
        let config = try VaultCrypto.slots(in: try BlockCrypto.open(payload: Vectors.string(vault, "configPayload"), with: personalKey))[0]
        let dek = try VaultCrypto.vaultDEK(slot: config, passphrase: Vectors.string(slot0, "passphrase"))
        XCTAssertEqual(VaultCrypto.perBlockDEK(vaultDEK: dek, blockId: Vectors.string(w, "id"), hkdfSalt: config.hkdfSalt).bytes.hex, Vectors.string(w, "perBlockDEK"))
        let inner = try VaultCrypto.openInner(wrapper, rowId: Vectors.string(w, "id"), vaultDEK: dek, hkdfSalt: config.hkdfSalt)
        XCTAssertTrue(JSON.equal(inner.object, w["innerExpected"]))
        // The wrong row id derives the wrong key.
        XCTAssertThrowsError(try VaultCrypto.openInner(wrapper, rowId: "other", vaultDEK: dek, hkdfSalt: config.hkdfSalt))
    }

    func testConstantsMatchTheApp() {
        let constants = Vectors.object("vault", "constants")
        XCTAssertEqual(Int(VaultCrypto.Constants.kdfIterations), Vectors.int(constants, "kdfIterations"))
        XCTAssertEqual(VaultCrypto.Constants.innerInfoPrefix, Vectors.string(constants, "infoPrefix"))
    }
}

final class VaultReportTests: XCTestCase {
    private var kept: [TestDatabase] = []
    var slot0: [String: Any] { (Vectors.object("vault")["slots"] as! [[String: Any]])[0] }
    var slot1: [String: Any] { (Vectors.object("vault")["slots"] as! [[String: Any]])[1] }

    private func session(vault: Bool = true) throws -> Session {
        let test = try SessionTests.fixture()
        if vault { try test.seedVault() }
        test.close()
        kept.append(test)
        return try SessionTests.session("alice", db: try Database(path: test.path))
    }

    private func messages(_ r: Report, _ level: Report.Level) -> String {
        r.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }

    func testListShowsEverySlotHiddenIncluded() throws {
        let r = try VaultReport.list(session: try session())
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .ok).contains("holds 2 vault slot(s)"))
        XCTAssertTrue(messages(r, .note).contains("1 vault(s) are hidden"))
        XCTAssertTrue(messages(r, .note).contains("several vaults share a name (Diary)"))
        XCTAssertTrue(r.text().contains(Vectors.string(slot1, "vaultId") + "  \"Diary\"  (hidden)"), r.text())
    }

    func testNoVault() throws {
        let r = try VaultReport.list(session: try session(vault: false))
        XCTAssertTrue(messages(r, .note).contains("this account has no vault"))
    }

    func testAmbiguousNameAsksForTheId() throws {
        let r = try VaultReport.check(session: try session(), selector: .name("Diary"), passphrase: "x", vaultDb: nil)
        XCTAssertTrue(messages(r, .warning).contains("2 vaults are named \"Diary\"; pick one with --vault <id>"), r.text())
    }

    func testOpensTheVaultById() throws {
        let r = try VaultReport.check(session: try session(), selector: .id(Vectors.string(slot0, "vaultId")),
                                      passphrase: Vectors.string(slot0, "passphrase"), vaultDb: nil)
        XCTAssertFalse(r.hasFailures, r.text())
        let oks = messages(r, .ok)
        XCTAssertTrue(oks.contains("the passphrase opens the slot"))
        XCTAssertTrue(oks.contains("one character added fails the slot's tag check"))
        XCTAssertTrue(oks.contains("every wrapper opens under the per-row key"))
        XCTAssertTrue(r.text().contains("wrappers in this vault: 1; inner layer opened: 1; by type: 2×1"), r.text())
        XCTAssertTrue(messages(r, .note).contains("no popt-vault.sqlite in the folder"))
        XCTAssertTrue(messages(r, .note).contains("no row sits at an id derived from the vault DEK yet"))
    }

    func testOnePassphraseAcrossAllSlots() throws {
        let r = try VaultReport.check(session: try session(), selector: .all, passphrase: Vectors.string(slot0, "passphrase"), vaultDb: nil)
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .note).contains("this passphrase does not open this vault"))
        XCTAssertTrue(messages(r, .ok).contains("the passphrase opens the slot"))
    }

    func testWrongPassphraseOnANamedVaultFails() throws {
        let r = try VaultReport.check(session: try session(), selector: .id(Vectors.string(slot0, "vaultId")), passphrase: "nope", vaultDb: nil)
        XCTAssertTrue(messages(r, .fail).contains("does not open this vault"), r.text())
    }

    func testComparesWithTheVaultDatabase() throws {
        let s = try session()
        let w = Vectors.object("vault", "wrapper")
        let inner = try DecryptedBlock(plaintext: try Vectors.json(w, "innerExpected"))
        let vaultTest = try TestDatabase(name: "vault-\(UUID().uuidString)")
        vaultTest.createSchema()
        vaultTest.insertMirror(id: Vectors.string(w, "id"), owner: "alice-uid", audience: nil, revision: 1, block: inner)
        vaultTest.close()
        kept.append(vaultTest)
        let r = try VaultReport.check(session: s, selector: .id(Vectors.string(slot0, "vaultId")),
                                      passphrase: Vectors.string(slot0, "passphrase"), vaultDb: try Database(path: vaultTest.path))
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .ok).contains("vault database's mirror decrypts to what this tool decrypts"), r.text())
        XCTAssertTrue(r.text().contains("vault database: 1 row(s) compared, 1 matching"))
    }

    func testDerivedIdsAreFoundWhenRowsSitThere() throws {
        let test = try SessionTests.fixture()
        try test.seedVault()
        // A wrapper at the vault's pages container id, with any content.
        let containerId = (slot0["defaultContainerIds"] as! [String: String])["6"]!
        let personal = Vectors.key(Vectors.object("blocks", "personal"), "key")
        let dek = SymmetricKey(data: Vectors.hex(slot0, "vaultDEK"))
        let hkdfSalt = Vectors.base64(slot0, "hkdfSalt")
        let innerKey = VaultCrypto.perBlockDEK(vaultDEK: dek, blockId: containerId, hkdfSalt: hkdfSalt)
        let innerEnvelope = try Envelope(sealing: Data("{\"payload\":{\"type\":1,\"value\":{}}}".utf8), with: innerKey)
        let outer = "{\"payload\":{\"type\":9,\"value\":{\"version\":1,\"vaultId\":\"\(Vectors.string(slot0, "vaultId"))\",\"innerCiphertext\":{\"nonce\":\"\(innerEnvelope.nonce.base64EncodedString())\",\"ciphertext\":\"\(innerEnvelope.ciphertext.base64EncodedString())\",\"tag\":\"\(innerEnvelope.tag.base64EncodedString())\"}}}}"
        try test.insertMirroredBlock(id: containerId, owner: "alice-uid", audience: nil, payload: try Envelope(sealing: Data(outer.utf8), with: personal).json(), key: personal)
        test.close()
        kept.append(test)
        let s = try SessionTests.session("alice", db: try Database(path: test.path))
        let r = try VaultReport.check(session: s, selector: .id(Vectors.string(slot0, "vaultId")), passphrase: Vectors.string(slot0, "passphrase"), vaultDb: nil)
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .ok).contains("rows exist at ids derived from the vault DEK: default container for UI group 6"), r.text())
    }
}
