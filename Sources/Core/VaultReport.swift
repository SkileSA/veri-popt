import CryptoKit
import Foundation

/// `vault-list` and `vault` (SPEC § 8).
enum VaultReport {
    static let maxListed = 15

    enum Error: Swift.Error, CustomStringConvertible {
        case noDatabase
        var description: String { "vaults need the database copy in the folder" }
    }

    enum Selector {
        case all
        case name(String)
        case id(String)
    }

    /// The config block: found at its derived id, opened under the
    /// personal key, its slots read. Shared by both commands.
    static func config(session: Session, into s: inout Report.Section) throws -> [VaultCrypto.Slot]? {
        guard let db = session.db else { throw Error.noDatabase }
        let id = VaultCrypto.configBlockId(masterDEK: session.keys.masterDEK)
        s.line("config block id: \(id)  (HKDF of the Master DEK, info \"\(VaultCrypto.Constants.configInfo)\")")
        guard let row = try db.query("SELECT payload, audience_id FROM blocks WHERE id = ?", [.text(id)]).first,
              let payload = row.string("payload")
        else {
            s.note("no secret config block at its id: this account has no vault")
            return nil
        }
        guard row.isNull("audience_id") else {
            s.fail("the row at the config id carries an audience; a secret config is a personal block")
            return nil
        }
        let block: DecryptedBlock
        do {
            block = try BlockCrypto.open(payload: payload, with: session.subkeys.personalBlocksKey)
        } catch {
            s.fail("the config block does not open under personalBlocksKey: \(error)")
            return nil
        }
        do {
            let slots = try VaultCrypto.slots(in: block)
            s.ok("the config block opens under personalBlocksKey (type \(VaultCrypto.Constants.configTypeTag), version \(VaultCrypto.Constants.configVersion)) and holds \(slots.count) vault slot(s)")
            return slots
        } catch {
            s.fail("\(error)")
            return nil
        }
    }

    // MARK: - vault-list

    static func list(session: Session) throws -> Report {
        var report = Report(title: "veri-popt vault-list")
        var slots: [VaultCrypto.Slot]?
        try report.section("Secret config") { s in
            slots = try config(session: session, into: &s)
        }
        guard let slots else { return report }
        report.section("Vaults") { s in
            if slots.isEmpty { s.note("no vault slots"); return }
            for slot in slots {
                s.line("\(slot.vaultId)  \"\(slot.name)\"\(slot.hidden ? "  (hidden)" : "")  kekSalt \(slot.kekSalt.base64EncodedString())  hkdfSalt \(slot.hkdfSalt.base64EncodedString())")
            }
            let hidden = slots.filter(\.hidden).count
            if hidden > 0 {
                s.note("\(hidden) vault(s) are hidden: hidden from the device's UI, not from whoever holds the Master DEK, which lists every slot here")
            }
            let names = Dictionary(grouping: slots, by: \.name).filter { $0.value.count > 1 }.keys.sorted()
            if !names.isEmpty {
                s.note("several vaults share a name (\(names.joined(separator: ", "))); pick one with `vault --vault <id>`")
            }
            s.line("open one: veri-popt vault <folder> --vault <id>   (or --name <name> when unique)")
        }
        return report
    }

    // MARK: - vault

    static func check(session: Session, selector: Selector, passphrase: String, vaultDb: Database?) throws -> Report {
        var report = Report(title: "veri-popt vault")
        guard let db = session.db else { throw Error.noDatabase }
        var slots: [VaultCrypto.Slot]?
        try report.section("Secret config") { s in
            slots = try config(session: session, into: &s)
        }
        guard let slots else { return report }

        // Which slots.
        let selected: [VaultCrypto.Slot]
        switch selector {
        case .all:
            selected = slots
        case .id(let id):
            selected = slots.filter { $0.vaultId == id }
            if selected.isEmpty {
                report.section("Selection") { $0.fail("no vault with id \(id); see `vault-list`") }
                return report
            }
        case .name(let name):
            let matches = slots.filter { $0.name == name }
            if matches.isEmpty {
                report.section("Selection") { $0.fail("no vault named \"\(name)\"; see `vault-list`") }
                return report
            }
            if matches.count > 1 {
                report.section("Selection") { s in
                    s.warning("\(matches.count) vaults are named \"\(name)\"; pick one with --vault <id>: \(matches.map(\.vaultId).joined(separator: ", "))")
                }
                return report
            }
            selected = matches
        }

        // Every wrapper of the account, opened once: the outer layer.
        var wrappers: [(id: String, row: Database.Row, outer: DecryptedBlock, wrapper: VaultCrypto.Wrapper)] = []
        var outerFailures: [String] = []
        let personalRows = try db.query(
            "SELECT id, revision, owner_id, root_id, audience_id, storage, storage_updated_at, storage_key, payload FROM blocks WHERE audience_id IS NULL AND owner_id = ? ORDER BY id",
            [.text(session.userId)]
        )
        for row in personalRows {
            guard let id = row.string("id"), let payload = row.string("payload"),
                  let outer = try? BlockCrypto.open(payload: payload, with: session.subkeys.personalBlocksKey)
            else { continue }
            guard outer.type == VaultCrypto.Constants.wrapperTypeTag else { continue }
            do {
                wrappers.append((id, row, outer, try VaultCrypto.wrapper(in: outer)))
            } catch {
                outerFailures.append("\(id): \(error)")
            }
        }
        report.section("Wrappers") { s in
            s.line("personal rows: \(personalRows.count); secret wrappers among them: \(wrappers.count) (type \(VaultCrypto.Constants.wrapperTypeTag), outer layer under personalBlocksKey like any personal block)")
            s.line("by vault: " + Dictionary(grouping: wrappers, by: { $0.wrapper.vaultId }).map { "\($0.key) \($0.value.count)" }.sorted().joined(separator: ", "))
            for line in outerFailures.prefix(Self.maxListed) { s.fail("wrapper \(line)") }
        }

        for slot in selected {
            try report.section("Vault \(slot.vaultId) \"\(slot.name)\"\(slot.hidden ? " (hidden)" : "")") { s in
                let dek: SymmetricKey
                do {
                    dek = try VaultCrypto.vaultDEK(slot: slot, passphrase: passphrase)
                } catch VaultCrypto.Error.wrongPassphrase {
                    let message = "this passphrase does not open this vault (PBKDF2-SHA256, \(VaultCrypto.Constants.kdfIterations) iterations, over kekSalt; the wrapped DEK's tag check failed)"
                    if case .all = selector {
                        s.note(message + ". Run again with its passphrase, naming the vault")
                    } else {
                        s.fail(message)
                    }
                    return
                }
                s.ok("the passphrase opens the slot: PBKDF2-SHA256 over kekSalt gives the KEK, the KEK opens the wrapped vault DEK (fingerprint \(Fingerprint.of(dek)))")
                if (try? VaultCrypto.vaultDEK(slot: slot, passphrase: passphrase + "x")) != nil {
                    s.fail("a passphrase with one character added also opened the slot")
                } else {
                    s.ok("a passphrase with one character added fails the slot's tag check")
                }

                let mine = wrappers.filter { $0.wrapper.vaultId == slot.vaultId }
                let ids = Set(mine.map(\.id))
                var opened = 0, byType: [Int: Int] = [:], problems: [String] = [], compared = 0, matched = 0, pending = 0
                for w in mine {
                    let inner: DecryptedBlock
                    do {
                        inner = try VaultCrypto.openInner(w.wrapper, rowId: w.id, vaultDEK: dek, hkdfSalt: slot.hkdfSalt)
                    } catch {
                        problems.append("\(w.id): inner layer does not open under HKDF(vaultDEK, hkdfSalt, \"\(VaultCrypto.Constants.innerInfoPrefix)<id>\"): \(error)")
                        continue
                    }
                    opened += 1
                    byType[inner.type, default: 0] += 1
                    // Containment: parents stay inside the vault.
                    if let parent = inner.parentBlockId, !ids.contains(parent) {
                        problems.append("\(w.id): the inner block's parent \(parent) is not a wrapper of this vault")
                    }
                    if let parent = w.outer.parentBlockId, !ids.contains(parent) {
                        problems.append("\(w.id): the wrapper's parent \(parent) is not a wrapper of this vault")
                    }
                    // The main mirror keeps the inner layer opaque.
                    if let mirror = try db.query("SELECT payload FROM plain_blocks WHERE id = ?", [.text(w.id)]).first,
                       let text = mirror.string("payload"), let object = try? JSON.parse(text) as? [String: Any] {
                        if object["innerCiphertext"] == nil {
                            problems.append("\(w.id): the main database's mirror row holds no innerCiphertext; the inner layer should be opaque there")
                        }
                    }
                    // The vault database, when copied while this vault was unlocked.
                    if let vaultDb, let mirror = try vaultDb.query("SELECT * FROM plain_blocks WHERE id = ?", [.text(w.id)]).first {
                        if mirror.int("revision") == w.row.int("revision") {
                            compared += 1
                            let diff = BlocksReport.differences(block: inner, blocksRow: w.row, mirror: mirror)
                            if diff.isEmpty { matched += 1 } else { problems.append("\(w.id): the vault database's mirror differs in \(diff.joined(separator: ", "))") }
                        } else {
                            pending += 1
                        }
                    }
                }
                s.line("wrappers in this vault: \(mine.count); inner layer opened: \(opened)" + (byType.isEmpty ? "" : "; by type: " + byType.keys.sorted().map { "\($0)×\(byType[$0]!)" }.joined(separator: ", ")))
                if mine.isEmpty {
                    s.note("this vault holds no blocks yet")
                } else if problems.isEmpty {
                    s.ok("every wrapper opens under the per-row key derived from the vault DEK, parents stay inside the vault, and the main database's mirror keeps the inner layer opaque")
                } else {
                    s.fail("\(problems.count) problem(s)")
                    for line in problems.prefix(Self.maxListed) { s.line(line) }
                }

                // Ids derived from the vault DEK, found among its rows.
                var found: [String] = []
                for group in 1 ... 9 where ids.contains(VaultCrypto.defaultContainerId(vaultDEK: dek, uiGroup: group)) {
                    found.append("default container for UI group \(group)")
                }
                if ids.contains(VaultCrypto.dictionaryId(vaultDEK: dek, type: "dashboard", scope: "vault")) {
                    found.append("the dashboard dictionary")
                }
                if found.isEmpty {
                    s.note("no row sits at an id derived from the vault DEK yet (default containers are minted when their widget first appears)")
                } else {
                    s.ok("rows exist at ids derived from the vault DEK: \(found.joined(separator: ", ")); the derivation matches the app's")
                }

                if vaultDb != nil {
                    s.line("vault database: \(compared) row(s) compared, \(matched) matching, \(pending) at another revision")
                    if compared > 0, matched == compared { s.ok("the vault database's mirror decrypts to what this tool decrypts") }
                } else {
                    s.note("no \(InputFolder.vaultDatabaseFileName) in the folder: the inner content was decrypted and counted, not compared with the app's own mirror (copy that file while the vault is unlocked to compare)")
                }
            }
        }
        return report
    }
}
