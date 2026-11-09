import CryptoKit
import Foundation

/// `derive`: the chain from recovery code and record to every key, each
/// step reported, then the evidence pass against a database when given.
enum DeriveReport {

    static func run(record: VaultRecord, code: RecoveryCode, db: Database?, reveal: Bool) throws -> Report {
        var report = Report(title: "veri-popt derive")

        report.section("Record") { s in
            s.line("account: \(record.id)")
            s.line("kdfSalt: \(record.kdfSalt.base64EncodedString())")
            s.line("signingPublicKey: \(record.signingPublicKey.base64EncodedString())")
            if let created = record.createdAt { s.line("createdAt: \(Date(timeIntervalSince1970: Double(created) / 1000))") }
        }
        report.section("Recovery code") { s in
            s.line("code: \(masked(code))")
            s.line("key material: the \(code.keyMaterial.count)-byte hyphenated string (SPEC § 3)")
        }

        // Whose database is this? Judged before the chain: a record and a
        // copy from different accounts is the likeliest reason a code fails.
        if let db {
            try report.section("Account") { s in
                if let dbUser = try db.userId() {
                    if dbUser == record.id {
                        s.ok("the database belongs to the record's account \(record.id)")
                    } else {
                        s.fail("the database belongs to \(dbUser), the record to \(record.id): export the locked keys while signed into the database's account, or copy that account's database")
                    }
                } else {
                    s.warning("the database names no account (no local_info row)")
                }
            }
        }

        let session: Session
        do {
            session = try Session(record: record, code: code, db: db)
        } catch let error as Derivation.Error {
            report.section("Derivation chain") { s in
                s.fail(failure(error))
            }
            return report
        }

        report.section("Derivation chain") { s in
            let keys = session.keys
            s.line("recoveryKEK   \(Fingerprint.of(Derivation.recoveryKEK(code: code, salt: record.kdfSalt)))   HKDF(code, kdfSalt, \"\(Derivation.Constants.recoveryInfo)\")")
            s.line("KEK           \(Fingerprint.of(keys.kek))   opened masterKekRecoveryWrapped")
            s.line("masterDEK     \(Fingerprint.of(keys.masterDEK))   opened masterDekWrapped")
            s.line("curvePrivate  \(Fingerprint.of(keys.curvePrivate.rawRepresentation))   opened privateKeyWrapped; public \(keys.curvePublic.base64EncodedString())")
            s.line("signingKey    \(Fingerprint.of(keys.signingPrivate.rawRepresentation))   opened signingKeyWrapped; public \(keys.signingPublic.base64EncodedString())")
            s.ok("the recovery code opened the KEK, and the KEK opened the Master DEK, the Curve25519 key and the Ed25519 key")
            if keys.signingPublic == record.signingPublicKey {
                s.ok("the derived Ed25519 public key is the one the record publishes")
            } else {
                s.fail("the derived Ed25519 public key differs from the record's signingPublicKey")
            }
        }

        report.section("Subkeys") { s in
            let t = session.subkeys
            s.line("personalBlocksKey  \(Fingerprint.of(t.personalBlocksKey))   HKDF(masterDEK, \"\(Derivation.Constants.masterSalt)\", \"\(Derivation.Constants.personalBlocksInfo)\")")
            s.line("sharedRootKey      \(Fingerprint.of(t.sharedRootKey))   HKDF(masterDEK, \"\(Derivation.Constants.masterSalt)\", \"\(Derivation.Constants.sharedRootInfo)\")")
            s.line("ownerWrapKey       \(Fingerprint.of(t.ownerWrapKey))   HKDF(sharedRootKey, \"\(Derivation.Constants.sharedRootSalt)\", \"\(Derivation.Constants.ownerWrapInfo)\")")
            s.line("shareExtensionKey  \(Fingerprint.of(t.shareExtensionKey))   HKDF(sharedRootKey, \"\(Derivation.Constants.sharedRootSalt)\", \"\(Derivation.Constants.shareExtensionInfo)\")")
            s.line("audienceMintKey    per audience: HKDF(sharedRootKey, \"\(Derivation.Constants.sharedRootSalt)\", \"\(Derivation.Constants.audienceInfoPrefix)<id>\")")
            s.line("fingerprints are the first 8 bytes of SHA-256 over the key; use --reveal for the keys themselves")
        }

        report.section("Negative control") { s in
            let wrong = altered(code)
            do {
                _ = try Derivation.unwrap(record: record, code: wrong)
                s.fail("a code with one character changed (\(masked(wrong))) still opened the record")
            } catch Derivation.Error.wrappedKEK(.authenticationFailed) {
                s.ok("a code with one character changed fails at the first unwrap, the KEK's tag check")
            } catch {
                s.fail("a code with one character changed failed in an unexpected way: \(error)")
            }
        }

        try KeyEvidence.run(session: session, into: &report)

        if reveal {
            report.section("Raw keys (--reveal)") { s in
                s.warning("these are the account's keys; anyone holding them reads every block. Do not paste them anywhere")
                let k = session.keys, t = session.subkeys
                s.line("KEK                \(k.kek.bytes.hex)")
                s.line("masterDEK          \(k.masterDEK.bytes.hex)")
                s.line("curvePrivate       \(k.curvePrivate.rawRepresentation.hex)")
                s.line("signingPrivate     \(k.signingPrivate.rawRepresentation.hex)")
                s.line("personalBlocksKey  \(t.personalBlocksKey.bytes.hex)")
                s.line("sharedRootKey      \(t.sharedRootKey.bytes.hex)")
                s.line("ownerWrapKey       \(t.ownerWrapKey.bytes.hex)")
                s.line("shareExtensionKey  \(t.shareExtensionKey.bytes.hex)")
            }
        }
        return report
    }

    // MARK: - Helpers

    /// `ABCD-····-····-····`: enough to recognize which code was used.
    static func masked(_ code: RecoveryCode) -> String {
        String(code.formatted.prefix(RecoveryCode.groupLength)) + "-····-····-····"
    }

    /// The same code with its first character replaced by another one from
    /// the alphabet, for the negative control.
    static func altered(_ code: RecoveryCode) -> RecoveryCode {
        var chars = Array(code.formatted)
        chars[0] = chars[0] == "A" ? "B" : "A"
        return try! RecoveryCode(parsing: String(chars))
    }

    static func failure(_ error: Derivation.Error) -> String {
        switch error {
        case .wrappedKEK(.authenticationFailed):
            "the recovery KEK does not open masterKekRecoveryWrapped: wrong recovery code, or a record from another account or an earlier rotation"
        case .wrappedKEK(let e):
            "masterKekRecoveryWrapped: \(e)"
        default:
            "the KEK opened but the record is inconsistent: \(error)"
        }
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
