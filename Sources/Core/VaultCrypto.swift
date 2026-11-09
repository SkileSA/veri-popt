import CommonCrypto
import CryptoKit
import Foundation

/// Secret vaults (SPEC § 8): the config block, the passphrase KEK, the
/// vault DEK, and the per-row inner keys.
enum VaultCrypto {
    enum Constants {
        static let configInfo = "popt-secret-config-v1"
        static let kdfIterations: UInt32 = 600_000
        static let innerInfoPrefix = "secret-mode-v1/"
        static let thumbnailInfo = "popt-vault-thumbnails-v1"
        static let containerSalt = "popt-vault-default-container"
        static let containerInfoPrefix = "popt-vault-default-container-v1|"
        static let dictionarySalt = "popt-vault-synced-dict"
        static let dictionaryInfoPrefix = "popt-vault-synced-dict-v1|"
        static let configTypeTag = 8
        static let wrapperTypeTag = 9
        static let configVersion = 2
    }

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case pbkdf2(Int32)
        case notAConfig(typeTag: Int)
        case configVersion(Int)
        case malformedSlot(String)
        case notAWrapper(typeTag: Int)
        case malformedWrapper(String)
        case wrongPassphrase

        var description: String {
            switch self {
            case .pbkdf2(let s): "PBKDF2 failed with status \(s)"
            case .notAConfig(let t): "the row at the config id is not a secret config block (type \(t))"
            case .configVersion(let v): "secret config version \(v) is not the one this tool reads (\(Constants.configVersion))"
            case .malformedSlot(let f): "a vault slot lacks or mangles \(f)"
            case .notAWrapper(let t): "not a secret wrapper block (type \(t))"
            case .malformedWrapper(let f): "the wrapper payload lacks or mangles \(f)"
            case .wrongPassphrase: "the passphrase does not open this vault's key (wrong passphrase, or a rotated slot)"
            }
        }
    }

    // MARK: - The config block

    /// `hex(HKDF(masterDEK, salt "popt-it-master-dek", info "popt-secret-config-v1", 16 bytes))`.
    static func configBlockId(masterDEK: SymmetricKey) -> String {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterDEK, salt: Data(Derivation.Constants.masterSalt.utf8),
            info: Data(Constants.configInfo.utf8), outputByteCount: 16
        )
        return derived.bytes.hex
    }

    struct Slot: Equatable {
        let vaultId: String
        let name: String
        let hidden: Bool
        let wrappedDEK: String
        let kekSalt: Data
        let hkdfSalt: Data
    }

    /// The slots of a decrypted config block.
    static func slots(in block: DecryptedBlock) throws -> [Slot] {
        guard block.type == Constants.configTypeTag else { throw Error.notAConfig(typeTag: block.type) }
        let value = block.value as? [String: Any] ?? [:]
        let version = (value["version"] as? NSNumber)?.intValue ?? 0
        guard version == Constants.configVersion else { throw Error.configVersion(version) }
        return try (value["slots"] as? [[String: Any]] ?? []).map { raw in
            guard let vaultId = raw["vaultId"] as? String else { throw Error.malformedSlot("vaultId") }
            guard let wrapped = raw["wrappedDEK"] as? String else { throw Error.malformedSlot("wrappedDEK") }
            guard let kek = (raw["kekSalt"] as? String).flatMap({ Data(base64Encoded: $0) }) else { throw Error.malformedSlot("kekSalt") }
            guard let hkdf = (raw["hkdfSalt"] as? String).flatMap({ Data(base64Encoded: $0) }) else { throw Error.malformedSlot("hkdfSalt") }
            return Slot(vaultId: vaultId, name: raw["name"] as? String ?? "", hidden: raw["hidden"] as? Bool ?? false,
                        wrappedDEK: wrapped, kekSalt: kek, hkdfSalt: hkdf)
        }
    }

    // MARK: - Passphrase → KEK → vault DEK

    /// PBKDF2-SHA256 over the passphrase's UTF-8 bytes, 32 bytes out.
    static func kek(passphrase: String, salt: Data, iterations: UInt32 = Constants.kdfIterations) throws -> SymmetricKey {
        let pass = Data(passphrase.utf8)
        var out = Data(count: 32)
        let status = out.withUnsafeMutableBytes { outBytes in
            pass.withUnsafeBytes { passBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passBytes.bindMemory(to: Int8.self).baseAddress, pass.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                        outBytes.bindMemory(to: UInt8.self).baseAddress, 32
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw Error.pbkdf2(status) }
        return SymmetricKey(data: out)
    }

    /// Opens a slot's wrapped DEK with its passphrase.
    static func vaultDEK(slot: Slot, passphrase: String, iterations: UInt32 = Constants.kdfIterations) throws -> SymmetricKey {
        let kek = try kek(passphrase: passphrase, salt: slot.kekSalt, iterations: iterations)
        do {
            let bytes = try Envelope(json: slot.wrappedDEK).open(with: kek)
            guard bytes.count == 32 else { throw Error.malformedSlot("wrappedDEK (\(bytes.count) bytes)") }
            return SymmetricKey(data: bytes)
        } catch Envelope.Error.authenticationFailed {
            throw Error.wrongPassphrase
        }
    }

    // MARK: - Keys and ids derived from the vault DEK

    static func perBlockDEK(vaultDEK: SymmetricKey, blockId: String, hkdfSalt: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vaultDEK, salt: hkdfSalt,
                               info: Data((Constants.innerInfoPrefix + blockId).utf8), outputByteCount: 32)
    }

    static func thumbnailKey(vaultDEK: SymmetricKey, hkdfSalt: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vaultDEK, salt: hkdfSalt,
                               info: Data(Constants.thumbnailInfo.utf8), outputByteCount: 32)
    }

    static func defaultContainerId(vaultDEK: SymmetricKey, uiGroup: Int) -> String {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vaultDEK, salt: Data(Constants.containerSalt.utf8),
                               info: Data((Constants.containerInfoPrefix + String(uiGroup)).utf8), outputByteCount: 16).bytes.hex
    }

    static func dictionaryId(vaultDEK: SymmetricKey, type: String, scope: String) -> String {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vaultDEK, salt: Data(Constants.dictionarySalt.utf8),
                               info: Data((Constants.dictionaryInfoPrefix + type + "|" + scope).utf8), outputByteCount: 16).bytes.hex
    }

    // MARK: - Wrappers

    struct Wrapper {
        let vaultId: String
        let version: Int
        let inner: Envelope
    }

    /// Reads a decrypted personal block as a secret wrapper.
    static func wrapper(in block: DecryptedBlock) throws -> Wrapper {
        guard block.type == Constants.wrapperTypeTag else { throw Error.notAWrapper(typeTag: block.type) }
        let value = block.value as? [String: Any] ?? [:]
        guard let vaultId = value["vaultId"] as? String else { throw Error.malformedWrapper("vaultId") }
        guard let raw = value["innerCiphertext"] as? [String: Any] else { throw Error.malformedWrapper("innerCiphertext") }
        func bytes(_ field: String) throws -> Data {
            guard let s = raw[field] as? String, let d = Data(base64Encoded: s) else { throw Error.malformedWrapper("innerCiphertext.\(field)") }
            return d
        }
        return Wrapper(vaultId: vaultId, version: (value["version"] as? NSNumber)?.intValue ?? 0,
                       inner: Envelope(nonce: try bytes("nonce"), ciphertext: try bytes("ciphertext"), tag: try bytes("tag")))
    }

    /// Opens a wrapper's inner content under the vault's key for that row.
    static func openInner(_ wrapper: Wrapper, rowId: String, vaultDEK: SymmetricKey, hkdfSalt: Data) throws -> DecryptedBlock {
        let key = perBlockDEK(vaultDEK: vaultDEK, blockId: rowId, hkdfSalt: hkdfSalt)
        return try DecryptedBlock(plaintext: try wrapper.inner.open(with: key))
    }
}
