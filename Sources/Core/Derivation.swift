import CryptoKit
import Foundation

/// Every key derivation in SPEC § 5, as pure functions, with the constants
/// gathered in one place so the spec's tables map onto them line by line.
enum Derivation {

    /// The literal salts and info strings (SPEC § 5.1, § 5.2, § 5.3).
    enum Constants {
        static let recoveryInfo = "popt-recovery-kek-v1"
        static let masterSalt = "popt-it-master-dek"
        static let personalBlocksInfo = "popt-personal-blocks-v1"
        static let sharedRootInfo = "popt-shared-root-v1"
        static let sharedRootSalt = "popt-it-shared-root"
        static let ownerWrapInfo = "popt-owner-wrap-v1"
        static let shareExtensionInfo = "popt-share-extension-v1"
        static let audienceInfoPrefix = "popt-audience-v1:"
        static let audienceIdPrefix = "popt-v1|"
        static let keyLength = 32
    }

    // MARK: - HKDF

    /// One HKDF-SHA256 step: 32 bytes out, ASCII salt and info.
    static func hkdf(_ ikm: SymmetricKey, salt: String, info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: Data(salt.utf8),
            info: Data(info.utf8),
            outputByteCount: Constants.keyLength
        )
    }

    /// The recovery KEK: HKDF over the formatted code with the record's salt.
    static func recoveryKEK(code: RecoveryCode, salt: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: code.keyMaterial),
            salt: salt,
            info: Data(Constants.recoveryInfo.utf8),
            outputByteCount: Constants.keyLength
        )
    }

    // MARK: - The chain (SPEC § 5.1)

    enum Error: Swift.Error, CustomStringConvertible {
        case wrappedKEK(Envelope.Error)
        case wrappedMasterDEK(Envelope.Error)
        case wrappedCurveKey(Envelope.Error)
        case wrappedSigningKey(Envelope.Error)
        case keyLength(String, Int)
        case invalidCurveKey
        case invalidSigningKey

        var description: String {
            switch self {
            case .wrappedKEK(let e): "masterKekRecoveryWrapped: \(e)"
            case .wrappedMasterDEK(let e): "masterDekWrapped: \(e)"
            case .wrappedCurveKey(let e): "privateKeyWrapped: \(e)"
            case .wrappedSigningKey(let e): "signingKeyWrapped: \(e)"
            case .keyLength(let what, let n): "\(what) unwrapped to \(n) bytes, expected 32"
            case .invalidCurveKey: "privateKeyWrapped did not unwrap to a Curve25519 private key"
            case .invalidSigningKey: "signingKeyWrapped did not unwrap to an Ed25519 private key"
            }
        }
    }

    /// Runs the whole chain: code + record → KEK → the three long-lived keys.
    /// A wrong code fails at `wrappedKEK` with `authenticationFailed`.
    static func unwrap(record: VaultRecord, code: RecoveryCode) throws -> VaultKeys {
        let recoveryKEK = recoveryKEK(code: code, salt: record.kdfSalt)
        let kekBytes = try open(record.masterKekRecoveryWrapped, with: recoveryKEK, or: Error.wrappedKEK)
        guard kekBytes.count == Constants.keyLength else { throw Error.keyLength("KEK", kekBytes.count) }
        let kek = SymmetricKey(data: kekBytes)
        return try unwrap(record: record, kek: kek)
    }

    /// The second half of the chain, from an already recovered KEK.
    static func unwrap(record: VaultRecord, kek: SymmetricKey) throws -> VaultKeys {
        let dekBytes = try open(record.masterDekWrapped, with: kek, or: Error.wrappedMasterDEK)
        guard dekBytes.count == Constants.keyLength else { throw Error.keyLength("Master DEK", dekBytes.count) }
        let curveBytes = try open(record.privateKeyWrapped, with: kek, or: Error.wrappedCurveKey)
        let signBytes = try open(record.signingKeyWrapped, with: kek, or: Error.wrappedSigningKey)
        guard let curve = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: curveBytes) else {
            throw Error.invalidCurveKey
        }
        guard let sign = try? Curve25519.Signing.PrivateKey(rawRepresentation: signBytes) else {
            throw Error.invalidSigningKey
        }
        return VaultKeys(kek: kek, masterDEK: SymmetricKey(data: dekBytes), curvePrivate: curve, signingPrivate: sign)
    }

    private static func open(
        _ json: String, with key: SymmetricKey, or wrap: (Envelope.Error) -> Error
    ) throws -> Data {
        do {
            return try Envelope(json: json).open(with: key)
        } catch let e as Envelope.Error {
            throw wrap(e)
        }
    }

    // MARK: - Subkeys (SPEC § 5.2)

    static func subkeys(masterDEK: SymmetricKey) -> SubkeyTree {
        let sharedRoot = hkdf(masterDEK, salt: Constants.masterSalt, info: Constants.sharedRootInfo)
        return SubkeyTree(
            personalBlocksKey: hkdf(masterDEK, salt: Constants.masterSalt, info: Constants.personalBlocksInfo),
            sharedRootKey: sharedRoot,
            ownerWrapKey: hkdf(sharedRoot, salt: Constants.sharedRootSalt, info: Constants.ownerWrapInfo),
            shareExtensionKey: hkdf(sharedRoot, salt: Constants.sharedRootSalt, info: Constants.shareExtensionInfo)
        )
    }

    /// The audience DEK an owner mints for `audienceId` (SPEC § 5.2).
    static func audienceMintKey(sharedRootKey: SymmetricKey, audienceId: String) -> SymmetricKey {
        hkdf(sharedRootKey, salt: Constants.sharedRootSalt, info: Constants.audienceInfoPrefix + audienceId)
    }

    // MARK: - Identifiers (SPEC § 5.3)

    /// The deterministic audience id: hex of the first 16 bytes of
    /// `SHA256("popt-v1|" + ownerId + "|" + sorted peer ids joined by ",")`.
    static func audienceId(ownerId: String, peerIds: [String]) -> String {
        let input = Constants.audienceIdPrefix + ownerId + "|" + peerIds.sorted().joined(separator: ",")
        return SHA256.hash(data: Data(input.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}

/// The three long-lived keys of a vault plus the KEK that wrapped them.
struct VaultKeys {
    let kek: SymmetricKey
    let masterDEK: SymmetricKey
    let curvePrivate: Curve25519.KeyAgreement.PrivateKey
    let signingPrivate: Curve25519.Signing.PrivateKey

    /// Raw public halves, the forms the server publishes.
    var curvePublic: Data { curvePrivate.publicKey.rawRepresentation }
    var signingPublic: Data { signingPrivate.publicKey.rawRepresentation }

    var subkeys: SubkeyTree { Derivation.subkeys(masterDEK: masterDEK) }
}

/// The HKDF subkey tree under one Master DEK (SPEC § 5.2).
struct SubkeyTree {
    let personalBlocksKey: SymmetricKey
    let sharedRootKey: SymmetricKey
    let ownerWrapKey: SymmetricKey
    let shareExtensionKey: SymmetricKey

    func audienceMintKey(_ audienceId: String) -> SymmetricKey {
        Derivation.audienceMintKey(sharedRootKey: sharedRootKey, audienceId: audienceId)
    }
}

extension SymmetricKey {
    var bytes: Data { withUnsafeBytes { Data($0) } }
}
