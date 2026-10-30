import Foundation

/// The user's `vaults` row as the connections service returns it and as the
/// app exports it (SPEC § 4). Field names are the service's JSON names.
///
/// Decoding is strict on purpose: the top-level keys must be a subset of the
/// known set. A record carrying anything else, a recovery code or an
/// unwrapped key above all, is refused with the offending keys named.
struct VaultRecord: Equatable, Sendable {
    let id: String
    /// 16 bytes.
    let kdfSalt: Data
    let masterKekRecoveryWrapped: String
    let masterDekWrapped: String
    let privateKeyWrapped: String
    let signingKeyWrapped: String
    /// Raw Ed25519 public key, 32 bytes.
    let signingPublicKey: Data
    let createdAt: Int64?
    let updatedAt: Int64?

    static let allowedKeys: Set<String> = [
        "id", "kdfSalt", "masterKekRecoveryWrapped", "masterDekWrapped", "privateKeyWrapped",
        "signingKeyWrapped", "signingPublicKey", "createdAt", "updatedAt",
    ]
    static let saltLength = 16
    static let publicKeyLength = 32

    enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case notJSON
        case unexpectedKeys([String])
        case missingField(String)
        case wrongType(String)
        case invalidBase64(String)
        case wrongLength(field: String, expected: Int, actual: Int)

        var description: String {
            switch self {
            case .notJSON: "vault record is not a JSON object"
            case .unexpectedKeys(let keys):
                "vault record carries unexpected keys \(keys.sorted()); a record must hold only the wrapped material"
            case .missingField(let f): "vault record is missing \"\(f)\""
            case .wrongType(let f): "vault record field \"\(f)\" has the wrong type"
            case .invalidBase64(let f): "vault record field \"\(f)\" is not valid base64"
            case .wrongLength(let f, let e, let a): "vault record field \"\(f)\" decodes to \(a) bytes, expected \(e)"
            }
        }
    }

    init(json data: Data) throws {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Error.notJSON
        }
        let unexpected = Set(object.keys).subtracting(Self.allowedKeys)
        guard unexpected.isEmpty else { throw Error.unexpectedKeys(unexpected.sorted()) }

        func string(_ name: String) throws -> String {
            guard let raw = object[name] else { throw Error.missingField(name) }
            guard let value = raw as? String else { throw Error.wrongType(name) }
            return value
        }
        func bytes(_ name: String, length: Int) throws -> Data {
            guard let value = Data(base64Encoded: try string(name)) else { throw Error.invalidBase64(name) }
            guard value.count == length else {
                throw Error.wrongLength(field: name, expected: length, actual: value.count)
            }
            return value
        }
        func millis(_ name: String) throws -> Int64? {
            guard let raw = object[name], !(raw is NSNull) else { return nil }
            guard let number = raw as? NSNumber else { throw Error.wrongType(name) }
            return number.int64Value
        }

        id = try string("id")
        kdfSalt = try bytes("kdfSalt", length: Self.saltLength)
        masterKekRecoveryWrapped = try string("masterKekRecoveryWrapped")
        masterDekWrapped = try string("masterDekWrapped")
        privateKeyWrapped = try string("privateKeyWrapped")
        signingKeyWrapped = try string("signingKeyWrapped")
        signingPublicKey = try bytes("signingPublicKey", length: Self.publicKeyLength)
        createdAt = try millis("createdAt")
        updatedAt = try millis("updatedAt")
    }

    init(contentsOf url: URL) throws {
        try self.init(json: try Data(contentsOf: url))
    }
}
