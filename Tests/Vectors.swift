import CryptoKit
import Foundation
import XCTest

/// Access to `Fixtures/vectors.json`, the known-answer vectors generated
/// once by the Popt app's own crypto code (see `generatedBy` in the file
/// and SPEC § 10). Every test in this bundle checks the tool's independent
/// implementation against these values.
enum Vectors {
    private final class Marker {}

    static let root: [String: Any] = {
        guard let url = Bundle(for: Marker.self).url(forResource: "vectors", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { fatalError("Tests/Fixtures/vectors.json is missing or not a JSON object") }
        return object
    }()

    /// Walks nested objects: `Vectors.object("vaults", "alice")`.
    static func object(_ path: String...) -> [String: Any] {
        var node: Any = root
        for key in path {
            guard let dict = node as? [String: Any], let next = dict[key] else {
                fatalError("vectors.json has no \(path.joined(separator: "."))")
            }
            node = next
        }
        guard let result = node as? [String: Any] else { fatalError("\(path.joined(separator: ".")) is not an object") }
        return result
    }

    static func string(_ dict: [String: Any], _ key: String) -> String {
        guard let value = dict[key] as? String else { fatalError("vector key \(key) is not a string") }
        return value
    }

    static func int(_ dict: [String: Any], _ key: String) -> Int {
        guard let value = (dict[key] as? NSNumber)?.intValue else { fatalError("vector key \(key) is not a number") }
        return value
    }

    static func hex(_ dict: [String: Any], _ key: String) -> Data {
        Data(hex: string(dict, key))
    }

    static func base64(_ dict: [String: Any], _ key: String) -> Data {
        guard let value = Data(base64Encoded: string(dict, key)) else { fatalError("vector key \(key) is not base64") }
        return value
    }

    static func key(_ dict: [String: Any], _ key: String) -> SymmetricKey {
        SymmetricKey(data: hex(dict, key))
    }

    static func json(_ dict: [String: Any], _ key: String) throws -> Data {
        guard let value = dict[key] else { fatalError("vector key \(key) is missing") }
        return try JSONSerialization.data(withJSONObject: value)
    }
}

extension Data {
    init(hex: String) {
        var bytes = [UInt8]()
        var chars = hex.makeIterator()
        while let high = chars.next(), let low = chars.next() {
            guard let byte = UInt8(String([high, low]), radix: 16) else { fatalError("bad hex \(hex)") }
            bytes.append(byte)
        }
        self.init(bytes)
    }
}

/// Flips one bit of a byte at `offset`.
func flipped(_ data: Data, at offset: Int) -> Data {
    var copy = data
    copy[copy.startIndex + offset] ^= 0x01
    return copy
}
