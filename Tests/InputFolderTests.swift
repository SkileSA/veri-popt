import XCTest

final class InputFolderTests: XCTestCase {
    private var folder: URL!

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("veri-popt-folder-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    func testEmptyFolderNamesWhatIsMissing() throws {
        let input = try InputFolder(path: folder.path)
        XCTAssertNil(input.databasePath)
        XCTAssertNil(input.keysPath)
        XCTAssertThrowsError(try input.database()) { XCTAssertTrue("\($0)".contains("no powersync-popt-it.sqlite in")) }
        XCTAssertThrowsError(try input.keys()) { XCTAssertTrue("\($0)".contains("Export Locked Keys")) }
    }

    func testFindsBothFilesByName() throws {
        let test = try TestDatabase()
        test.createSchema()
        test.close()
        let dbPath = folder.appendingPathComponent(Database.appFileName).path
        try FileManager.default.copyItem(atPath: test.path, toPath: dbPath)
        try Vectors.json(Vectors.object("vaults", "alice"), "record").write(to: folder.appendingPathComponent(InputFolder.keysFileName))

        let input = try InputFolder(path: folder.path)
        XCTAssertEqual(input.databasePath, dbPath)
        XCTAssertEqual(try input.keys().id, "alice-uid")
        XCTAssertEqual(try input.database().columns(of: "blocks").count, 13)

        // The database file itself is accepted, and the keys beside it are found.
        let direct = try InputFolder(path: dbPath)
        XCTAssertEqual(direct.path, folder.path)
        XCTAssertNotNil(direct.keysPath)
    }

    func testMissingFolder() {
        XCTAssertThrowsError(try InputFolder(path: "/nowhere/at/all")) { XCTAssertTrue("\($0)".contains("no such folder")) }
    }
}
