//
//  Database.swift
//  pman
//
//  Created by Serhii Zashchelkin on 14.09.23.
//

import Foundation
import CryptoKit

class Database: Hashable, Identifiable, Equatable, ObservableObject {
    let id: String
    let name: String
    let errorMessage: String?
    let dbId: UInt64?
    var isOpened: Bool
    
    init(dbURL: URL) {
        name = dbURL.absoluteString
        id = name
        isOpened = false
        do {
            let rawData: Data = try Data(contentsOf: dbURL)
            dbId = try prepare(data: rawData, fileName: name)
            errorMessage = nil
        } catch PmanError.ErrorMessage(let e) {
            dbId = nil
            errorMessage = e
        } catch {
            dbId = nil
            errorMessage = error.localizedDescription
        }
    }
    
    init(dbName: String, message: String?) {
        name = dbName
        id = name
        isOpened = false
        errorMessage = message
        dbId = nil
    }
    
    func open_database(firstPassword: String, secondPassword: String?) -> String {
        if dbId == nil {
            return "Database is not prepared"
        }
        if secondPassword == nil {
            return "Second password is required"
        }
        do {
            let hash1 = Data(SHA256.hash(data: firstPassword.data(using: .utf8)!))
            let hash2 = if secondPassword == nil { nil as Data? } else {Data(SHA256.hash(data: secondPassword!.data(using: .utf8)!))}
            let fileNames = try preOpen(databaseId: dbId!, passwordHash: hash1, password2Hash: hash2, keyFileContents: nil)
            let data = try loadFiles(names: fileNames)
            try open(databaseId: dbId!, data: data)
            isOpened = true
            objectWillChange.send()
        } catch PmanError.ErrorMessage(let e) {
            return e
        } catch {
            return error.localizedDescription
        }
        return ""
    }
    
    func loadFiles(names: [String]) throws -> [Data] {
        var result: [Data] = []
        for name in names {
            let data = try Data(contentsOf: URL(string: name)!)
            result.append(data)
        }
        return result
    }
    
    public func hash(into hasher: inout Hasher) {
        return hasher.combine(id)
    }

    static func == (lhs: Database, rhs: Database) -> Bool {
        return lhs.id == rhs.id
    }
}

class Databases: ObservableObject {
    static var databases = staticInit()
    
    static func staticInit() -> [Database] {
        libInit();
        let dbs = UserDefaults.standard.array(forKey: "databases") as? [String] ?? []
        return dbs.map{ Database(dbURL: URL(string: $0)!) }
    }
    
    init() {
    }
    
    func add(databaseURL: URL) {
        Databases.databases.append(Database(dbURL: databaseURL))
        let dbs = Databases.databases.map { $0.name }
        UserDefaults.standard.set(dbs, forKey: "databases")
    }
    
    func remove(database: Database) {
        Databases.databases.removeAll(where: { $0 == database })
        let dbs = Databases.databases.map { $0.name }
        UserDefaults.standard.set(dbs, forKey: "databases")
    }
}
