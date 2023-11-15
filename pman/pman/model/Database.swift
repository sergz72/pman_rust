//
//  Database.swift
//  pman
//
//  Created by Serhii Zashchelkin on 14.09.23.
//

import Foundation
import CryptoKit

struct Database: Equatable, Identifiable {
    let id: String
    let name: String
    let errorMessage: String?
    let dbId: UInt64?
    var isOpened: Bool
    var groups: [DBGroup]
    var entities: [DBEntity]
    var selectedGroup: UInt32
    
    init(dbURL: URL) {
        name = dbURL.absoluteString
        id = name
        isOpened = false
        groups = []
        entities = []
        selectedGroup = 0
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
        groups = []
        entities = []
        selectedGroup = 0
    }
    
    init(groupName: String, entitiesCount: Int) {
        name = "test"
        id = name
        isOpened = true
        errorMessage = ""
        dbId = 1
        entities = []
        selectedGroup = 0
        groups = [DBGroup(n: groupName, eCount: entitiesCount)]
    }
    
    mutating func open_database(firstPassword: String, secondPassword: String?) -> String {
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
            let g = try getGroups(databaseId: dbId!)
            groups = g.map { DBGroup(group: $0) }.sorted {$0.name < $1.name}
            isOpened = true
            Databases.save(database: self)
        } catch PmanError.ErrorMessage(let e) {
            return e
        } catch {
            return error.localizedDescription
        }
        return ""
    }
    
    mutating func selectGroup(groupId: UInt32) -> String {
        selectedGroup = groupId
        do {
            let e = try getEntities(databaseId: dbId!, groupId: groupId)
            entities = try e.map { try DBEntity(entityId: $0.key, e: $0.value) }.sorted {$0.name < $1.name}
            Databases.save(database: self)
        } catch PmanError.ErrorMessage(let e) {
            entities = []
            return e
        } catch {
            entities = []
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
    
    private func getDatabaseEntities(groupId: UInt32) throws -> [UInt32: DatabaseEntity] {
        if !isOpened {
            throw DatabaseError.databaseIsNotOpened
        }
        return try getEntities(databaseId: dbId!, groupId: groupId)
    }
}

class Databases: ObservableObject {
    static var databases = staticInit()
    
    static func staticInit() -> [Database] {
        libInit();
        let dbs = UserDefaults.standard.array(forKey: "databases") as? [String] ?? []
        return dbs.map{ Database(dbURL: URL(string: $0)!) }
    }
    
    static func save(database: Database) {
        for i in 0...databases.count-1 {
            if databases[i].id == database.id {
                databases[i] = database
                break
            }
        }
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

enum DatabaseError: Error {
    case databaseIsNotOpened
}

struct DBGroup: Equatable, Identifiable {
    let name: String
    let entitesCount: String
    let id: UInt32
    
    init(n: String, eCount: Int) {
        self.name = n
        self.entitesCount = String(eCount)
        self.id = 0
    }
    
    init(group: DatabaseGroup) {
        self.name = group.getName()
        self.id = group.getId()
        self.entitesCount = String(group.getEntitiesCount())
    }
}

struct DBEntity: Equatable, Identifiable {
    let id: UInt32
    let name: String
    //let entity: DatabaseEntity
    
    init(entityId: UInt32, e: DatabaseEntity) throws {
        self.id = entityId
        self.name = try e.getName()
        //self.entity = e
    }
}
