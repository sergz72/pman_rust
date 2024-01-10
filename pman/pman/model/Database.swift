//
//  Database.swift
//  pman
//
//  Created by Serhii Zashchelkin on 14.09.23.
//

import Foundation
import CryptoKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

struct Database: Equatable, Identifiable {
    let id: String
    let name: String
    let errorMessage: String?
    let dbId: UInt64?
    var isOpened: Bool
    var users: [UInt32 : String]
    var groups: [DBGroup]
    var entities: [DBEntity]
    var selectedGroup: UInt32
    var propertyNames: [IdName]
    var keyFile: URL?

    init(dbString: String) {
        let parts = dbString.components(separatedBy: "|")
        name = parts[0]
        let dbURL = URL(string: parts[0])!
        keyFile = parts.count == 2 ? URL(string: parts[1]) : nil
        id = name
        isOpened = false
        groups = []
        users = [:]
        entities = []
        propertyNames = []
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
        users = [:]
        entities = []
        propertyNames = []
        selectedGroup = 0
    }
    
    init(groupName: String, entitiesCount: Int) {
        name = "test"
        id = name
        isOpened = true
        errorMessage = ""
        dbId = 1
        entities = []
        users = [:]
        selectedGroup = 0
        propertyNames = []
        groups = [DBGroup(n: groupName, eCount: entitiesCount)]
    }

    init(eName: String) {
        name = "test"
        id = name
        isOpened = true
        errorMessage = ""
        dbId = 1
        entities = []
        users = [:]
        selectedGroup = 0
        groups = []
        propertyNames = []
        entities = [DBEntity(entityName: eName)]
    }

    mutating func open_database(firstPassword: String, secondPassword: String?) -> String {
        if dbId == nil {
            return "Database is not prepared"
        }
        if secondPassword == nil {
            return "Second password is required"
        }
        do {
            let keyData: Data? = if keyFile != nil {
                try Data(contentsOf: keyFile!)
            } else { nil }
            let hash1 = Data(SHA256.hash(data: firstPassword.data(using: .utf8)!))
            let hash2 = if secondPassword == nil { nil as Data? } else {Data(SHA256.hash(data: secondPassword!.data(using: .utf8)!))}
            try preOpen(databaseId: dbId!, passwordHash: hash1, password2Hash: hash2, keyFileContents: keyData)
            try open(databaseId: dbId!)
            let g = try getGroups(databaseId: dbId!)
            groups = g.map { DBGroup(group: $0) }.sorted {$0.name < $1.name}
            users = try getUsers(databaseId: dbId!)
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

    mutating func fetchPropertyNames(entity: DatabaseEntity?) -> String {
        if entity != nil {
            do {
                self.propertyNames = try entity!.getPropertyNames(version: 0).map { IdName.init(iD: $0.value, n: $0.key) }
                Databases.save(database: self)
                return ""
            } catch PmanError.ErrorMessage(let e) {
                return e
            } catch {
                return error.localizedDescription
            }
        }
        return "entity is null"
    }

    func getUserName(entity: DatabaseEntity?) -> ValueError {
        if entity != nil {
            do {
                let value = try entity!.getUserId(version: 0)
                return ValueError.init(v: self.users[value]!, message: "")
            } catch PmanError.ErrorMessage(let e) {
                return ValueError.init(v: "", message: e)
            } catch {
                return ValueError.init(v: "", message: error.localizedDescription)
            }
        }
        return ValueError.init(v: "", message: "entity is null")
    }

    private func getDatabaseEntities(groupId: UInt32) throws -> [UInt32: DatabaseEntity] {
        if !isOpened {
            throw DatabaseError.databaseIsNotOpened
        }
        return try getEntities(databaseId: dbId!, groupId: groupId)
    }
    
    func buildDBString() -> String {
        return self.name + (self.keyFile == nil ? "" : "|" + self.keyFile!.absoluteString)
    }
}

class Databases: ObservableObject {
    static var databases = staticInit()
    
    static func staticInit() -> [Database] {
        libInit();
        let dbs = UserDefaults.standard.array(forKey: "databases") as? [String] ?? []
        return dbs.map{ Database(dbString: $0) }
    }
    
    static func save(database: Database) {
        for i in 0...databases.count-1 {
            if databases[i].id == database.id {
                databases[i] = database
                break
            }
        }
    }
    
    static func saveToUserDefaults() {
        let dbs = Databases.databases.map { $0.buildDBString() }
        UserDefaults.standard.set(dbs, forKey: "databases")
    }
    
    func add(databaseURL: URL) {
        Databases.databases.append(Database(dbString: databaseURL.absoluteString))
        Databases.saveToUserDefaults()
    }
    
    func remove(database: Database) {
        Databases.databases.removeAll(where: { $0 == database })
        Databases.saveToUserDefaults()
    }
}

enum DatabaseError: Error {
    case databaseIsNotOpened
}

struct DBGroup: Equatable, Identifiable, Hashable {
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

struct ValueError {
    let errorMessage: String
    let value: String
    
    init(v: String, message: String) {
        self.value = v
        self.errorMessage = message
    }
    
    func copy() -> String {
        if self.errorMessage == "" {
#if os(macOS)
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(self.value, forType: .string)
#else
            UIPasteboard.general.string = self.value
#endif
        }
        return self.errorMessage
    }
}

struct IdName: Equatable, Identifiable {
    let id: UInt32
    let name: String
    
    init(iD: UInt32, n: String) {
        id = iD
        name = n
    }
}

struct DBEntity: Equatable, Identifiable {
    let id: UInt32
    let name: String
    let entity: DatabaseEntity?
    
    init(entityName: String) {
        self.id = 1
        self.name = entityName
        self.entity = nil
    }
    
    init(entityId: UInt32, e: DatabaseEntity) throws {
        self.id = entityId
        self.name = try e.getName()
        self.entity = e
    }
        
    func getPassword() -> ValueError {
        if entity != nil {
            do {
                let value = try entity!.getPassword(version: 0)
                return ValueError.init(v: value, message: "")
            } catch PmanError.ErrorMessage(let e) {
                return ValueError.init(v: "", message: e)
            } catch {
                return ValueError.init(v: "", message: error.localizedDescription)
            }
        }
        return ValueError.init(v: "", message: "entity is null")
    }
    
    func getPropertyValue(propertyId: UInt32) -> ValueError {
        if entity != nil {
            do {
                let value = try entity!.getPropertyValue(version: 0, id: propertyId)
                return ValueError.init(v: value, message: "")
            } catch PmanError.ErrorMessage(let e) {
                return ValueError.init(v: "", message: e)
            } catch {
                return ValueError.init(v: "", message: error.localizedDescription)
            }
        }
        return ValueError.init(v: "", message: "entity is null")
    }
        
    static func == (lhs: DBEntity, rhs: DBEntity) -> Bool {
        return lhs.id == rhs.id && lhs.name == rhs.name
    }
}
