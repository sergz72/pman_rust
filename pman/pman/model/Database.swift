//
//  Database.swift
//  pman
//
//  Created by Serhii Zashchelkin on 14.09.23.
//

import Foundation

class Database: Hashable, Identifiable, Equatable {
    let id: String
    let name: String
    let errorMessage: String?
    let dbId: uint64?
    var isOpened: Bool
    
    init(dbURL: URL) {
        name = dbURL.absoluteString
        id = name
        isOpened = false
        do {
            let rawData: Data = try Data(contentsOf: dbURL)
            dbId = try prepare(data: rawData, fileName: name)
            errorMessage = nil
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
    
    public func hash(into hasher: inout Hasher) {
        return hasher.combine(id)
    }

    static func == (lhs: Database, rhs: Database) -> Bool {
        return lhs.id == rhs.id
    }
}

class Databases: ObservableObject {
    var databases: [Database]
    
    init() {
        libInit();
        let dbs = UserDefaults.standard.array(forKey: "databases") as? [String] ?? []
        databases = dbs.map{ Database(dbURL: URL(string: $0)!) }
    }
    
    func add(databaseURL: URL) {
        databases.append(Database(dbURL: databaseURL))
        let dbs = databases.map { $0.name }
        UserDefaults.standard.set(dbs, forKey: "databases")
    }
    
    func remove(database: Database) {
        databases.removeAll(where: { $0 == database })
        let dbs = databases.map { $0.name }
        UserDefaults.standard.set(dbs, forKey: "databases")
    }
}
