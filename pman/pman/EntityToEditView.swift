//
//  EntityToEditView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 10.01.24.
//

import SwiftUI

struct EntityToEditView: View {
    @Binding var selectedDatabase: Database?
    @Binding var entityToEdit: DBEntity?
    
    @State var name = ""
    @State var group = ""
    @State var userName = ""
    @State var showProperties: Bool
    @State var properties: [UInt32 : String] = [:]

    init(entity: Binding<DBEntity?>, database: Binding<Database?>) {
        self._entityToEdit = entity
        self._selectedDatabase = database
        self._showProperties = State(initialValue: entity.wrappedValue?.entity == nil)

        self.name = entity.wrappedValue?.name ?? ""

        let groupId = try? entity.wrappedValue?.entity?.getGroupId(version: 0)
        let group = selectedDatabase?.groups.first(where: { $0.id == groupId})
        let groupName = group?.name ?? ""
        self._group = State(initialValue: groupName)

        let userId = try? entity.wrappedValue?.entity?.getUserId(version: 0)
        let userName = userId == nil ? "" : (selectedDatabase?.users[userId!] ?? "")
        self._userName = State(initialValue: userName)
    }
    
    var body: some View {
        Grid {
            GridRow {
                Text("Name")
                TextField("name", text: $name)
                    .disabled(entityToEdit?.entity == nil)
            }
            GridRow {
                Text("Group")
                PickerView(database: $selectedDatabase,
                           entity: $entityToEdit,
                           getter: {try? $0.entity?.getGroupId(version: 0)},
                           list: selectedDatabase?.groups.reduce(into: [:]) { dict, item in
                    dict[item.id] = item.name
                } ?? [:])
            }
            GridRow {
                Text("User")
                PickerView(database: $selectedDatabase,
                           entity: $entityToEdit,
                           getter: {try? $0.entity?.getUserId(version: 0)},
                           list: selectedDatabase?.users ?? [:])
            }
            GridRow {
                Text("Password")
                TextView(entity: $entityToEdit, getter: {try? $0.entity?.getPassword(version: 0)})
            }
            GridRow {
                Text("URL")
                TextView(entity: $entityToEdit, getter: {try? $0.entity?.getUrl(version: 0)})
            }
            GridRow {
                Text("Properties")
                HStack {
                    Spacer()
                    Button("Show") {
                        
                    }
                }
            }
            if self.showProperties {
                ForEach(self.properties.map{}) {
                    
                }
            }
        }
    }
}

struct PickerView: View {
    @Binding var selectedDatabase: Database?
    @Binding var entityToEdit: DBEntity?

    @State var editMode: Bool
    @State var selection = ""
    
    let getter: ((DBEntity) -> UInt32?)
    let list: [UInt32 : String]
    
    init(database: Binding<Database?>, entity: Binding<DBEntity?>, getter: @escaping (DBEntity) -> UInt32?, list: [UInt32 : String]) {
        self._selectedDatabase = database
        self._entityToEdit = entity
        self._editMode = State(initialValue: entity.wrappedValue?.entity == nil)
        //self._editMode = State(initialValue: false)
        self.getter = getter
        self.list = list
    }
    
    var body: some View {
        if editMode {
            Picker("", selection: $selection) {
                ForEach(list.map{$0.value}, id: \.self ) {
                    Text($0)
                }
            }.labelsHidden()
        } else {
            Button {
                let id = entityToEdit == nil ? nil : self.getter(entityToEdit!)
                let name = id == nil ? "" : (list[id!] ?? "")
                self.selection = name
                self.editMode = true
            } label: {
                Text("Edit").frame(maxWidth: /*@START_MENU_TOKEN@*/.infinity/*@END_MENU_TOKEN@*/)
            }
        }
    }
}

struct TextView: View {
    @Binding var entityToEdit: DBEntity?

    @State var editMode: Bool
    @State var value = ""
    
    let getter: ((DBEntity) -> String?)
    
    init(entity: Binding<DBEntity?>, getter: @escaping (DBEntity) -> String?) {
        self._entityToEdit = entity
        self._editMode = State(initialValue: entity.wrappedValue?.entity == nil)
        //self._editMode = State(initialValue: false)
        self.getter = getter
    }
    
    var body: some View {
        if editMode {
            TextField("", text: $value)
        } else {
            Button {
                let value = entityToEdit == nil ? nil : self.getter(entityToEdit!)
                self.value = value ?? ""
                self.editMode = true
            } label: {
                Text("Edit").frame(maxWidth: /*@START_MENU_TOKEN@*/.infinity/*@END_MENU_TOKEN@*/)
            }
        }
    }
}

#Preview {
    StatefulPreviewWrapper2(value: DBEntity(entityName: "eee"), value2: Database(groupName: "gr1", entitiesCount: 1)) {
        EntityToEditView(entity: $0, database: $1)
    }
}
