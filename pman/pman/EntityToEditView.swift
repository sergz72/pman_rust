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
    @State var showProperties: Bool
    @State var properties: [DBProperty] = []
    @State var groupId: UInt32?
    @State var userId: UInt32?
    @State var password: String?
    @State var URL: String?
    
    init(entity: Binding<DBEntity?>, database: Binding<Database?>) {
        self._entityToEdit = entity
        self._selectedDatabase = database
        self._showProperties = State(initialValue: entity.wrappedValue?.entity == nil)

        self.name = entity.wrappedValue?.name ?? ""
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
                           } ?? [:],
                           value: $groupId)
            }
            GridRow {
                Text("User")
                PickerView(database: $selectedDatabase,
                           entity: $entityToEdit,
                           getter: {try? $0.entity?.getUserId(version: 0)},
                           list: selectedDatabase?.users ?? [:],
                           value: $userId)
            }
            GridRow {
                Text("Password")
                TextView(entity: $entityToEdit,
                         getter: {try? $0.entity?.getPassword(version: 0)},
                         value: $password)
            }
            GridRow {
                Text("URL")
                TextView(entity: $entityToEdit,
                         getter: {try? $0.entity?.getUrl(version: 0)},
                         value: $URL)
            }
            GridRow {
                Text("Properties")
                HStack {
                    Spacer()
                    if showProperties {
                        Button("Add") {
                            
                        }
                    } else {
                        Button("Show") {
                            selectedDatabase?.fetchPropertyNames(entity: entityToEdit?.entity)
                            let mayBeProperties = try? entityToEdit?.
                            properties = entityToEdit?.
                            showProperties = true
                        }
                    }
                }
            }
            if self.showProperties {
                ForEach(self.properties) {
                    TextField("name", text: $0.name)
                        .disabled($0.id > 0)
                }
            }
        }
    }
}

struct PickerView: View {
    @Binding var selectedDatabase: Database?
    @Binding var entityToEdit: DBEntity?
    @Binding var value: UInt32?

    @State var editMode: Bool
    @State var selection = ""
    
    @State var initialValue: UInt32?
    
    let getter: ((DBEntity) -> UInt32?)
    let list: [UInt32 : String]
    let list2: [String : UInt32]

    init(database: Binding<Database?>, entity: Binding<DBEntity?>, getter: @escaping (DBEntity) -> UInt32?, list: [UInt32 : String], value: Binding<UInt32?>) {
        self._selectedDatabase = database
        self._entityToEdit = entity
        self._value = value
        let editMode = entity.wrappedValue?.entity == nil
        self._editMode = State(initialValue: editMode)
        //self._editMode = State(initialValue: false)
        self.getter = getter
        self.list = list
        self.list2 = list.reduce(into: [:]) {
            $0[$1.value] = $1.key
        }
        if self.editMode {
            let f = list.first
            self.selection = f?.value ?? ""
            self.value = f?.key
        }
    }
    
    var body: some View {
        if editMode {
            Picker("", selection: $selection) {
                ForEach(list.map{$0.value}, id: \.self ) {
                    Text($0)
                }
            }.labelsHidden().onChange(of: selection) {
                let maybeNewValue = list2[selection]
                self.value = initialValue == nil ? maybeNewValue : (maybeNewValue == initialValue ? nil : maybeNewValue)
            }
        } else {
            Button {
                let id = entityToEdit == nil ? nil : self.getter(entityToEdit!)
                let name = id == nil ? "" : (list[id!] ?? "")
                self.selection = name
                self.initialValue = id
                self.editMode = true
            } label: {
                Text("Edit").frame(maxWidth: /*@START_MENU_TOKEN@*/.infinity/*@END_MENU_TOKEN@*/)
            }
        }
    }
}

struct TextView: View {
    @Binding var entityToEdit: DBEntity?
    @Binding var value: String?

    @State var editMode: Bool
    @State var newValue = ""
    @State var initialValue = ""
    
    let getter: ((DBEntity) -> String?)
    
    init(entity: Binding<DBEntity?>, getter: @escaping (DBEntity) -> String?,
         value: Binding<String?>) {
        self._entityToEdit = entity
        self._value = value
        self._editMode = State(initialValue: entity.wrappedValue?.entity == nil)
        //self._editMode = State(initialValue: false)
        self.getter = getter
    }
    
    var body: some View {
        if editMode {
            TextField("", text: $newValue).onChange(of: newValue) {
                value = newValue != initialValue ? newValue : nil
            }
        } else {
            Button {
                let value = entityToEdit == nil ? nil : self.getter(entityToEdit!)
                self.newValue = value ?? ""
                self.initialValue = self.newValue
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
