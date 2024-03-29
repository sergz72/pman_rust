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
    @Binding var errorMessage: String

    @State var name = ""
    @State var showProperties: Bool
    @State var properties: [DBProperty] = []
    @State var groupId: UInt32?
    @State var userId: UInt32?
    @State var password: String?
    @State var URL: String?
    
    init(entity: Binding<DBEntity?>, database: Binding<Database?>, errorMessage: Binding<String>) {
        self._entityToEdit = entity
        self._selectedDatabase = database
        let showProperties = entity.wrappedValue?.entity == nil
        self._showProperties = State(initialValue: showProperties)

        self._name = State(initialValue: entity.wrappedValue?.name ?? "")
        
        self._errorMessage = errorMessage
        
        if showProperties {
            self._userId = State(initialValue: selectedDatabase?.users.first?.key)
            self._groupId = State(initialValue: selectedDatabase?.groups.first?.id)
        }
    }
    
    var body: some View {
        Grid {
            GridRow {
                Text("Name")
                TextField("name", text: $name)
                    .disabled(entityToEdit?.entity != nil)
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
                         value: $password, forceEditMode: false)
            }
            GridRow {
                Text("URL")
                TextView(entity: $entityToEdit,
                         getter: {try? $0.entity?.getUrl(version: 0)},
                         value: $URL, forceEditMode: false)
            }
            GridRow {
                Text("Properties")
                HStack {
                    Spacer()
                    if showProperties {
                        Button("Add") {
                            properties.append(DBProperty.init())
                        }
                    } else {
                        Button("Show") {
                            errorMessage = selectedDatabase!.fetchPropertyNames(entity: entityToEdit?.entity)
                            properties = selectedDatabase!.propertyNames.map { DBProperty(pid: $0.id, pname: $0.name)}
                            showProperties = true
                        }
                    }
                }
            }
            if self.showProperties {
                ForEach($properties.filter{!$0.isDeleted.wrappedValue}) { p in
                    GridRow {
                        PropertyView(property: p, entity: $entityToEdit)
                            .gridCellColumns(2)
                    }
                }
            }
            GridRow {
                Button("Save") {
                    errorMessage = selectedDatabase!.saveEntity(entity: entityToEdit!, name: name, properties: properties, groupId: groupId, userId: userId, password: password, url: URL, changeUrl: false)
                    entityToEdit = nil
                }
                Button {
                    entityToEdit = nil
                } label: {
                    Text("Cancel").frame(maxWidth: /*@START_MENU_TOKEN@*/.infinity/*@END_MENU_TOKEN@*/)
                }
            }
        }
    }
}

struct PropertyView: View {
    @Binding var property: DBProperty
    @Binding var entity: DBEntity?
    
    var body: some View {
        HStack {
            TextField("name", text: $property.name)
                .disabled($property.id > 0)
            TextView(entity: $entity, getter: {
                try? $0.entity?.getPropertyValue(version: 0, id: UInt32(property.id))
            }, value: $property.value, forceEditMode: $property.id < 0)
            Button("Delete") {
                property.isDeleted = true
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
        if self.value != nil {
            let name = list[self.value!]
            self._selection = State(initialValue: name ?? "")
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
         value: Binding<String?>, forceEditMode: Bool) {
        self._entityToEdit = entity
        self._value = value
        if forceEditMode {
            self._editMode = State(initialValue: true)
        } else {
            self._editMode = State(initialValue: entity.wrappedValue?.entity == nil)
        }
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
    StatefulPreviewWrapper3(value: DBEntity(entityName: "eee"), value2: Database(groupName: "gr1", entitiesCount: 1), value3: "") {
        EntityToEditView(entity: $0, database: $1, errorMessage: $2)
    }
}
