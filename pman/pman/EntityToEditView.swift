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

    init(entity: Binding<DBEntity?>, database: Binding<Database?>) {
        self._entityToEdit = entity
        self._selectedDatabase = database
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
                Picker("", selection: $group) {
                    ForEach(selectedDatabase?.groups.map { $0.name } ?? [], id: \.self ) {
                        Text($0)
                    }
                }.labelsHidden()
            }
            GridRow {
                Text("User")
                Picker("", selection: $userName) {
                    ForEach(selectedDatabase?.users.map { $0.value } ?? [], id: \.self ) {
                        Text($0)
                    }
                }.labelsHidden()
            }
        }
    }
}

#Preview {
    StatefulPreviewWrapper2(value: DBEntity(entityName: "eee"), value2: Database(groupName: "gr1", entitiesCount: 1)) {
        EntityToEditView(entity: $0, database: $1)
    }
}
