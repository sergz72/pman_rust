//
//  GroupsView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct GroupsView: View {
    @Binding var selectedDatabase: Database?
    @Binding var errorMessage: String

    @State var groupOperation = EntityOperations.none
    
    var body: some View {
        VStack {
            HeaderView(entityOperation: $groupOperation, title: "Groups", backgroundColor: .yellow)
            List(selectedDatabase?.groups ?? []) { item in
                HStack {
                    Text(item.name)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text(item.entitesCount)
                }
                .contentShape(Rectangle())
                .listRowBackground(selectedDatabase?.selectedGroup ?? 0 == item.id ? Color.green : Color.gray)
                .onTapGesture {
                    errorMessage = selectedDatabase?.selectGroup(groupId: item.id) ?? "Database is not selected"
                }
#if os(macOS)
                    .contextMenu {
                        Button("Rename") {
                            
                        }
                        Button("Delete") {
                            
                        }
                    }
#else
                    .swipeActions {
                        Button("Rename") {
                        }
                        .tint(.yellow)
                        Button("Delete") {
                        }
                        .tint(.red)
                    }
#endif
            }
            .listStyle(PlainListStyle())
            .padding(.horizontal)
        }
        .background(Color(red: 0.93, green: 0.93, blue: 0.93))
        .scrollContentBackground(.hidden)
    }
}

#Preview {
    StatefulPreviewWrapper2(value: Database.init(groupName: "Internet", entitiesCount: 100), value2: "") {
        GroupsView(selectedDatabase: $0, errorMessage: $1)
    }
}
