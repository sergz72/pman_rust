//
//  ContentView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct ContentView: View {
    @AppStorage("dbViewWidth") var dbViewWidth = 200.0
    @AppStorage("groupsViewWidth") var groupsViewWidth = 200.0

    @State var selectedDatabase: Database?
    @State var errorMessage: String = ""
    @State var entityToEdit: DBEntity?

    @Binding var databaseOperation: EntityOperations

    var body: some View {
#if !os(macOS)
        GeometryReader { geometry in
            if geometry.size.width < geometry.size.height + 100 {
                VStack {
                    DBView(selectedDatabase: $selectedDatabase, databaseOperation: $databaseOperation)
                        .frame(minHeight: 200, maxHeight: 200)
                    Divider()
                    if selectedDatabase?.name == nil {
                        Spacer()
                    } else {
                        if selectedDatabase!.errorMessage != nil {
                            Text(selectedDatabase!.errorMessage!)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        } else {
                            if selectedDatabase!.isOpened {
                                GroupsView(selectedDatabase: $selectedDatabase, errorMessage: $errorMessage)
                                    .frame(minHeight: 200, maxHeight: 200)
                                Divider()
                                EntityView(selectedDatabase: $selectedDatabase, errorMessage: $errorMessage)
                                    .frame(maxHeight: .infinity)
                            } else {
                                PasswordView(selectedDatabase: $selectedDatabase)
                            }
                        }
                    }
                    Text(errorMessage).tint(.red)
                }
                .padding()
            } else {
                buildHorizontalView()
            }
        }
#else
        buildHorizontalView()
#endif
    }
    
    func buildHorizontalView() -> some View {
        VStack {
            HStack(spacing: 3) {
                DBView(selectedDatabase: $selectedDatabase, databaseOperation: $databaseOperation, errorMessage: $errorMessage)
                    .frame(width: dbViewWidth)
                DraggableDivider(viewWidth: $dbViewWidth, minViewWidth: 200)
                if selectedDatabase == nil {
                    Spacer()
                } else {
                    if selectedDatabase?.errorMessage != nil {
                        Text(selectedDatabase!.errorMessage!)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        if selectedDatabase!.isOpened {
                            if entityToEdit == nil {
                                GroupsView(selectedDatabase: $selectedDatabase, errorMessage: $errorMessage)
                                    .frame(width: groupsViewWidth)
                                DraggableDivider(viewWidth: $groupsViewWidth, minViewWidth: 200)
                                EntityView(selectedDatabase: $selectedDatabase, errorMessage: $errorMessage, entityToEdit: $entityToEdit)
                                    .frame(maxWidth: .infinity)
                            } else {
                                EntityToEditView(entity: $entityToEdit, database: $selectedDatabase, errorMessage: $errorMessage)
                                    .frame(maxWidth: .infinity)
                            }
                        } else {
                            PasswordView(selectedDatabase: $selectedDatabase)
                        }
                    }
                }
            }
            Text(errorMessage).tint(.red)
        }
        .padding()
    }
}

#Preview {
    StatefulPreviewWrapper(EntityOperations.none) {
        ContentView(databaseOperation: $0)
            .previewLayout(.fixed(width: 900, height: 400))
    }
}
