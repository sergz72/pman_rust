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
    
    @Binding var databaseOperation: EntityOperations

    var body: some View {
#if !os(macOS)
        GeometryReader { geometry in
            if geometry.size.width < geometry.size.height {
                VStack {
                    DBView(selectedDatabase: $selectedDatabase, databaseOperation: $databaseOperation)
                        .frame(minHeight: 100, maxHeight: 100)
                    Divider()
                    if selectedDatabase?.name == nil {
                        Spacer()
                    } else {
                        if selectedDatabase!.errorMessage != nil {
                            Text(selectedDatabase!.errorMessage!)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        } else {
                            if selectedDatabase!.isOpened {
                                GroupsView(selectedDatabase: $selectedDatabase)
                                    .frame(minHeight: 100, maxHeight: 100)
                                Divider()
                                EntityView(selectedDatabase: $selectedDatabase)
                                    .frame(maxHeight: .infinity)
                            } else {
                                PasswordView(selectedDatabase: $selectedDatabase)
                            }
                        }
                    }
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
                DBView(selectedDatabase: $selectedDatabase, databaseOperation: $databaseOperation)
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
                            GroupsView(selectedDatabase: $selectedDatabase, errorMessage: $errorMessage)
                                .frame(width: groupsViewWidth)
                            DraggableDivider(viewWidth: $groupsViewWidth, minViewWidth: 200)
                            EntityView(selectedDatabase: $selectedDatabase)
                                .frame(maxWidth: .infinity)
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
