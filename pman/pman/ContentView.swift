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
                                GroupsView()
                                    .frame(minHeight: 100, maxHeight: 100)
                                Divider()
                                EntityView()
                                    .frame(maxHeight: .infinity)
                            } else {
                                buildPasswordView()
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
        HStack(spacing: 3) {
            DBView(selectedDatabase: $selectedDatabase, databaseOperation: $databaseOperation)
                .frame(width: dbViewWidth)
            DraggableDivider(viewWidth: $dbViewWidth, minViewWidth: 200)
            if selectedDatabase?.name == nil {
                Spacer()
            } else {
                if selectedDatabase!.errorMessage != nil {
                    Text(selectedDatabase!.errorMessage!)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    if selectedDatabase!.isOpened {
                        GroupsView()
                            .frame(width: groupsViewWidth)
                        DraggableDivider(viewWidth: $groupsViewWidth, minViewWidth: 200)
                        EntityView()
                            .frame(maxWidth: .infinity)
                    } else {
                        buildPasswordView()
                    }
                }
            }
        }
        .padding()
    }
    
    func buildPasswordView() -> some View {
        PasswordView(selectedDatabase: $selectedDatabase)
    }
}

#Preview {
    StatefulPreviewWrapper(EntityOperations.none) {
        ContentView(databaseOperation: $0)
            .previewLayout(.fixed(width: 900, height: 400))
    }
}
