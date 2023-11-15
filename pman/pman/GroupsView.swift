//
//  GroupsView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct GroupsView: View {
    @Binding var selectedDatabase: Database?

    @State var groupOperation = EntityOperations.none

    var body: some View {
        VStack {
            HeaderView(entityOperation: $groupOperation, title: "Groups", backgroundColor: .yellow)
            List {
                Text(/*@START_MENU_TOKEN@*/"Hello, World!"/*@END_MENU_TOKEN@*/)
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
        }
        .background(Color(red: 0.93, green: 0.93, blue: 0.93))
        .scrollContentBackground(.hidden)
    }
}

#Preview {
    StatefulPreviewWrapper(nil) {
        GroupsView(selectedDatabase: $0)
    }
}
