//
//  GroupsView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct GroupsView: View {
    @State var groupOperation = EntityOperations.none

    var body: some View {
        VStack {
            HeaderView(entityOperation: $groupOperation, title: "Groups", backgroundColor: .yellow)
            List {
                Text(/*@START_MENU_TOKEN@*/"Hello, World!"/*@END_MENU_TOKEN@*/)
#if os(macOS)
                    .contextMenu {
                        Button("Delete") {
                            
                        }
                    }
#else
                    .swipeActions {
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

struct GroupsView_Previews: PreviewProvider {
    static var previews: some View {
        GroupsView()
    }
}
