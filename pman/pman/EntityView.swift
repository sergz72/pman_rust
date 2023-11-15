//
//  EntityView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct EntityView: View {
    @Binding var selectedDatabase: Database?

    @State var entityOperation = EntityOperations.none
    
    var body: some View {
        VStack {
            HeaderView(entityOperation: $entityOperation, title: "Entities", backgroundColor: .white)
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

struct EntityView_Previews: PreviewProvider {
    static var previews: some View {
        StatefulPreviewWrapper(nil) {
            EntityView(selectedDatabase: $0)
        }
    }
}
