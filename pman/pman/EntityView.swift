//
//  EntityView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct EntityView: View {
    @Binding var selectedDatabase: Database?
    @Binding var errorMessage: String

    @State var entityOperation = EntityOperations.none
    @State var showPropertiesForEntity: UInt32 = 0
    
    var body: some View {
        VStack {
            HeaderView(entityOperation: $entityOperation, title: "Entities", backgroundColor: .white)
            List(selectedDatabase?.entities ?? []) { item in
                VStack {
                    HStack {
                        Text(item.name)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .font(.system(size: 18))
                        Button("Copy user name") {
                            let result = selectedDatabase!.getUserName(entity: item.entity)
                            errorMessage = result.copy()
                        }
                        Button("Copy password") {
                            let result = item.getPassword()
                            errorMessage = result.copy()
                        }
                        if showPropertiesForEntity != item.id {
                            Button("Show Properties") {
                                showPropertiesForEntity = item.id
                                errorMessage = selectedDatabase!.fetchPropertyNames(entity: item.entity)
                            }
                        } else {
                            Button("Hide Properties") {
                                showPropertiesForEntity = 0
                            }
                        }
                    }
                    if showPropertiesForEntity == item.id {
                        HStack {
                            Spacer()
                            ForEach(selectedDatabase?.propertyNames ?? []) { p in
                                Button("Copy \(p.name)") {
                                    let result = item.getPropertyValue(propertyId: p.id)
                                    errorMessage = result.copy()
                                }
                            }
                        }.frame(alignment: .leading)
                    }
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

struct EntityView_Previews: PreviewProvider {
    static var previews: some View {
        StatefulPreviewWrapper2(value: Database.init(eName: "test entity"), value2: "") {
            EntityView(selectedDatabase: $0, errorMessage: $1)
        }
    }
}
