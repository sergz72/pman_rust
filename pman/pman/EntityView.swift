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
    @Binding var entityToEdit: DBEntity?

    @State var entityOperation = EntityOperations.none
    @State var showProperties = false
    
    var body: some View {
        VStack {
            HeaderView(entityOperation: $entityOperation, title: "Entities", backgroundColor: .white)
            List(selectedDatabase?.entities ?? []) { item in
                VStack {
                    HStack {
                        Text(item.name)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .font(.system(size: 18))
                        if (selectedDatabase?.selectedEntity ?? 0 == item.id) {
                            Button("Copy user name") {
                                let result = selectedDatabase!.getUserName(entity: item.entity)
                                errorMessage = result.copy()
                            }
                            .buttonStyle(.bordered)
                            .background(Color.green)
                            Button("Copy password") {
                                let result = item.getPassword()
                                errorMessage = result.copy()
                            }
                            .buttonStyle(.bordered)
                            .background(Color.green)
                            if showProperties {
                                Button("Hide Properties") {
                                    showProperties = false
                                }
                                .buttonStyle(.bordered)
                                .background(Color.green)
                            } else {
                                Button("Show Properties") {
                                    errorMessage = selectedDatabase!.fetchPropertyNames(entity: item.entity)
                                    showProperties = true
                                }
                                .buttonStyle(.bordered)
                                .background(Color.green)
                            }
                        }
                    }
                    if showProperties {
                        HStack {
                            Spacer()
                            ForEach(selectedDatabase?.propertyNames ?? []) { p in
                                Button("Copy \(p.name)") {
                                    let result = item.getPropertyValue(propertyId: p.id)
                                    errorMessage = result.copy()
                                }
                                .buttonStyle(.bordered)
                                .background(Color.green)
                            }
                        }.frame(alignment: .leading)
                    }
                }
                .contentShape(Rectangle())
                .listRowBackground(selectedDatabase?.selectedEntity ?? 0 == item.id ? Color.green : Color.clear)
                .onTapGesture {
                    if selectedDatabase!.selectedEntity != item.id {
                        selectedDatabase!.selectedEntity = item.id
                        showProperties = false
                    }
                }
#if os(macOS)
                    .contextMenu {
                        Button("Edit") {
                            entityToEdit = item
                        }
                        Button("Delete") {
                            
                        }
                    }
#else
                    .swipeActions {
                        Button("Edit") {
                            entityToEdit = item
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
        StatefulPreviewWrapper3(value: Database.init(eName: "test entity"), value2: "",
                                value3: nil) {
            EntityView(selectedDatabase: $0, errorMessage: $1, entityToEdit: $2)
        }
    }
}
