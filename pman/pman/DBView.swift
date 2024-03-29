//
//  DBView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI
import UniformTypeIdentifiers

struct DBView: View {
    @Binding var selectedDatabase: Database?
    @Binding var databaseOperation: EntityOperations
    @Binding var errorMessage: String

    var databases = Databases()

    var body: some View {
        let isPresented = Binding<Bool>(
            get: { self.databaseOperation == .add },
            set: { _ in databaseOperation = .none })
        let kdbxType = UTType(filenameExtension: "kdbx")!
        let pdbfType = UTType(filenameExtension: "pdbf")!
        VStack {
            HeaderView(entityOperation: $databaseOperation, title: "Databases", backgroundColor: .cyan)
            List(Databases.databases) { item in
                HStack {
                    Text(item.name)
                    if selectedDatabase == item {
                        Spacer()
                        Button("Save") {
                            var db = item
                            errorMessage = db.save()
                            Databases.save(database: db)
                            selectedDatabase = db
                        }.disabled(!item.isUpdated)
                    }
                }
                .listRowBackground(selectedDatabase == item ? Color.green : Color.clear)
                .onTapGesture {
                    selectedDatabase = item
                }
#if os(macOS)
                .contextMenu {
                    Button("Remove") {
                        if selectedDatabase != nil {
                            databases.remove(database: selectedDatabase!)
                            selectedDatabase = nil
                        }
                    }
                    Button("Edit") {
                        databaseOperation = .edit
                    }
                }
#else
                .swipeActions {
                    Button("Remove") {
                        if selectedDatabase != nil {
                            databases.remove(database: selectedDatabase!)
                            selectedDatabase = nil
                        }
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
        .fileImporter(
            isPresented: isPresented,
            allowedContentTypes: [kdbxType, pdbfType],
            onCompletion: { result in
                switch result {
                case .success(let file):
                    databases.add(databaseURL: file.absoluteURL)
                case .failure:
                    break
                }
            })
    }
}

struct DBView_Previews: PreviewProvider {
    static var previews: some View {
        StatefulPreviewWrapper3(value: Database.init(dbName: "", message: nil), value2: EntityOperations.none, value3: "") {
            DBView(selectedDatabase: $0, databaseOperation: $1, errorMessage: $2)
        }
    }
}
