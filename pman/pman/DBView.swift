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
    
    var databases = Databases()

    var body: some View {
        let isPresented = Binding<Bool>(
            get: { self.databaseOperation == .add },
            set: { _ in databaseOperation = .none })
        let kdbxType = UTType(filenameExtension: "kdbx")!
        let pdbfType = UTType(filenameExtension: "pdbf")!
        VStack {
            HeaderView(entityOperation: $databaseOperation, title: "Databases", backgroundColor: .cyan)
            List(databases.databases) { item in
                Text(item.name)
                    .listRowBackground(selectedDatabase == item ? Color.red : Color.gray)
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
                    var size: UInt64 = 0;
                    do {
                        let name = file.relativePath;
                        size = try testFile(fileName: name);
                    } catch {
                        print("Unexpected error: \(error).")
                    }
                    databases.add(databaseURL: file.absoluteURL)
                case .failure:
                    break
                }
            })
    }
}

struct DBView_Previews: PreviewProvider {
    static var previews: some View {
        StatefulPreviewWrapper2(value: nil, value2: EntityOperations.none) {
            DBView(selectedDatabase: $0, databaseOperation: $1)
        }
    }
}
