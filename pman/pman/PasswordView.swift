//
//  PasswordView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 10.11.23.
//

import SwiftUI
import UniformTypeIdentifiers

struct PasswordView: View {
    @Binding var selectedDatabase: Database?

    @State var firstPassword = ""
    @State var secondPassword = ""
    @State var errorMessage = ""
    @State var isPresented = false

    var body: some View {
        let pubType = UTType(filenameExtension: "pub")!
        let keyType = UTType(filenameExtension: "key")!
        Grid {
            GridRow {
                Text("First password")
                    .gridColumnAlignment(.leading)
                SecureField("Enter password", text: $firstPassword)
                    .textFieldStyle(.roundedBorder)
                    .gridCellColumns(2)
            }
            GridRow {
                Text("Second password")
                SecureField("Enter password", text: $secondPassword)
                    .textFieldStyle(.roundedBorder)
                    .gridCellColumns(2)
            }
            GridRow {
                Text("Key file")
                Text(selectedDatabase?.keyFile?.absoluteString ?? "")
                    .frame(maxWidth: .infinity)
                Button("Select") {
                    isPresented = true
                }
                .buttonStyle(.bordered)
                .background(Color.green)
                .fileImporter(
                    isPresented: $isPresented,
                    allowedContentTypes: [pubType, keyType],
                    onCompletion: { result in
                        switch result {
                        case .success(let file):
                            selectedDatabase!.keyFile = file.absoluteURL
                        case .failure:
                            break
                        }
                    })
            }
            GridRow {
                Button("Open database") {
                    errorMessage = selectedDatabase?
                        .open_database(
                            firstPassword: firstPassword, secondPassword: secondPassword)
                        ?? "Database is not selected"
                    if errorMessage.isEmpty {
                        Databases.saveToUserDefaults()
                    }
                }
                .buttonStyle(.bordered)
                .background(Color.green)
                .keyboardShortcut(.defaultAction)
                .gridCellColumns(3)
                .disabled(secondPassword.isEmpty || firstPassword.isEmpty)
            }
            GridRow {
                Text(errorMessage)
                    .gridCellColumns(2)
                    .foregroundStyle(.red)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

#Preview {
    StatefulPreviewWrapper(nil) {
        PasswordView(selectedDatabase: $0)
    }
}
