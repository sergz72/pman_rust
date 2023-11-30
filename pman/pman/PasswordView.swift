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
    @State var keyFile: URL?
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
                Text(keyFile?.absoluteString ?? "")
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
                            keyFile = file.absoluteURL
                        case .failure:
                            break
                        }
                    })
            }
            GridRow {
                Button("Open database") {
                    errorMessage = selectedDatabase?
                        .open_database(
                            firstPassword: firstPassword, secondPassword: secondPassword, keyFile: keyFile)
                        ?? "Database is not selected"
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
