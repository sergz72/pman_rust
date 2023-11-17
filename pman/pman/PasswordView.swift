//
//  PasswordView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 10.11.23.
//

import SwiftUI

struct PasswordView: View {
    @Binding var selectedDatabase: Database?

    @State var firstPassword = ""
    @State var secondPassword = ""
    @State var errorMessage = ""

    var body: some View {
        Grid {
            GridRow {
                Text("First password")
                    .gridColumnAlignment(.leading)
                SecureField("Enter password", text: $firstPassword)
                    .textFieldStyle(.roundedBorder)
            }
            GridRow {
                Text("Second password")
                SecureField("Enter password", text: $secondPassword)
                    .textFieldStyle(.roundedBorder)
            }
            GridRow {
                Button("Open database") {
                    errorMessage = selectedDatabase?
                        .open_database(
                            firstPassword: firstPassword, secondPassword: secondPassword)
                        ?? "Database is not selected"
                }
                .buttonStyle(.bordered)
                .background(Color.green)
                .keyboardShortcut(.defaultAction)
                .gridCellColumns(2)
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
