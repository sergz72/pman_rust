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
                TextField("Enter password", text: $firstPassword)
                    .textContentType(.password)
            }
            GridRow {
                Text("Second password")
                TextField("Enter password", text: $secondPassword)
                    .textContentType(.password)
            }
            GridRow {
                Button("Open database") {
                   errorMessage = selectedDatabase?
                        .open_database(
                            firstPassword: firstPassword, secondPassword: secondPassword)
                        ?? "Database is not selected"
                }
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
