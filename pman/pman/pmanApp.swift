//
//  pmanApp.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

@main
struct pmanApp: App {
#if os(macOS)
    @AppStorage("windowWidth") var width = 1000.0
    @AppStorage("windowHeight") var height = 800.0
#endif

    @State var databaseOperation = EntityOperations.none
    
    var body: some Scene {
        WindowGroup {
#if os(macOS)
            GeometryReader { geometry in
                ContentView(databaseOperation: $databaseOperation)
                    .frame(minWidth: width, maxWidth: .infinity, minHeight: height, maxHeight: .infinity)
                    .onChange(of: geometry.size) { oldSize, newSize in
                        width = newSize.width
                        height = newSize.height
                    }
            }
#else
            ContentView(databaseOperation: $databaseOperation)
#endif
        }
#if os(macOS)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(action: {databaseOperation = .create}, label: {
                    Text("New")
                })
            }
            CommandGroup(after: .newItem) {
                Button(action: {databaseOperation = .add}, label: {
                    Text("Open")
                })
            }
            CommandGroup(replacing: .saveItem) {
                Button(action: {}, label: {
                    Text("Save")
                })
            }
            CommandGroup(after: .saveItem) {
                Button(action: {}, label: {
                    Text("Save As...")
                })
            }
        }
#endif
    }
}
