//
//  HeaderView.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct HeaderView: View {
    @Binding var entityOperation: EntityOperations

    let title: String
    let backgroundColor: Color

    var body: some View {
        HStack {
            Text(title)
                .frame(maxWidth: .infinity, alignment: .leading)
                .font(.system(size: 20))
            Button("+") {
                entityOperation = .add
            }
            .buttonStyle(.bordered)
            .background(.white)
            .cornerRadius(10)
        }
        .background(backgroundColor)
    }
}

struct HeaderView_Previews: PreviewProvider {
    static var previews: some View {
        StatefulPreviewWrapper(EntityOperations.none) {
            HeaderView(entityOperation: $0, title: "Databases", backgroundColor: .cyan)
        }
    }
}
