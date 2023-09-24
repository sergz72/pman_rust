//
//  DraggableDivider.swift
//  pman
//
//  Created by Serhii Zashchelkin on 03.09.23.
//

import SwiftUI

struct DraggableDivider: View {
    @State private var hoverState = false
    @Binding var viewWidth: Double
    let minViewWidth: Double
    
    var body: some View {
        Divider()
#if os(macOS)
            .onHover { inside in
                if inside {
                    if !hoverState {
                        NSCursor.resizeLeftRight.push()
                        hoverState = true
                    }
                } else if hoverState {
                    NSCursor.pop()
                    hoverState = false
                }
            }
#endif
            .gesture(
                DragGesture()
                    .onEnded { gesture in
                        var w = viewWidth + Double(gesture.translation.width)
                        if w < minViewWidth {
                            w = minViewWidth
                        }
                        if (viewWidth != w) {
                            viewWidth = w
                        }
                    }
            )
    }
}

struct DraggableDivider_Previews: PreviewProvider {
    @State private static var vWidth = 200.0
    
    static var previews: some View {
        DraggableDivider(viewWidth: $vWidth, minViewWidth: 200.0)
    }
}
