//
//  utils.swift
//  pman
//
//  Created by Serhii Zashchelkin on 14.09.23.
//

import SwiftUI

struct StatefulPreviewWrapper<Value, Content: View>: View {
    @State var value: Value
    var content: (Binding<Value>) -> Content

    var body: some View {
        content($value)
    }

    init(_ value: Value, content: @escaping (Binding<Value>) -> Content) {
        self._value = State(wrappedValue: value)
        self.content = content
    }
}

struct StatefulPreviewWrapper2<Value, Value2, Content: View>: View {
    @State var value: Value
    @State var value2: Value2
    var content: (Binding<Value>, Binding<Value2>) -> Content

    var body: some View {
        content($value, $value2)
    }

    init(value: Value, value2: Value2, content: @escaping (Binding<Value>, Binding<Value2>) -> Content) {
        self._value = State(wrappedValue: value)
        self._value2 = State(wrappedValue: value2)
        self.content = content
    }
}

struct StatefulPreviewWrapper3<Value, Value2, Value3, Content: View>: View {
    @State var value: Value
    @State var value2: Value2
    @State var value3: Value3
    var content: (Binding<Value>, Binding<Value2>, Binding<Value3>) -> Content

    var body: some View {
        content($value, $value2, $value3)
    }

    init(value: Value, value2: Value2, value3: Value3, content: @escaping (Binding<Value>, Binding<Value2>, Binding<Value3>) -> Content) {
        self._value = State(wrappedValue: value)
        self._value2 = State(wrappedValue: value2)
        self._value3 = State(wrappedValue: value3)
        self.content = content
    }
}
