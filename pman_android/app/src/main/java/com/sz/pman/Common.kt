package com.sz.pman

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

@Composable
fun HeaderView(title: String, color: Color, buttonEnabled: Boolean, addHandler: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.background(color)
    ) {
        Text(text = title)
        Spacer(Modifier.weight(1f))
        Button(onClick = addHandler, enabled = buttonEnabled) {
            Text("+")
        }
    }
}
