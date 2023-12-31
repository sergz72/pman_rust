package com.sz.pman

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Divider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import com.sz.pman.entities.DBGroup
import com.sz.pman.entities.Database
import com.sz.pman.ui.theme.PmanTheme

@Composable
fun DatabaseView(selectedDatabase: Database) {
    Column {
        HeaderView("Groups", Color.Green) { }
        Column {
            selectedDatabase.groups.forEach { group ->
                Row(modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        if (group == selectedDatabase.selectedGroup.value)
                            Color.Green else Color.White
                    )
                    .selectable(
                        selected = group == selectedDatabase.selectedGroup.value,
                        onClick = {
                            if (group != selectedDatabase.selectedGroup.value) {
                                selectedDatabase.selectGroup(group)
                            }
                        }
                    )
                ) {
                    Text(text = group.name, modifier = Modifier.weight(1f))
                    Text(group.items.toString())
                }
            }
        }
        Divider()
        HeaderView("Entities", Color.Yellow) { }
        Column(modifier = Modifier.fillMaxHeight()) {

        }
    }
}

@Preview(showBackground = true)
@Composable
fun DatabaseViewPreview() {
    PmanTheme {
        DatabaseView(Database("test", "", 1UL,
            listOf(
                DBGroup(1U, "group1", 10U),
                DBGroup(2U, "group2", 20U)
            )))
    }
}