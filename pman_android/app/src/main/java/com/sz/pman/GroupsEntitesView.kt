package com.sz.pman

import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.tooling.preview.Preview
import com.sz.pman.entities.DBGroup
import com.sz.pman.entities.Database
import com.sz.pman.ui.theme.PmanTheme

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GroupsEntitiesView(selectedDatabase: Database) {
    val clipboardManager = LocalClipboardManager.current

    Column {
        HeaderView("Groups", Color.Green, false) { }
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
                            } else {
                                selectedDatabase.selectGroup(null)
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
        HeaderView("Entities", Color.Yellow, true) { }
        Column(modifier = Modifier.fillMaxHeight()) {
            selectedDatabase.entities.forEach { entity ->
                Row(modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        if (entity == selectedDatabase.selectedEntity.value)
                            Color.Green else Color.White
                    )
                    .selectable(
                        selected = entity == selectedDatabase.selectedEntity.value,
                        onClick = {
                            if (entity != selectedDatabase.selectedEntity.value) {
                                selectedDatabase.selectedEntity.value = entity
                            }
                        }
                    )
                ) {
                    FlowRow(verticalAlignment = Alignment.CenterVertically) {
                        Text(text = entity.name)
                        if (entity == selectedDatabase.selectedEntity.value) {
                            Button(onClick = {
                                clipboardManager.setText(AnnotatedString(entity.entity!!.getName()))
                            }) {
                                Text("Copy user name")
                            }
                            Button(onClick = {
                                clipboardManager.setText(
                                    AnnotatedString(
                                        entity.entity!!.getPassword(
                                            0U
                                        )
                                    )
                                )
                            }) {
                                Text("Copy password")
                            }
                            Button(onClick = {
                                selectedDatabase.selectedEntity.value!!.showProperties.value =
                                    !selectedDatabase.selectedEntity.value!!.showProperties.value
                            }) {
                                Text(
                                    if (selectedDatabase.selectedEntity.value!!.showProperties.value) {
                                        "Hide properties"
                                    } else {
                                        "Show properties"
                                    }
                                )
                            }
                            if (selectedDatabase.selectedEntity.value!!.showProperties.value) {
                                selectedDatabase.selectedEntity.value!!.propertyNames.forEach {
                                    Button(onClick = {
                                        clipboardManager.setText(
                                            AnnotatedString(
                                                entity.entity!!.getPropertyValue(
                                                    0U,
                                                    it.value
                                                )
                                            )
                                        )
                                    }) {
                                        Text("Copy " + it.key + " value")
                                    }
                                }
                            }
                            Button(onClick = { }) {
                                Text("Edit")
                            }
                            Button(onClick = { }) {
                                Text("Delete")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GroupsEntitiesViewPreview() {
    val keyFile = remember { mutableStateOf(KeyFile()) }

    PmanTheme {
        GroupsEntitiesView(Database("test", Uri.EMPTY, "", 1UL, keyFile,
            listOf(
                DBGroup(1U, "group1", 10U),
                DBGroup(2U, "group2", 20U)
            ), listOf()
        ))
    }
}