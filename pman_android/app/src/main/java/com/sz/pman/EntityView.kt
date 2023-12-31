package com.sz.pman

import android.net.Uri
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sz.pman.entities.DBEntity
import com.sz.pman.entities.DBGroup
import com.sz.pman.entities.Database
import com.sz.pman.entities.StringEntityField
import com.sz.pman.entities.UIntEntityField
import com.sz.pman.ui.theme.PmanTheme

@Composable
fun EntityView(entityToEdit: MutableState<DBEntity?>, database: Database) {
    var showPasswordGenerator by remember { mutableStateOf(false) }
    var genNumbers by remember { mutableStateOf(true) }
    var genSymbols by remember { mutableStateOf(true) }
    var genLength by remember { mutableStateOf(30) }

    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Name", modifier = Modifier.width(60.dp))
            BasicTextField(
                value = entityToEdit.value!!.name.value,
                readOnly = entityToEdit.value!!.entity != null,
                onValueChange = { entityToEdit.value!!.name.value = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .then(Modifier.border(1.dp, Color.LightGray))
                    .then(Modifier.height(40.dp)),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Group", modifier = Modifier.width(60.dp))
            UIntFieldEdit(
                entityToEdit.value!!.groupField,
                database.groups.associate { it.id to it.name }
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("User", modifier = Modifier.width(60.dp))
            UIntFieldEdit(entityToEdit.value!!.userNameField, database.users)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Pwd", modifier = Modifier.width(60.dp))
            StringFieldEdit(entityToEdit.value!!.passwordField, Modifier.weight(1f))
            Button(onClick = {
                showPasswordGenerator = !showPasswordGenerator
                entityToEdit.value!!.passwordField.getValue()
                entityToEdit.value!!.passwordField.editMode.value = true
            }) {
                Text("Gen")
            }
        }
        if (showPasswordGenerator) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Num")
                Checkbox(checked = genNumbers, onCheckedChange = { genNumbers = !genNumbers })
                Text("Sy")
                Checkbox(checked = genSymbols, onCheckedChange = { genSymbols = !genSymbols })
                Text("Len")
                Button(onClick = { if (genLength > 1) { genLength--} }) {
                    Text("<")
                }
                Text(genLength.toString())
                Button(onClick = { genLength++ }) {
                    Text(">")
                }
                Button(onClick = {
                    entityToEdit.value!!.passwordField.value.value =
                        generatePassword(genNumbers, genSymbols, genLength)
                    showPasswordGenerator = false
                }) {
                    Text("Gen")
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("URL", modifier = Modifier.width(60.dp))
            StringFieldEdit(entityToEdit.value!!.urlField, Modifier.fillMaxWidth())
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Properties", modifier = Modifier.weight(1f))
            if (entityToEdit.value!!.showProperties.value) {
                Button(onClick = {
                    entityToEdit.value!!.newProperty()
                }) {
                    Text("+")
                }
            } else {
                Button(onClick = { entityToEdit.value!!.toggleShowProperties() }) {
                    Text("Show")
                }
            }
        }
        if (entityToEdit.value!!.showProperties.value) {
            Column {
                entityToEdit.value!!.propertyFields.forEach { entity ->
                    Row {
                        if (entity.key > 0) {
                            Text(entity.value.first.value)
                        } else {
                            BasicTextField(
                                value = entity.value.first.value,
                                onValueChange = { entity.value.first.value = it },
                                modifier = Modifier
                                    .width(60.dp)
                                    .then(Modifier.border(1.dp, Color.LightGray))
                                    .then(Modifier.height(40.dp)),
                            )
                        }
                        StringFieldEdit(
                            entityToEdit.value!!.propertyFields[entity.key]!!.second,
                            Modifier.weight(1f)
                        )
                        Button(onClick = { entityToEdit.value!!.propertyFields.remove(entity.key) }) {
                            Text("Delete")
                        }
                    }
                }
            }
        }
        Row {
            Button(onClick = {
                entityToEdit.value?.reset()
                entityToEdit.value = null
            }, modifier = Modifier.weight(0.5f)) {
                Text("Cancel")
            }
            Button(onClick = {
                database.saveEntity(entityToEdit.value!!)
                entityToEdit.value = null
            }, modifier = Modifier.weight(0.5f)) {
                Text("Save")
            }
        }
    }
}

const val letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const val numbers = "0123456789"
const val symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

fun generatePassword(genNumbers: Boolean, genSymbols: Boolean, genLength: Int): String {
    var table = letters
    if (genNumbers) {
        table += numbers
    }
    if (genSymbols) {
        table += symbols
    }
    return (0 until genLength).map { table[table.indices.random()] }
        .joinToString(prefix = "", postfix = "", separator = "")
}

@Composable
fun StringFieldEdit(field: StringEntityField, modifier: Modifier) {
    if (field.editMode.value) {
        BasicTextField(
            value = field.value.value,
            onValueChange = { field.value.value = it },
            modifier = modifier
                .then(Modifier.border(1.dp, Color.LightGray))
                .then(Modifier.height(20.dp)),
            textStyle = LocalTextStyle.current.copy(fontSize = 15.sp)
        )
    } else {
        Button(onClick = {
            field.getValue()
            field.editMode.value = true
        }, modifier = modifier) {
            Text("Edit")
        }
    }
}

@Composable
fun UIntFieldEdit(field: UIntEntityField, list: Map<UInt, String>) {
    var expanded by remember { mutableStateOf(false) }
    var selectedItemText by remember { mutableStateOf(list[field.value] ?: "") }

    if (field.editMode.value) {
        Column {
            if (expanded) {
                list.forEach {
                    Text(it.value,
                        Modifier
                            .clickable {
                                selectedItemText = it.value
                                field.value = it.key
                                expanded = false
                            }
                            .then(Modifier.fillMaxWidth()))
                }
            } else {
                Text(
                    selectedItemText, modifier = Modifier
                        .fillMaxWidth()
                        .then(Modifier.clickable {
                            expanded = true
                        })
                )
            }
        }
    } else {
        Button(onClick = {
            field.getValue()
            selectedItemText = list[field.value] ?: "Unknown"
            field.editMode.value = true
        }, modifier = Modifier.fillMaxWidth()) {
            Text("Edit")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun EntityViewPreview() {
    val keyFile = remember { mutableStateOf(KeyFile()) }
    val entityToEdit = remember { mutableStateOf(DBEntity(0U, null) as DBEntity?) }
    val groups = remember { mutableStateListOf<DBGroup>() }
    val entities = remember { mutableStateListOf<DBEntity>() }

    PmanTheme {
        EntityView(
            entityToEdit,
            Database("test", Uri.EMPTY, "", 1UL, keyFile, groups, entities)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun UIntFieldEditPreview() {
    PmanTheme {
        UIntFieldEdit(UIntEntityField(), mapOf(1U to "ee", 2U to "dd", 3U to "ww"))
    }
}